#!/usr/bin/env python3
"""Read-only artifact contract v1; JSON on stdout, no external commands.

Required inputs: --manifest, --manifest-sha256, --context, --metadata, --iid,
--inspection, --archive, --expected-index-digest. The two expected digests must
come from trusted source/build captures; hashes are not signatures. This checks
captured evidence, not whether an untrusted builder really built the source.
Manifest fields are schemaVersion=1, sourceCommit,
contextSHA256 (hex), version, candidateTag and files[{path,bytes,sha256,mode}].
The context is an uncompressed source tar with exactly that regular-file set.
Inspection is {native: <unfiltered image inspect object>, selected: <amd64
inspect object>}. Contract v1 requires an OCI index, one linux/amd64 manifest,
one retained SLSA v0.2 provenance attestation (Statement v0.1 or v1), and
Docker-save manifest.json. Only empty blobs/ and blobs/sha256/ directories
are permitted in image archives.
Unsupported exporter/provenance formats fail; this does not attest a live tag,
builder honesty, vulnerability status, container hardening or deployment.

Inputs are copied into private temporary files to prevent substitution between
verification passes; originals are never written. Limits: JSON 4 MiB/depth 64,
source tar 128 MiB, image tar 2 GiB/4096 members, decoded layers 1 GiB total.
No archive extraction or layer execution. No approvals or recovery records.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import zlib

from build_identity import archive_config, verify as verify_graph, INDEX, MANIFEST, CONFIG
from evidence_schema import field, strict_json
from security import SecurityError, require, valid_digest

JSON_MAX = 4 * 1024**2
SOURCE_MAX = 128 * 1024**2
ARCHIVE_MAX = 2 * 1024**3
DECODED_MAX = 1024**3
MEMBERS_MAX = 4096
PROVENANCE = 'https://slsa.dev/provenance/v0.2'
HEX = r'[0-9a-f]{64}'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    require(len(raw) <= JSON_MAX, 'INPUT_LIMIT', 'JSON input exceeds limit.')
    # Decode once: the guard and JSON parser must interpret identical text.
    require(not raw.startswith((b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff', b'\x00\x00\xfe\xff')),
            'JSON_ENCODING', 'Only BOM-free UTF-8 JSON is supported.')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeError:
        raise SecurityError('JSON_ENCODING', 'Only BOM-free UTF-8 JSON is supported.') from None
    require('\0' not in text, 'JSON_ENCODING', 'NUL-containing JSON encodings are unsupported.')
    depth = 0; quoted = False; escaped = False
    for char in text:
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in ('[', '{'):
            depth += 1
            require(depth <= 64, 'INPUT_LIMIT', 'JSON nesting exceeds limit.')
        elif char in (']', '}'): depth -= 1
    return strict_json(text)


def snapshot(source, destination, limit):
    require(not str(source).startswith(('//','\\\\')), 'INPUT_PATH', 'Network/device input paths are unsupported.')
    p = Path(source).absolute()
    require(all(not x.is_symlink() and not (hasattr(x, 'is_junction') and x.is_junction()) for x in (p, *p.parents)),
            'INPUT_PATH', 'Linked input paths are unsupported.')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(p, flags)
    with os.fdopen(fd, 'rb') as src:
        before = os.fstat(src.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, 'INPUT_LIMIT', 'Input must be a bounded regular file.')
        count = 0
        with destination.open('xb') as out:
            while chunk := src.read(1024**2):
                count += len(chunk)
                require(count <= limit, 'INPUT_LIMIT', 'Input grew beyond limit.')
                out.write(chunk)
        after = os.fstat(src.fileno())
        require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns) and count == before.st_size,
                'INPUT_CHANGED', 'Input changed while being captured.')


def safe_name(name):
    require(type(name) is str and name and not name.startswith('/') and '\\' not in name and ':' not in name
            and all(x not in ('', '.', '..') for x in name.split('/')), 'ARCHIVE_PATH', 'Unsafe archive path.')


def image_directory(member):
    return member.isdir() and member.size == 0 and member.name.rstrip('/') in ('blobs', 'blobs/sha256')


def members(tar, source=False):
    result = {}; total = 0
    for m in tar:
        name = m.name.rstrip('/') if m.isdir() else m.name
        safe_name(name)
        require(name not in result and len(result) < MEMBERS_MAX, 'ARCHIVE_MEMBERS', 'Duplicate or excessive archive members.')
        require(m.isfile() or (source and m.isdir()) or image_directory(m), 'ARCHIVE_TYPE', 'Links and special archive entries are forbidden.')
        total += m.size
        require(0 <= m.size <= (SOURCE_MAX if source else ARCHIVE_MAX) and total <= (SOURCE_MAX if source else ARCHIVE_MAX),
                'INPUT_LIMIT', 'Archive logical size exceeds limit.')
        require(not any(parent in result and result[parent].isfile() for parent in ('/'.join(name.split('/')[:i]) for i in range(1, len(name.split('/'))))),
                'ARCHIVE_PATH', 'Conflicting archive paths.')
        result[name] = m
    require(result, 'ARCHIVE_MEMBERS', 'Empty archive.')
    require(not any(m.isfile() and any(n.startswith(name+'/') for n in result) for name,m in result.items()),
            'ARCHIVE_PATH', 'Conflicting archive paths.')
    return result


def physical_tar(path, source=False):
    # Bound extension headers before tarfile can allocate their payloads.
    with path.open('rb') as stream:
        count = 0
        while True:
            raw = stream.read(512)
            require(len(raw) == 512, 'ARCHIVE_FRAMING', 'Truncated tar header.')
            if raw == bytes(512):
                require(stream.read(512) == bytes(512), 'ARCHIVE_FRAMING', 'Two tar end blocks required.')
                while chunk := stream.read(1024**2):
                    require(not chunk.strip(b'\0'), 'ARCHIVE_FRAMING', 'Trailing nonzero tar bytes.')
                return
            m = tarfile.TarInfo.frombuf(raw, 'utf-8', 'strict'); count += 1
            require(count <= MEMBERS_MAX*2 and 0 <= m.size <= (SOURCE_MAX if source else ARCHIVE_MAX),
                    'INPUT_LIMIT', 'Tar header exceeds limits.')
            extension = source and m.type in (tarfile.XHDTYPE, tarfile.XGLTYPE)
            require(m.type in (tarfile.REGTYPE,tarfile.AREGTYPE) or (source and m.isdir()) or image_directory(m) or extension,
                    'ARCHIVE_TYPE', 'Unsupported physical tar member.')
            if extension:
                require(m.size <= 4096, 'INPUT_LIMIT', 'Source tar extension exceeds limit.')
            stream.seek((m.size+511)//512*512, 1)
            require(stream.tell() <= path.stat().st_size, 'ARCHIVE_FRAMING', 'Truncated tar payload.')


def bounded_json(tar, member):
    require(member.isfile() and member.size <= JSON_MAX, 'INPUT_LIMIT', 'Oversized JSON archive member.')
    return parse(tar.extractfile(member).read(JSON_MAX+1))


def source_check(manifest, context):
    require(type(manifest) is dict and set(manifest) == {'schemaVersion','sourceCommit','contextSHA256','version','candidateTag','files'}
            and type(manifest['schemaVersion']) is int and manifest['schemaVersion'] == 1, 'SOURCE_SCHEMA', 'Unsupported source manifest.')
    require(re.fullmatch(r'[0-9a-f]{40}', field(manifest,'sourceCommit',str))
            and re.fullmatch(HEX, field(manifest,'contextSHA256',str))
            and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', field(manifest,'version',str)),
            'SOURCE_SCHEMA', 'Invalid source identity/version.')
    require(re.fullmatch(r'passwordforge:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}',field(manifest,'candidateTag',str)),
            'SOURCE_SCHEMA', 'Explicit PasswordForge candidate tag required.')
    require(sha(context.read_bytes()) == manifest['contextSHA256'], 'SOURCE_CONTEXT', 'Frozen context differs.')
    entries = field(manifest,'files',list)
    require(0 < len(entries) <= MEMBERS_MAX, 'SOURCE_SCHEMA', 'Bounded source inventory required.')
    expected = {}
    for e in entries:
        require(type(e) is dict and set(e) == {'path','bytes','sha256','mode'}, 'SOURCE_SCHEMA', 'Malformed source entry.')
        name = field(e,'path',str); safe_name(name)
        require(name not in expected and type(e['bytes']) is int and 0 <= e['bytes'] <= SOURCE_MAX
                and re.fullmatch(HEX,field(e,'sha256',str)) and e['mode'] in ('0644','0755'), 'SOURCE_SCHEMA', 'Invalid source entry.')
        expected[name] = e
    with tarfile.open(context, 'r:') as tar:
        found = members(tar, source=True)
        require({n for n,m in found.items() if m.isfile()} == set(expected), 'SOURCE_INVENTORY', 'Frozen source inventory differs.')
        for name,e in expected.items():
            m = found[name]
            require(m.size == e['bytes'] and m.mode == int(e['mode'],8)
                    and sha(tar.extractfile(m).read()) == e['sha256'], 'SOURCE_FILE', 'Frozen source bytes or permissions differ.')
        package = bounded_json(tar,found['package.json'])
        require(package['version'] == manifest['version'], 'SOURCE_VERSION', 'Package version differs.')
        dockerfile = tar.extractfile(found['Dockerfile']).read().decode('utf-8')
        refs = re.findall(r'^FROM\s+(\S+)',dockerfile,re.M)
        require(len(refs) == 2 and refs[0].startswith('node:') and refs[1].startswith('nginx:')
                and all(re.fullmatch(r'(node|nginx):[^\s@]+@sha256:'+HEX,r) for r in refs),
                'SOURCE_BASES', 'Two pinned base references required.')
        require('org.opencontainers.image.version="'+manifest['version']+'"' in dockerfile,
                'SOURCE_VERSION', 'Dockerfile version differs.')
    return refs


def provenance(value, manifest, refs):
    invocation = field(value,'invocation',dict)
    source = field(invocation,'configSource',dict)
    require(field(source,'digest',dict).get('sha256') == manifest['contextSHA256'] and source.get('entryPoint') == 'Dockerfile'
            and field(invocation,'environment',dict).get('platform') == 'linux/amd64', 'SOURCE_PROVENANCE', 'Build provenance differs.')
    materials = field(value,'materials',list)
    require(all(any(type(m) is dict and m.get('digest',{}).get('sha256') == ref.split('@sha256:')[1]
                    and type(m.get('uri')) is str and m['uri'].startswith('pkg:docker/'+ref.split(':')[0]+'@')
                    for m in materials) for ref in refs), 'SOURCE_PROVENANCE', 'Pinned base provenance missing.')


def image_policy(configuration, inspection, manifest):
    config = field(configuration,'config',dict); captured = field(inspection,'Config',dict)
    for key in ('Labels','User','Entrypoint','Cmd','Healthcheck','ExposedPorts','Volumes','WorkingDir','OnBuild','StopSignal','Env'):
        require(config.get(key) == captured.get(key), 'RUNTIME_CAPTURE', 'Runtime inspection differs from authenticated config.')
    labels = field(config,'Labels',dict)
    require(all(type(k) is str and type(value) is str for k,value in labels.items()), 'RUNTIME_CONFIG', 'Image labels must be strings.')
    required = {'org.opencontainers.image.title':'PasswordForge','org.opencontainers.image.version':manifest['version'],
                'org.opencontainers.image.revision':manifest['sourceCommit'],'org.passwordforge.source':manifest['contextSHA256']}
    require(all(labels.get(k) == v for k,v in required.items()), 'IMAGE_LABELS', 'Source/version labels differ.')
    require(config.get('User') == '10001:10001' and config.get('Entrypoint') == ['nginx']
            and config.get('Cmd') == ['-g','daemon off;'] and config.get('Volumes') in (None,{})
            and config.get('WorkingDir') in (None,'','/') and config.get('OnBuild') in (None,[]) and config.get('StopSignal') in (None,'SIGQUIT'),
            'RUNTIME_CONFIG', 'Unexpected image execution configuration.')
    ports = field(config,'ExposedPorts',dict)
    require('8080/tcp' in ports and set(ports) <= {'80/tcp','8080/tcp'} and all(v == {} for v in ports.values()),
            'RUNTIME_CONFIG', 'Unexpected image port metadata.')
    h = field(config,'Healthcheck',dict)
    require(h.get('Test') == ['CMD-SHELL','wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1']
            and all(type(h.get(k)) is int and h[k] == v for k,v in {'Interval':30_000_000_000,'Timeout':3_000_000_000,'StartPeriod':10_000_000_000,'Retries':3}.items())
            and set(h) == {'Test','Interval','Timeout','StartPeriod','Retries'}, 'RUNTIME_CONFIG', 'Healthcheck differs.')


def graph_policy(archive, metadata, selected, manifest, refs):
    rootid = field(metadata,'containerimage.digest',str)
    require(valid_digest(rootid), 'BUILD_DIGEST', 'Invalid build digest.')
    with tarfile.open(archive, 'r:') as tar:
        found = members(tar); blobs = set(); decoded = 0
        for name in found:
            require(image_directory(found[name]) or name in ('manifest.json','index.json','oci-layout') or re.fullmatch('blobs/sha256/'+HEX,name),
                    'ARCHIVE_PATH', 'Unsupported OCI archive entry.')
        def obj(desc):
            identity = field(desc,'digest',str); require(valid_digest(identity),'DESCRIPTOR_DIGEST','Invalid descriptor.')
            name = 'blobs/sha256/'+identity[7:]; blobs.add(name)
            return bounded_json(tar,found[name])
        root = obj({'digest':rootid})
        require(root.get('mediaType') in INDEX, 'EXPORT_TYPE', 'Contract v1 requires an OCI index.')
        descriptors = field(root,'manifests',list)
        require(len(descriptors) == 2, 'ATTESTATION_POLICY', 'Exactly one runtime and one provenance manifest required.')
        runtime = [d for d in descriptors if d.get('platform',{}).get('os') == 'linux']
        attest = [d for d in descriptors if d.get('annotations',{}).get('vnd.docker.reference.type') == 'attestation-manifest']
        require(len(runtime) == len(attest) == 1, 'ATTESTATION_POLICY', 'Required retained provenance missing.')
        rd = runtime[0]; rm = obj(rd); cd = field(rm,'config',dict); configuration = obj(cd)
        require(rd.get('platform') in ({'os':'linux','architecture':'amd64'},{'os':'linux','architecture':'amd64','variant':'v1'}),
                'PLATFORM', 'Unexpected runtime platform.')
        require(selected.get('Descriptor') == rd and selected.get('Id') in (rd['digest'],cd['digest']),
                'PLATFORM_IDENTITY', 'Selected manifest/configuration identity differs.')
        for d in field(rm,'layers',list):
            name = 'blobs/sha256/'+field(d,'digest',str)[7:]; blobs.add(name)
            require(d.get('mediaType') in ('application/vnd.oci.image.layer.v1.tar','application/vnd.oci.image.layer.v1.tar+gzip',
                    'application/vnd.docker.image.rootfs.diff.tar.gzip'), 'LAYER_COMPRESSION', 'Unsupported runtime layer type.')
            with tar.extractfile(found[name]) as stream:
                prefix = stream.read(2); stream.seek(0)
                require((prefix == b'\x1f\x8b') == d['mediaType'].endswith(('+gzip','.gzip')), 'LAYER_COMPRESSION', 'Layer encoding differs.')
                reader = gzip.GzipFile(fileobj=stream) if prefix == b'\x1f\x8b' else stream
                try:
                    while chunk := reader.read(1024**2):
                        decoded += len(chunk)
                        require(decoded <= DECODED_MAX, 'INPUT_LIMIT', 'Decoded layer limit exceeded.')
                finally:
                    if reader is not stream: reader.close()
        am = obj(attest[0]); ac = field(am,'config',dict)
        if ac.get('mediaType') == 'application/vnd.oci.empty.v1+json':
            # Only the retained, index-selected attestation may use this exact
            # empty configuration. The shared verifier authenticates the full
            # index/manifest graph and attestation subject before acceptance.
            require(attest[0].get('platform') == {'os':'unknown','architecture':'unknown'}
                    and attest[0].get('annotations',{}).get('vnd.docker.reference.digest') == rd['digest'],
                    'ATTESTATION_POLICY', 'Empty configuration requires an identified attestation.')
            require(ac.get('digest') == 'sha256:'+sha(b'{}') and type(ac.get('size')) is int and ac['size'] == 2,
                    'ATTESTATION_CONFIG', 'Empty attestation configuration descriptor differs.')
            name = 'blobs/sha256/'+ac['digest'][7:]
            require(name in found and found[name].size == 2, 'ATTESTATION_CONFIG', 'Empty attestation configuration blob missing or invalid.')
            with tar.extractfile(found[name]) as stream:
                require(stream.read(3) == b'{}', 'ATTESTATION_CONFIG', 'Attestation configuration must be exactly empty.')
            require(obj(ac) == {}, 'ATTESTATION_CONFIG', 'Attestation configuration must be an empty object.')
        else:
            require(ac.get('mediaType') in CONFIG, 'ATTESTATION_POLICY', 'Unsupported attestation configuration type.')
            obj(ac)
        layers = field(am,'layers',list)
        require(len(layers) == 1, 'ATTESTATION_POLICY', 'One retained provenance statement required.')
        statement = obj(layers[0])
        require(statement.get('_type') in ('https://in-toto.io/Statement/v0.1','https://in-toto.io/Statement/v1') and statement.get('predicateType') == PROVENANCE,
                'ATTESTATION_POLICY', 'Unsupported retained attestation.')
        provenance(field(statement,'predicate',dict),manifest,refs)
        # Shared graph verifier performs cryptographic descriptor/subject/layer checks.
        require({n for n,m in found.items() if m.isfile() and n.startswith('blobs/')} == blobs, 'ARCHIVE_GRAPH', 'Unreferenced or missing graph blobs.')
        if 'index.json' in found:
            wrapper = bounded_json(tar,found['index.json'])
            require(wrapper.get('schemaVersion') == 2 and wrapper.get('manifests') == [metadata['containerimage.descriptor']],
                    'ARCHIVE_WRAPPER', 'Unexpected OCI layout root.')
        if 'oci-layout' in found:
            require(bounded_json(tar,found['oci-layout']) == {'imageLayoutVersion':'1.0.0'}, 'ARCHIVE_WRAPPER', 'Unsupported layout version.')
        # Bind the Docker-save transport references before any shared reader
        # can follow them. All referenced JSON has passed bounded_json above.
        legacy = bounded_json(tar,found['manifest.json'])
        require(type(legacy) is list and len(legacy) == 1, 'ARCHIVE_RUNTIME', 'Exactly one Docker runtime entry required.')
        require(field(legacy[0],'Config',str) == 'blobs/sha256/'+cd['digest'][7:],
                'ARCHIVE_CONFIG_PATH', 'Docker config reference differs from the selected OCI config.')
        layer_names = ['blobs/sha256/'+field(d,'digest',str)[7:] for d in field(rm,'layers',list)]
        require(field(legacy[0],'Layers',list) == layer_names and len(set(layer_names)) == len(layer_names)
                and legacy[0]['Config'] not in layer_names,
                'ARCHIVE_LAYER_BINDING', 'Docker layer references differ, repeat or conflict with the OCI graph.')
        image_policy(configuration,selected,manifest)
    return cd['digest']


def verify_inputs(args):
    require(re.fullmatch(HEX,args.manifest_sha256 or ''), 'MANIFEST_HASH', 'Explicit approved manifest checksum required.')
    require(valid_digest(args.expected_index_digest), 'EXPECTED_INDEX', 'Trusted Buildx index digest required.')
    with tempfile.TemporaryDirectory(prefix='passwordforge-verify-') as temporary:
        root = Path(temporary); paths = {}
        for key,limit in (('manifest',JSON_MAX),('context',SOURCE_MAX),('metadata',JSON_MAX),('iid',256),('inspection',JSON_MAX),('archive',ARCHIVE_MAX)):
            paths[key] = root/key; snapshot(getattr(args,key),paths[key],limit)
        physical_tar(paths['context'],source=True); physical_tar(paths['archive'])
        raw = paths['manifest'].read_bytes()
        require(sha(raw) == args.manifest_sha256, 'MANIFEST_HASH', 'Approved source manifest differs.')
        manifest = parse(raw); refs = source_check(manifest,paths['context'])
        metadata = parse(paths['metadata'].read_bytes()); captured = parse(paths['inspection'].read_bytes())
        require(type(captured) is dict and set(captured) == {'native','selected'}, 'INSPECTION_SCHEMA', 'Both native and platform-selected captures required.')
        native = field(captured,'native',dict); selected = field(captured,'selected',dict)
        iid = paths['iid'].read_bytes().decode('ascii').strip(); export = field(metadata,'containerimage.digest',str)
        require(export == args.expected_index_digest, 'EXPECTED_INDEX', 'Captured image differs from trusted build digest.')
        require(valid_digest(export) and iid == export and native.get('Id') == export
                and native.get('Descriptor') == field(metadata,'containerimage.descriptor',dict), 'BUILD_IDENTITY', 'Build IID/index capture differs.')
        require(metadata.get('image.name') in (manifest['candidateTag'],'docker.io/library/'+manifest['candidateTag'])
                and manifest['candidateTag'] in field(native,'RepoTags',list), 'CANDIDATE_TAG', 'Captured candidate tag differs.')
        require(native.get('Os') == selected.get('Os') == 'linux' and native.get('Architecture') == selected.get('Architecture') == 'amd64'
                and native.get('Variant') in (None,'','v1') and selected.get('Variant') in (None,'','v1')
                and native.get('Config') == selected.get('Config') and native.get('RootFS') == selected.get('RootFS'),
                'PLATFORM', 'Native/selected runtime differs.')
        provenance(field(metadata,'buildx.build.provenance',dict),manifest,refs)
        configid = graph_policy(paths['archive'],metadata,selected,manifest,refs)
        # Authenticate the complete graph before the transport reader follows
        # its now-bound references. Private snapshots preserve the checked bytes.
        identities = verify_graph(paths['archive'],metadata,selected,iid,configid)
        require(archive_config(paths['archive'],selected) == configid,'MANIFEST_CONFIG','Configuration identity differs.')
        return {'status':'PASS','contractVersion':1,'sourceCommit':manifest['sourceCommit'],'contextSHA256':manifest['contextSHA256'],
                'version':manifest['version'],'candidateTag':manifest['candidateTag'],'indexDigest':export,
                'manifestDigest':identities['manifestId'],'configDigest':configid,'attestationPolicy':PROVENANCE}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SecurityError('ARGUMENTS','Explicit artifact paths and manifest checksum are required.')


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        for name in ('manifest','manifest-sha256','context','metadata','iid','inspection','archive','expected-index-digest'):
            parser.add_argument('--'+name,required=True)
        result = verify_inputs(parser.parse_args(argv)); status = 0
    except SecurityError as error:
        result = {'status':'FAIL','code':error.code}; status = 2
    except (OSError,ValueError,TypeError,KeyError,IndexError,AttributeError,RecursionError,tarfile.TarError,EOFError,zlib.error):
        result = {'status':'FAIL','code':'ARTIFACT_FORMAT_OR_IO'}; status = 2
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
