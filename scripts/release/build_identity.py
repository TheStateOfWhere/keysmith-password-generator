"""Bind Buildx result, OCI descriptor graph and selected Docker runtime config.
No digest-type substitution; unsupported or incomplete exports stop explicitly.
"""
import hashlib
import gzip
import tarfile
from evidence_schema import field, strict_json
from security import require, valid_digest

INDEX = ('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json')
MANIFEST = ('application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json')
CONFIG = ('application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json')

def digest(raw):
    return 'sha256:'+hashlib.sha256(raw).hexdigest()

def verify(path, metadata, inspected, iid, config_id):
    export_id=field(metadata, 'containerimage.digest', str)
    require(valid_digest(export_id) and valid_digest(iid), 'BUILD_DIGEST', 'Malformed Buildx export/IID digest.')
    if 'containerimage.config.digest' in metadata:
        require(field(metadata,'containerimage.config.digest',str)==config_id,
                'BUILD_CONFIG', 'Buildx config digest differs from exported runtime config bytes.')
    if 'buildx.build.provenance' in metadata:
        field(metadata, 'buildx.build.provenance', dict)
    with tarfile.open(path) as tar:
        members={m.name:m for m in tar.getmembers()}
        require(len(members)==len(tar.getmembers()), 'ARCHIVE_DUPLICATE', 'Duplicate archive names.')
        def raw_blob(identity, size=None):
            require(valid_digest(identity), 'DESCRIPTOR_DIGEST', 'Malformed OCI descriptor digest.')
            name='blobs/sha256/'+identity[7:]
            require(name in members, 'EXPORT_GRAPH_MISSING', 'Export does not retain the digest-addressed build graph: '+identity)
            member=members[name]
            require(member.isfile() and member.size<=4*1024*1024,
                    'DESCRIPTOR_MEMBER', 'Descriptor metadata must be a bounded regular file.')
            raw=tar.extractfile(member).read()
            require(digest(raw)==identity, 'DESCRIPTOR_HASH', 'OCI metadata bytes do not match descriptor digest.')
            if size is not None:
                require(type(size) is int and size>=0 and size==len(raw), 'DESCRIPTOR_SIZE', 'OCI descriptor size differs.')
            return raw
        def object_blob(desc, allowed):
            media=field(desc,'mediaType',str)
            require(media in allowed, 'DESCRIPTOR_TYPE', 'Unexpected OCI descriptor media type.')
            raw=raw_blob(field(desc,'digest',str),field(desc,'size',int))
            value=strict_json(raw)
            require(type(value) is dict and field(value,'schemaVersion',int)==2
                    and field(value,'mediaType',str)==media, 'DESCRIPTOR_SCHEMA', 'OCI content/type differs from descriptor.')
            return value
        raw=raw_blob(export_id); root=strict_json(raw)
        require(type(root) is dict and field(root,'schemaVersion',int)==2,
                'EXPORT_SCHEMA', 'Build export is not an OCI index/image manifest.')
        kind=field(root,'mediaType',str)
        require(kind in INDEX+MANIFEST, 'EXPORT_TYPE', 'Unsupported build export digest type.')
        if 'containerimage.descriptor' in metadata:
            desc=field(metadata,'containerimage.descriptor',dict)
            require(field(desc,'digest',str)==export_id and field(desc,'mediaType',str)==kind
                    and field(desc,'size',int)==len(raw), 'BUILD_DESCRIPTOR', 'Buildx descriptor differs from exported bytes.')
        runtime=[]; attestations=[]
        if kind in INDEX:
            for desc in field(root,'manifests',list):
                platform=field(desc,'platform',dict)
                os=field(platform,'os',str); arch=field(platform,'architecture',str)
                annotations=desc.get('annotations',{})
                require(type(annotations) is dict, 'INDEX_ANNOTATIONS', 'Malformed index annotations.')
                manifest=object_blob(desc,MANIFEST)
                if os=='linux' and arch=='amd64' and platform.get('variant') in (None,'','v1'):
                    require(annotations.get('vnd.docker.reference.type')!='attestation-manifest',
                            'ATTESTATION_PLATFORM', 'Attestation cannot masquerade as runtime.')
                    runtime.append((desc['digest'],manifest))
                else:
                    require(os=='unknown' and arch=='unknown'
                            and annotations.get('vnd.docker.reference.type')=='attestation-manifest',
                            'INDEX_PLATFORM', 'Unexpected additional runtime platform.')
                    attestations.append((desc,manifest))
        else:
            runtime.append((export_id,root))
        require(len(runtime)==1, 'RUNTIME_SELECTION', 'Expected exactly one linux/amd64 runtime manifest.')
        manifest_id,manifest=runtime[0]
        config=field(manifest,'config',dict)
        require(field(config,'mediaType',str) in CONFIG and field(config,'digest',str)==config_id,
                'MANIFEST_CONFIG', 'Selected runtime manifest references a different config.')
        config_raw=raw_blob(config_id,field(config,'size',int))
        configuration=strict_json(config_raw)
        require(configuration.get('os')=='linux' and configuration.get('architecture')=='amd64'
                and configuration.get('variant') in (None,'','v1'), 'CONFIG_PLATFORM', 'Runtime config is not linux/amd64.')
        require(field(field(configuration,'rootfs',dict),'diff_ids',list)==inspected['RootFS']['Layers'],
                'CONFIG_ROOTFS', 'Runtime config and daemon layer identities differ.')
        require(field(field(configuration,'config',dict),'Labels',dict)==inspected['Config']['Labels'],
                'CONFIG_LABELS', 'Exported and daemon ownership/version/source labels differ.')
        legacy= strict_json(tar.extractfile(members['manifest.json']).read())
        require(type(legacy) is list and len(legacy)==1, 'ARCHIVE_RUNTIME', 'Ambiguous Docker runtime entry.')
        require(field(legacy[0],'Config',str)=='blobs/sha256/'+config_id[7:],
                'ARCHIVE_CONFIG_PATH','Docker runtime config does not reference the authenticated graph blob.')
        layers=field(manifest,'layers',list)
        require(field(legacy[0],'Layers',list)==['blobs/sha256/'+field(x,'digest',str)[7:] for x in layers],
                'ARCHIVE_LAYER_BINDING','Docker transport layers differ from selected manifest layer order.')
        require(len(layers)==len(inspected['RootFS']['Layers']), 'MANIFEST_LAYERS', 'Runtime layer count differs.')
        # Hash packed manifest layers; archive_config independently verifies decoded diff IDs.
        for desc in layers:
            identity=field(desc,'digest',str); size=field(desc,'size',int)
            require(valid_digest(identity) and type(size) is int and size>=0, 'LAYER_DESCRIPTOR', 'Malformed runtime layer descriptor.')
            name='blobs/sha256/'+identity[7:]
            require(name in members and members[name].isfile() and members[name].size==size,
                    'LAYER_MEMBER', 'Runtime manifest layer is missing or has a wrong size.')
            h=hashlib.sha256()
            with tar.extractfile(members[name]) as stream:
                for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
            require('sha256:'+h.hexdigest()==identity, 'LAYER_HASH', 'Runtime manifest layer hash differs.')
        for desc,attestation in attestations:
            require(desc['annotations'].get('vnd.docker.reference.digest')==manifest_id,
                    'ATTESTATION_SUBJECT', 'Attestation references another runtime manifest.')
            ac=field(attestation,'config',dict)
            raw_blob(field(ac,'digest',str),field(ac,'size',int))
            for layer in field(attestation,'layers',list):
                require(field(layer,'mediaType',str)=='application/vnd.in-toto+json',
                        'ATTESTATION_TYPE','Unsupported attestation layer type.')
                statement=strict_json(raw_blob(field(layer,'digest',str),field(layer,'size',int)))
                subjects=field(statement,'subject',list)
                require(bool(subjects) and all(field(field(x,'digest',dict),'sha256',str)==manifest_id[7:] for x in subjects),
                        'ATTESTATION_STATEMENT','Attestation statement subject differs from selected runtime manifest.')
        roles={config_id:'config',manifest_id:'manifest'}
        if kind in INDEX: roles[export_id]='index'
        require(inspected['Id'] in roles, 'BUILD_ID', 'Daemon ID is not an authenticated runtime graph identity.')
        require(iid in roles, 'BUILD_IID', 'Build IID is not an authenticated runtime graph identity.')
        return {'configId':config_id,'manifestId':manifest_id,'exportId':export_id,
                'exportMediaType':kind,'imageIdKind':roles[inspected['Id']], 'iidKind':roles[iid]}


def archive_config(path, inspected):
    # Ordinary docker save is only ephemeral scanner transport, never imported.
    with tarfile.open(path) as tar:
        members=tar.getmembers(); names=[m.name for m in members]
        require(len(names)==len(set(names)),'ARCHIVE_DUPLICATE','Ambiguous archive metadata.')
        def member(name):
            require(type(name) is str and name and not name.startswith('/') and '\\' not in name
                    and all(part not in ('', '.', '..') for part in name.split('/')),
                    'ARCHIVE_PATH','Unsafe archive member reference.')
            m=tar.getmember(name)
            require(m.isfile(),'ARCHIVE_MEMBER','Referenced archive member is not a regular file.')
            return m
        def data(name):
            m=member(name)
            require(m.isfile() and m.size<=4*1024*1024,'ARCHIVE_METADATA','Invalid archive metadata.')
            return tar.extractfile(m).read()
        manifest=strict_json(data('manifest.json'))
        require(type(manifest) is list and len(manifest)==1,'ARCHIVE_FORMAT','Expected one Docker runtime entry; unsupported exports stop.')
        raw=data(field(manifest[0],'Config',str)); config=strict_json(raw)
        require(config.get('os')=='linux' and config.get('architecture')=='amd64','ARCHIVE_PLATFORM','Archive platform differs.')
        require(config.get('rootfs',{}).get('diff_ids')==inspected['RootFS']['Layers'],'ARCHIVE_ROOTFS','Archive and daemon runtime layers differ.')
        layers=field(manifest[0],'Layers',list)
        diffs=field(field(config,'rootfs',dict),'diff_ids',list)
        require(len(layers)==len(diffs) and all(valid_digest(x) for x in diffs),
                'ARCHIVE_LAYERS','Layer references and runtime diff IDs must agree.')
        for name,diff in zip(layers,diffs):
            m=member(name)
            with tar.extractfile(m) as stream:
                prefix=stream.read(4); stream.seek(0)
                packed=hashlib.sha256()
                for chunk in iter(lambda:stream.read(1024*1024),b''): packed.update(chunk)
            if name.startswith('blobs/sha256/'):
                require(name=='blobs/sha256/'+packed.hexdigest(),
                        'ARCHIVE_BLOB','Layer blob digest differs from its content.')
            require(prefix!=b'\x28\xb5\x2f\xfd','ARCHIVE_COMPRESSION','Zstandard layers are unsupported; stop.')
            with tar.extractfile(m) as stream:
                decoded=gzip.GzipFile(fileobj=stream) if prefix[:2]==b'\x1f\x8b' else stream
                h=hashlib.sha256()
                try:
                    for chunk in iter(lambda:decoded.read(1024*1024),b''): h.update(chunk)
                finally:
                    if decoded is not stream: decoded.close()
            require('sha256:'+h.hexdigest()==diff,'ARCHIVE_LAYER','Exported layer bytes differ from the runtime diff ID.')
        return 'sha256:'+hashlib.sha256(raw).hexdigest()
