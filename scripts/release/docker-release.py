#!/usr/bin/env python3
"""Small operator helper around Docker build/save/run. Never deploys or imports.

--approval ARCHIVE PRIVATE_JSON TRUSTED_SHA256 build VERSION | scan|check IMAGE DIRECTORY
runtime IMAGE DIRECTORY PRIVATE_JSON TRUSTED_SHA256
Each operation is explicit. Interrupted attempts require review, never replay.
"""
import collections
import contextlib
import datetime as dt
import hashlib
import gzip
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
from security import require, valid_digest, SecurityError
from evidence_schema import field, strict_json, scan_schema
from checks import load, database, isolation
from scan_contract import combine
from builder_contract import inspect_builder
from build_identity import verify as verify_build_identity
from private_metadata import read_metadata
from runtime_inputs import prepare_inputs, load_inputs, production_inspection
from source_approval import Approval
import build_proof

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parents[1]
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
SCANNER = 'docker.io/aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa'
LABEL = 'org.passwordforge.scan-run'
APPROVAL = None

def environment():
    env = {k:v for k,v in os.environ.items()
           if not k.startswith(('BUILDX_', 'BUILDKIT_', 'COMPOSE_'))
           and k not in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_DEFAULT_PLATFORM','DOCKER_BUILDKIT')}
    env.update(DOCKER_BUILDKIT='1', PYTHONDONTWRITEBYTECODE='1')
    return env

def command(args, log=None, timeout=300, input_text=None, input_bytes=None):
    require(input_text is None or input_bytes is None, 'COMMAND_INPUT', 'Ambiguous command input.')
    try:
        p = subprocess.run(args, capture_output=True, env=environment(), cwd=SOURCE, timeout=timeout, input=input_bytes if input_text is None else input_text.encode())
    except subprocess.TimeoutExpired as error:
        if log:
            with Path(log).open('xb') as f: f.write((error.stdout or b'')+(error.stderr or b''))
            save(str(log)+'.status.json',{'exitCode':None,'timedOut':True})
        raise SecurityError('COMMAND_TIMEOUT','Command timed out; stop and inspect owned resources.') from None
    if log:
        with Path(log).open('xb') as f: f.write(p.stdout + p.stderr)
        save(str(log)+'.status.json',{'exitCode':p.returncode,'timedOut':False})
    require(p.returncode == 0, 'COMMAND_FAILED', 'Command failed; retained private log is not a clean result.')
    return p.stdout.decode('utf-8')

def save(path, value):
    with Path(path).open('x', encoding='utf-8') as f: json.dump(value,f,indent=2); f.write('\n')

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def source_hash():
    # Hash every actual Docker COPY input, not a hand-maintained release inventory.
    paths=[SOURCE/n for n in ('Dockerfile','nginx.conf','package.json','package-lock.json','tsconfig.json','.dockerignore','compose.yaml','compose.dev.yaml','.gitignore')]
    for directory in ('src','public','scripts','tests','data'):
        paths.extend(p for p in (SOURCE/directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    h=hashlib.sha256()
    for p in sorted(paths):
        require(not p.is_symlink(),'SOURCE_LINK','Symlink build inputs are unsupported.')
        h.update(p.relative_to(SOURCE).as_posix().encode()+b'\0'+bytes.fromhex(sha(p)))
    return h.hexdigest()

@contextlib.contextmanager
def locked():
    # Shared across this operator's source copies; never auto-recover a stale lock.
    path=Path.home()/'.cache/passwordforge-docker.lock'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.mkdir(mode=0o700)
    token=secrets.token_hex(16)
    save(path/'owner.json',{'token':token,'pid':os.getpid()})
    try: yield
    finally:
        require(load(path/'owner.json').get('token')==token,'LOCK_OWNER','Lock ownership changed; stop.')
        (path/'owner.json').unlink(); path.rmdir()

def image(ref):
    d=strict_json(command(DOCKER+['image','inspect',ref]))
    require(type(d) is list and len(d)==1 and type(d[0]) is dict,'IMAGE_SCHEMA','Invalid image inspection.')
    return d[0]

def platform(d):
    require(d.get('Os')=='linux' and d.get('Architecture')=='amd64' and d.get('Variant') in (None,'','v1'),
            'PLATFORM','Only linux/amd64 is approved.')
    require(valid_digest(d.get('Id')),'IMAGE_ID','Missing full immutable image ID.')

def builder():
    require(os.name=='posix' and os.getuid()!=0,'OPERATOR','Use a non-root Linux operator with Docker access.')
    require(command(DOCKER+['version','--format','{{.Server.Os}}/{{.Server.Arch}}']).strip()=='linux/amd64',
            'DAEMON','Expected local Linux/amd64 Engine.')
    endpoint=inspect_builder(command(DOCKER+['buildx','inspect','default']))
    if endpoint=='default':
        context=strict_json(command(DOCKER+['context','inspect','default']))
        require(type(context) is list and len(context)==1,'CONTEXT','Invalid default context.')
        endpoint=context[0]['Endpoints']['docker']['Host']
    require(endpoint=='unix:///var/run/docker.sock','BUILDER_ENDPOINT','Builder must use the approved local socket.')

def reference(value):
    require(type(value) is str and re.fullmatch(r'passwordforge:[0-9]+\.[0-9]+\.[0-9]+',value),
            'TAG','Use an explicit PasswordForge semantic version tag.')
    return value

def cached_image(ref):
    require(type(ref) is str and re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',ref), 'PIN', 'Require an immutable cached reference.')
    d=strict_json(command(DOCKER+['image','inspect','--platform','linux/amd64',ref]))
    require(type(d) is list and len(d)==1 and type(d[0]) is dict,'IMAGE_SCHEMA','Invalid cached image inspection.')
    platform(d[0]); return d[0]

def approval():
    require(isinstance(APPROVAL, Approval), 'APPROVAL_REQUIRED', 'Explicit checksummed archive/private approval is required.')
    APPROVAL.refresh(SOURCE)
    return APPROVAL


def protected():
    approved=approval(); m=dict(approved.metadata)
    selected='{"containerId":{{json .Id}},"imageId":{{json .Image}},"startedAt":{{json .State.StartedAt}},"name":{{json .Name}},"status":{{json .State.Status}},"health":{{json .State.Health.Status}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}}}'
    baseline=prepare_inputs('passwordforge:'+m['releaseVersion'],{'version':m['releaseVersion']},
        {'Config':{'Labels':{'org.opencontainers.image.version':m['releaseVersion']}}},m)
    production_inspection(baseline,command(DOCKER+['inspect','--format',selected,m['productionContainerName']]),'sha256:'+('0'*64 if m['productionImageId']!='sha256:'+'0'*64 else '1'*64))
    require(image(m['productionImageTag'])['Id']==m['productionImageId'], 'PRODUCTION_IMAGE', 'Protected production tag changed.')
    require(sha(Path(m['productionComposePath']))==m['productionComposeSHA256'], 'PRODUCTION_COMPOSE', 'Private production Compose changed.')
    network=strict_json(command(DOCKER+['network','inspect','--format','{{json .Id}}',m['proxyNetwork']]))
    require(network==m['proxyNetworkId'], 'PRODUCTION_NETWORK', 'Protected network identity changed.')
    membership=strict_json(command(DOCKER+['inspect','--format','{{json .NetworkSettings.Networks}}',m['productionContainerName']]))
    require(type(membership) is dict and type(membership.get(m['proxyNetwork'])) is dict
            and membership[m['proxyNetwork']].get('NetworkID')==m['proxyNetworkId'],
            'PRODUCTION_NETWORK','Production proxy membership changed.')


def build(version):
    approved=approval()
    tag=reference('passwordforge:'+version)
    require(version==approved.identity['version'] and version==load(SOURCE/'package.json')['version'],
            'VERSION','Tag must match approved source version.')
    builder(); protected()
    tags=command(DOCKER+['image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines()
    require(tag not in tags,'TAG_COLLISION','Version tag already exists; never overwrite it.')
    refs=re.findall(r'^FROM\s+(\S+)',approved.files['Dockerfile'][0].decode(),re.M)
    require(len(refs)==2,'BASES','Require two pinned base images.')
    for ref in refs: cached_image(ref)
    run=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dt%H%M%Sz')+'-'+secrets.token_hex(8)
    out=SOURCE/'validation-results'/run; out.mkdir(parents=True,mode=0o700)
    print('Evidence: '+str(out),flush=True)
    fingerprint=approved.fingerprint
    save(out/'approval.json',dict(approved.identity))
    with (out/'SOURCE-MANIFEST.json').open('xb') as f: f.write(approved.manifest)
    with (out/'build-context.tar').open('xb') as f: f.write(approved.context)
    save(out/'build-started.json',{'schemaVersion':1,'image':tag,'run':run,
        'approval':dict(approved.identity),'sourceSHA256':fingerprint})
    # Validate only the frozen example, never production Compose.
    with (out/'example-compose.yaml').open('xb') as f: f.write(approved.files['compose.yaml'][0])
    command(DOCKER+['compose','--env-file','/dev/null','-p','passwordforge','-f',str(out/'example-compose.yaml'),'config','--quiet'])
    # stdin is a frozen in-memory tar, never a live directory or external context.
    protected()
    command(DOCKER+['buildx','build','--builder','default','--platform','linux/amd64','--pull=false',
                    '--label',LABEL+'='+run,'--label','org.passwordforge.source='+fingerprint,
                    '--iidfile',str(out/'build.iid'),'--metadata-file',str(out/'build-metadata.json'),
                    '--tag',tag,'-'],out/'build.log',3600,input_bytes=approved.context)
    protected()
    d=image(tag); platform(d)
    record=validate_build(tag,out,d,fingerprint,run)
    publish_build(out,record)
    build_proof.validate(out,record,approved)
    print('Build complete; STOP for scan. Evidence: '+str(out))

def validate_build(tag,out,d,fingerprint,run):
    platform(d)
    version=tag.split(':')[1]
    labels=field(field(d,'Config',dict),'Labels',dict)
    require(labels.get(LABEL)==run and labels.get('org.passwordforge.source')==fingerprint,
            'BUILD_OWNERSHIP','Build ownership/source labels differ.')
    require(approval().fingerprint==fingerprint,'SOURCE_CHANGED','Source changed during build; candidate is not approved.')
    require(labels.get('org.opencontainers.image.version')==version,'VERSION','Image version differs.')
    metadata=load(out/'build-metadata.json')
    archive=out/'build-identity.tar'
    # Full export retains the index/attestations; platform-filtered save may drop the root.
    command(DOCKER+['image','save','--output',str(archive),d['Id']],out/'identity-save.log',900)
    config_id=archive_config(archive,d)
    identities=verify_build_identity(archive,metadata,d,(out/'build.iid').read_text().strip(),config_id)
    require(image(tag)['Id']==d['Id'] and approval().fingerprint==fingerprint,
            'BUILD_CHANGED','Candidate/source changed during identity verification.')
    record={'schemaVersion':1,'approval':dict(approval().identity),'image':tag,'imageId':d['Id'],'sourceSHA256':fingerprint,'run':run,
            'metadataSHA256':sha(out/'build-metadata.json'),'identityArchiveSHA256':sha(archive),**identities,'artifacts':build_proof.hashes(out)}
    save(out/'build-identity.json',record)
    # Retain the authenticated graph/layers as mandatory private proof.
    return record

def publish_build(out,record):
    with (out/'image.id').open('x') as f: f.write(record['imageId']+'\n')
    save(out/'build.json',record)

def verify_existing(version,previous,expected):
    # Legacy successful builds have no authenticated snapshot/approval receipt.
    # Never manufacture that missing proof during image reconciliation.
    require(False,'REBUILD_REQUIRED','Legacy evidence cannot establish approved build context; a separately approved new build is required.')

def candidate(ref,out):
    reference(ref); approved=approval(); record=load(out/'build.json')
    build_proof.validate(out,record,approved)
    d=image(ref); platform(d)
    require(record['image']==ref and record['imageId']==d['Id'],'IDENTITY','Candidate tag changed; never substitute an image.')
    labels=field(field(d,'Config',dict),'Labels',dict)
    require(labels.get(LABEL)==record['run'] and labels.get('org.passwordforge.source')==record['sourceSHA256']
            and labels.get('org.opencontainers.image.version')==approved.identity['version'],
            'OWNERSHIP','Candidate ownership/source/version differs.')
    config_id=archive_config(out/'build-identity.tar',d)
    actual=verify_build_identity(out/'build-identity.tar',load(out/'build-metadata.json'),d,
        (out/'build.iid').read_text().strip(),config_id)
    require(all(record[k]==v for k,v in actual.items()),'BUILD_IDENTITY','Export proof differs from current candidate.')
    return d,record

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

def scan_results(out, config_id):
    d=load(out/'vulnerabilities.json'); scan_schema(d); database(out/'database-metadata.json')
    require(d['Metadata']['ImageID']==config_id,'SCAN_IDENTITY','Scanner analyzed a different runtime config.')
    require(any(r['Class']=='os-pkgs' and r['Packages'] for r in d['Results']),'OS_INVENTORY','Runtime OS inventory missing.')
    counts=collections.Counter({s:0 for s in ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')}); rows=[]
    for r in d['Results']:
        for v in r['Vulnerabilities']:
            counts[v['Severity']]+=1
            rows.append({k:v.get(k,'') for k in ('Severity','PkgName','VulnerabilityID','InstalledVersion','FixedVersion')})
    return dict(counts),rows

def scan_gate(out, config_id):
    counts,rows=scan_results(out,config_id)
    require(not any(counts[s] for s in ('CRITICAL','HIGH','UNKNOWN')),'VULNERABILITY_GATE','HIGH/CRITICAL/UNKNOWN findings block runtime and deployment.')
    return counts,rows

def owned_remove(container_id,run):
    require(type(container_id) is str and re.fullmatch(r'[0-9a-f]{64}',container_id),
            'CONTAINER_ID','Cleanup requires a captured full container ID.')
    ids=command(DOCKER+['container','ls','-a','--no-trunc','--format','{{.ID}}']).splitlines()
    if container_id not in ids: return
    d=strict_json(command(DOCKER+['inspect','--format',
        '{"Id":{{json .Id}},"Labels":{{json .Config.Labels}}}',container_id]))
    require(d.get('Id')==container_id and field(d,'Labels',dict).get(LABEL)==run,
            'CLEANUP_OWNER','Refuse deletion of an unowned container ID.')
    protected()
    command(DOCKER+['container','rm','-f',container_id])
    protected()

def scanner_cleanup(work,out,containers,run):
    errors=[]
    # Preserve even partial/malformed output: it is evidence, never a passed gate.
    for name in ('native','explicit'):
        src=work/f'output/{name}.json'; dst=out/f'{name}.json'
        try:
            if src.exists():
                require(src.is_file() and not src.is_symlink(),'SCAN_OUTPUT','Unsafe scanner output.')
                with src.open('rb') as source, dst.open('xb') as target:
                    shutil.copyfileobj(source,target)
        except Exception: errors.append('preserve-'+name)
    for container_id in containers:
        try: owned_remove(container_id,run)
        except Exception: errors.append('cleanup-'+container_id)
    save(out/'scanner-cleanup.json',{'status':'failed' if errors else 'passed','errors':errors})
    # Keep scratch evidence if preservation or resource cleanup failed; no broad deletion.
    if not errors: shutil.rmtree(work)
    require(not errors,'SCANNER_CLEANUP','Evidence preservation/resource cleanup failed; inspect private evidence.')

def scan(ref,out):
    d,record=candidate(ref,out); protected(); save(out/'scan-started.json',{'imageId':d['Id'],**build_proof.continuity(record)})
    work=out/'scanner'; work.mkdir(mode=0o700)
    for n in ('input','output','cache'): (work/n).mkdir()
    run=record['run']; containers=[]
    try:
        archive=work/'input/image.tar'
        command(DOCKER+['image','save','--platform','linux/amd64','--output',str(archive),d['Id']],out/'save.log')
        config_id=archive_config(archive,d); archive_sha=sha(archive)
        require(config_id==record['configId'],'BUILD_CONFIG','Saved runtime config does not match the build export config digest.')
        shutil.copyfile(ROOT/'scan-contract.tpl',work/'input/scan-contract.tpl')
        scanner=cached_image(SCANNER)
        def run_scanner(step,network,args):
            name='pfscan-'+run+'-'+step
            require(name not in command(DOCKER+['container','ls','-a','--format','{{.Names}}']).splitlines(),'CONTAINER_COLLISION','Scanner name exists.')
            protected()
            container_id=command(DOCKER+['create','--pull','never','--name',name,'--label',LABEL+'='+run,'--network',network,
                    '--read-only','--user',str(os.getuid())+':'+str(os.getgid()),'--cap-drop','ALL',
                    '--security-opt','no-new-privileges:true','--pids-limit','128','--memory','1g','--cpus','1',
                    '--tmpfs','/tmp:rw,noexec,nosuid,size=256m,mode=1777','--env','HOME=/tmp',
                    '--mount',f'type=bind,src={work}/cache,dst=/cache',
                    '--mount',f'type=bind,src={work}/input,dst=/input,readonly',
                    '--mount',f'type=bind,src={work}/output,dst=/output',scanner['Id'],'--cache-dir','/cache',*args]).strip()
            require(re.fullmatch(r'[0-9a-f]{64}',container_id) is not None,'CONTAINER_ID','Create did not return a full container ID; inspect named resource manually.')
            containers.append(container_id)
            save(out/(step+'-container.json'),{'containerId':container_id,'name':name,'run':run})
            selected='{"NetworkMode":{{json .HostConfig.NetworkMode}},"Networks":{{json .NetworkSettings.Networks}},"User":{{json .Config.User}},"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"Privileged":{{json .HostConfig.Privileged}},"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"Memory":{{json .HostConfig.Memory}},"PidsLimit":{{json .HostConfig.PidsLimit}},"NanoCpus":{{json .HostConfig.NanoCpus}},"PortBindings":{{json .HostConfig.PortBindings}},"Mounts":{{json .Mounts}}}'
            save(out/(step+'-isolation.json'),strict_json(command(DOCKER+['inspect','--format',selected,container_id])))
            isolation(out/(step+'-isolation.json'),network,str(os.getuid())+':'+str(os.getgid()),str(work))
            protected()
            command(DOCKER+['start','-a',container_id],out/(step+'.log'),1200)
            require(command(DOCKER+['inspect','--format','{{.State.ExitCode}}',container_id]).strip()=='0','SCANNER_EXIT','Scanner exit failed.')
        run_scanner('version','none',['--version'])
        require('Version: 0.75.0' in (out/'version.log').read_text(),'SCANNER_VERSION','Unexpected scanner version.')
        save(out/'scanner-identity.json',{'imageId':scanner['Id'],'reference':SCANNER})
        run_scanner('db','bridge',['image','--download-db-only','--disable-telemetry','--no-progress'])
        shutil.copyfile(work/'cache/db/metadata.json',out/'database-metadata.json'); database(out/'database-metadata.json')
        dbsha=sha(work/'cache/db/trivy.db'); metasha=sha(work/'cache/db/metadata.json')
        save(out/'scan-input.json',{'imageId':d['Id'],'configId':config_id,'archiveSHA256':archive_sha,'databaseSHA256':dbsha})
        args=['image','--input','/input/image.tar','--skip-db-update','--skip-java-db-update','--offline-scan',
              '--disable-telemetry','--skip-version-check','--scanners','vuln','--pkg-types','os,library',
              '--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--ignorefile','/dev/null',
              '--exit-code','0','--no-progress','--timeout','15m']
        run_scanner('native','none',args+['--list-all-pkgs','--format','json','--output','/output/native.json'])
        run_scanner('explicit','none',args+['--format','template','--template','@/input/scan-contract.tpl','--output','/output/explicit.json'])
        require(sha(archive)==archive_sha and sha(work/'cache/db/trivy.db')==dbsha and sha(work/'cache/db/metadata.json')==metasha,
                'SCAN_INPUT_CHANGED','Scanner input/database changed.')
        for n in ('version','db','native','explicit'):
            require(not re.search(r'\b(WARN|ERROR|FATAL)\b',(out/(n+'.log')).read_text()),'SCANNER_LOG','Scanner warning/error requires review.')
        combine(work/'output/native.json',work/'output/explicit.json',out/'vulnerabilities.json')
        # Preserve all findings even when the security gate rejects the candidate.
        counts,rows=scan_results(out,config_id)
        save(out/'scan-findings.json',{'counts':counts,'findings':rows})
        with (out/'SCAN-REPORT.md').open('x') as f:
            f.write('Runtime image: '+d['Id']+'\n\n'+json.dumps({'counts':counts,'findings':rows},indent=2)+'\nHIGH/CRITICAL/UNKNOWN block validation. MEDIUM findings require operator disposition. No deployment approval.\n')
        scan_gate(out,config_id)
    finally:
        scanner_cleanup(work,out,containers,run)
    candidate(ref,out); protected()
    save(out/'scan.json',{**build_proof.continuity(record),'imageId':d['Id'],'configId':config_id,'resultSHA256':sha(out/'vulnerabilities.json'),
                        'metadataSHA256':sha(out/'database-metadata.json'),'counts':counts,'findings':rows})
    print('Scan passed; STOP for runtime validation and findings review.')

def passed_scan(ref,out):
    d,record=candidate(ref,out); gate=load(out/'scan.json')
    build_proof.same_attempt(gate,record)
    build_proof.same_attempt(load(out/'scan-started.json'),record)
    require(load(out/'scan-started.json').get('imageId')==d['Id'],'SCAN_ATTEMPT','Scan start identity differs.')
    require(gate['imageId']==d['Id'] and sha(out/'vulnerabilities.json')==gate['resultSHA256']
            and sha(out/'database-metadata.json')==gate['metadataSHA256'],'SCAN_BINDING','Scan evidence changed.')
    require(gate.get('configId')==record['configId'],'SCAN_CONFIG_BINDING','Scan config differs from the authoritative build config.')
    counts,rows=scan_gate(out,record['configId'])
    require(counts==gate['counts'] and rows==gate['findings'],'SCAN_SUMMARY','Scan summary differs.')
    return d,record

def runtime(ref,out,private_path=None,private_sha256=None):
    d,record=passed_scan(ref,out)
    require(isinstance(private_path,(str,Path)) and type(private_sha256) is str,
            'RUNTIME_APPROVAL','Runtime requires explicit checksummed private metadata.')
    bound=approval()
    require(Path(private_path).absolute()==bound.private and private_sha256==bound.checksum,
            'RUNTIME_APPROVAL','Runtime metadata differs from build approval.')
    approved=read_metadata(private_path,private_sha256)
    protected()
    inputs=prepare_inputs(ref,load(SOURCE/'package.json'),d,approved)
    save(out/'runtime-inputs.json',inputs)
    load_inputs(out/'runtime-inputs.json')
    save(out/'runtime-started.json',{'imageId':d['Id'],**build_proof.continuity(record)})
    work=out/'runtime'; work.mkdir(mode=0o700)
    token=secrets.token_hex(32)
    boundary=out/'runtime-boundary.json'
    save(boundary,{'parentPID':os.getpid(),'tokenSHA256':hashlib.sha256(token.encode()).hexdigest(),
                   'inputsSHA256':sha(out/'runtime-inputs.json'),
                   'approvalArchive':str(bound.archive),'approvalPrivate':str(bound.private),'approvalChecksum':bound.checksum})
    try:
        command(['bash',str(ROOT/'runtime.sh'),str(work),record['run'],d['Id'],str(SOURCE)],out/'runtime.log',300,input_text=token+'\n')
    finally:
        boundary.unlink()
    result=load(work/'runtime-validation.json')
    require(result.get('status')=='passed' and result.get('imageId')==d['Id']
            and result.get('version')==inputs['version'],'RUNTIME','Runtime result/version missing or mismatched.')
    passed_scan(ref,out); protected()
    save(out/'runtime.json',{**build_proof.continuity(record),'imageId':d['Id'],'resultSHA256':sha(work/'runtime-validation.json')})
    print('Runtime passed; STOP. Deployment still requires operator approval.')

def check(ref,out):
    d,record=passed_scan(ref,out); r=load(out/'runtime.json'); actual=load(out/'runtime/runtime-validation.json')
    build_proof.same_attempt(r,record)
    build_proof.same_attempt(load(out/'runtime-started.json'),record)
    require(load(out/'runtime-started.json').get('imageId')==d['Id'],'RUNTIME_ATTEMPT','Runtime start identity differs.')
    require(actual.get('version')==approval().identity['version'],'RUNTIME_VERSION','Runtime version differs from approval.')
    require(r['imageId']==d['Id'] and r['resultSHA256']==sha(out/'runtime/runtime-validation.json')
            and actual.get('status')=='passed' and actual.get('imageId')==d['Id'],'RUNTIME_BINDING','Runtime evidence changed.')
    return d['Id']

def runtime_guard(target,out,token):
    global APPROVAL
    require(out.parent==SOURCE/'validation-results','DIRECTORY','Wrong runtime directory.')
    require(type(token) is str and re.fullmatch(r'[0-9a-f]{64}',token) is not None,
            'RUNTIME_BOUNDARY','Direct runtime invocation is prohibited.')
    boundary=load(out/'runtime-boundary.json')
    require(boundary.get('inputsSHA256')==sha(out/'runtime-inputs.json'),
            'RUNTIME_INPUTS','Runtime inputs changed outside the locked operation.')
    load_inputs(out/'runtime-inputs.json')
    owner=load(Path.home()/'.cache/passwordforge-docker.lock/owner.json')
    require(type(boundary.get('parentPID')) is int and boundary['parentPID']==owner.get('pid')
            and boundary.get('tokenSHA256')==hashlib.sha256(token.encode()).hexdigest(),
            'RUNTIME_BOUNDARY','Runtime is outside its owning locked operation.')
    os.kill(boundary['parentPID'],0)
    APPROVAL=Approval(boundary['approvalArchive'],boundary['approvalPrivate'],boundary['approvalChecksum'])
    record=load(out/'build.json'); d,_=passed_scan(record['image'],out)
    build_proof.same_attempt(load(out/'runtime-started.json'),record)
    protected()
    require(d['Id']==target and load(out/'runtime-started.json').get('imageId')==target,
            'RUNTIME_GUARD','Runtime helper is not bound to the passed scan.')
    require(not (out/'runtime/runtime-validation.json').exists(),'RUNTIME_REPLAY','Existing runtime evidence must not be overwritten.')
    save(out/'runtime-consumed.json',{'imageId':target})

def interrupted(*_):
    raise SecurityError('INTERRUPTED','Interrupted; preserve evidence and review, never replay.')

def main():
    global SOURCE, APPROVAL
    os.umask(0o077)
    for s in (signal.SIGINT,signal.SIGTERM): signal.signal(s,interrupted)
    try:
        argv=sys.argv[1:]
        if argv[:1]==['--source']:
            require(len(argv)>=3,'USAGE','--source requires an original source directory and operation.')
            SOURCE=Path(argv[1]).resolve(); argv=argv[2:]
        require(ROOT == SOURCE/'scripts/release', 'TOOL_SOURCE',
                'Run the release helper from the approved staged source, not another tooling copy.')
        if argv[:1]==['--approval']:
            require(len(argv)>=5,'USAGE','--approval requires ARCHIVE PRIVATE_JSON TRUSTED_SHA256 and operation.')
            APPROVAL=Approval(argv[1],argv[2],argv[3]); argv=argv[4:]
        action,*args=argv
        if action=='runtime-guard' and len(args)==2:
            require(os.name=='posix','OPERATOR','Runtime boundary requires a Linux operator.')
            runtime_guard(args[0],Path(args[1]).resolve(),sys.stdin.readline().strip())
            return 0
        require(action in ('build','scan','runtime','check','verify-existing') and len(args)==(1 if action=='build' else 3 if action=='verify-existing' else 4 if action=='runtime' else 2),'USAGE','build VERSION | scan|check IMAGE DIRECTORY | runtime IMAGE DIRECTORY PRIVATE_JSON TRUSTED_SHA256')
        approval()
        with locked():
            if action=='build': build(*args)
            elif action=='verify-existing': verify_existing(*args)
            else:
                out=Path(args[1]).resolve()
                require(out.parent==SOURCE/'validation-results' and not Path(args[1]).is_symlink(),'DIRECTORY','Use the exact build evidence directory.')
                result=runtime(args[0],out,args[2],args[3]) if action=='runtime' else globals()[action](args[0],out)
                if action=='check': print(result)
    except Exception as error:
        print('STOP ['+(error.code if isinstance(error,SecurityError) else 'IO_OR_SCHEMA')+']; '+(str(error) if isinstance(error,SecurityError) else 'I/O or malformed evidence; review private files')+'; no deployment performed.',file=sys.stderr)
        return 2
    return 0

if __name__=='__main__': sys.exit(main())
