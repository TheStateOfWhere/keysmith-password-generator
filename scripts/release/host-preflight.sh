#!/usr/bin/env bash
# Inspection only. No extraction, privilege changes, registry access or Docker mutation.
set -Eeuo pipefail
[[ $# == 4 ]] || { printf 'Usage: bash host-preflight.sh /absolute/path/source.tar.gz EXPECTED_SHA256 PRIVATE_METADATA_JSON PRIVATE_METADATA_SHA256\n' >&2; exit 2; }
command -v python3 >/dev/null || { printf 'BLOCKER: Python 3 is required.\n' >&2; exit 2; }
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)" || exit 2
python3 -B - "$1" "$2" "$3" "$4" "$SOURCE_DIR" <<'PY'
import ast,hashlib,json,os,platform,re,shutil,socket,subprocess,sys,tarfile,types
from pathlib import Path
EXPECTED=sys.argv[2]
if not re.fullmatch(r'[0-9a-f]{64}',EXPECTED):
    print('BLOCKER: invalid trusted archive checksum');sys.exit(2)
blockers=[]; warnings=[]
def check(ok,reason):
    if not ok: blockers.append(reason)
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()
def parse(raw):
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise ValueError('Duplicate JSON field')
            d[k]=v
        return d
    def constant(_):raise ValueError('Invalid JSON constant')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
def main():
    archive=Path(sys.argv[1]).resolve(strict=True)
    if not archive.is_file() or digest(archive)!=EXPECTED:raise ValueError('Source archive checksum mismatch')
    print('Archive SHA-256: '+EXPECTED)
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers();names=[m.name for m in members]
        if len(set(names))!=len(names) or any(not m.isfile() or m.name.startswith('/') or any(p in ('','..','.') for p in m.name.split('/')) for m in members):raise ValueError('Unsafe archive layout')
        manifest=parse(tar.extractfile('SOURCE-MANIFEST.json').read())
        if type(manifest.get('files')) is not list or type(manifest.get('fileCount')) is not int or manifest['fileCount']!=len(manifest['files']):raise ValueError('Invalid source manifest')
        if manifest.get('version')!=parse(tar.extractfile('passwordforge/package.json').read()).get('version') or type(manifest.get('sourceCommit')) is not str or re.fullmatch(r'[0-9a-f]{40}',manifest['sourceCommit']) is None:raise ValueError('Release version/commit metadata invalid')
        private_namespace={}
        exec(compile(tar.extractfile('passwordforge/scripts/release/private_metadata.py').read(), 'verified-private-metadata', 'exec'),private_namespace)
        approved=private_namespace['read_metadata'](sys.argv[3],sys.argv[4])
        if EXPECTED!=approved['sourceArchiveSHA256'] or hashlib.sha256(tar.extractfile('SOURCE-MANIFEST.json').read()).hexdigest()!=approved['sourceManifestSHA256']:raise ValueError('Archive/manifest differs from private approval')
        if manifest['version']!=approved['releaseVersion'] or manifest['sourceCommit']!=approved['sourceCommit']:raise ValueError('Approved source version/commit differs')
        PRODUCTION_ID=approved['productionImageId']
        candidate_tag='passwordforge:'+approved['releaseVersion']
        listed=[e['path'] for e in manifest['files']]
        if len(set(listed))!=len(listed) or set(names)!=set(listed)|{'SOURCE-MANIFEST.json'}:raise ValueError('Manifest inventory mismatch')
        for entry in manifest['files']:
            m=tar.getmember(entry['path']);raw=tar.extractfile(m).read()
            if hashlib.sha256(raw).hexdigest()!=entry['sha256'] or len(raw)!=entry['bytes'] or m.mode!=int(entry['mode'],8):raise ValueError('Manifest bytes/mode mismatch')
        # Execute shared verifier only from the independently checksummed archive.
        saved={name:sys.modules.get(name) for name in ('security','evidence_schema','private_metadata','source_approval')}
        try:
            for name in saved:
                module=types.ModuleType(name)
                sys.modules[name]=module
                exec(compile(tar.extractfile('passwordforge/scripts/release/'+name+'.py').read(), 'approved-'+name, 'exec'),module.__dict__)
            sys.modules['source_approval'].Approval(archive,sys.argv[3],sys.argv[4]).verify_tree(Path(sys.argv[5]))
        finally:
            for name,original in saved.items():
                if original is None:sys.modules.pop(name,None)
                else:sys.modules[name]=original
        builder_code=tar.extractfile('passwordforge/scripts/release/builder_contract.py').read().decode()
        builder_namespace={}
        exec(compile(builder_code,'verified-builder-contract','exec'),builder_namespace)
        inspect_builder=builder_namespace['inspect_builder']
        dockerfile=tar.extractfile('passwordforge/Dockerfile').read().decode()
        refs=re.findall(r'^FROM\s+(\S+)',dockerfile,re.M)
        module=ast.parse(tar.extractfile('passwordforge/scripts/release/docker-release.py').read().decode())
        scanner=[ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SCANNER' for t in n.targets)]
        if len(refs)!=2 or len(scanner)!=1 or any(not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',r) for r in refs+scanner):raise ValueError('Pinned references invalid')
    print('Source manifest: '+str(len(listed))+' files verified; no extraction performed')
    if sys.platform!='linux' or os.getuid()==0:raise ValueError('Use the non-root Linux Docker operator')
    release={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);release[k]=v.strip('"')
    check(release.get('ID')=='ubuntu' and release.get('VERSION_ID')=='24.04','Expected Ubuntu 24.04')
    check(platform.machine()=='x86_64','Expected x86_64/linux/amd64 host')
    print('Host: '+platform.node()+'; OS '+release.get('ID','unknown')+' '+release.get('VERSION_ID','unknown')+'; architecture '+platform.machine())
    for tool in ('docker','bash','python3','curl','ss','free','df','sha256sum','realpath','tar'):
        check(shutil.which(tool) is not None,'Required tool missing: '+tool)
    env={k:v for k,v in os.environ.items() if not k.startswith(('BUILDX_','BUILDKIT_','COMPOSE_')) and k not in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_DEFAULT_PLATFORM','DOCKER_BUILDKIT')}
    def run(args):
        p=subprocess.run(args,capture_output=True,text=True,timeout=30,env=env)
        if p.returncode:raise ValueError('Read-only command failed: '+args[0]+' '+args[1])
        return p.stdout.strip()
    def docker(args):
        # Explicit read-only allowlist: no arbitrary operator-supplied Docker arguments.
        pair=tuple(args[:2])
        if pair not in {('version','--format'),('info','--format'),('compose','version'),('buildx','inspect'),('context','inspect'),('image','inspect'),('image','ls'),('container','ls'),('container','inspect'),('network','inspect')}:
            raise ValueError('Forbidden Docker operation')
        return run(['docker','--host','unix:///var/run/docker.sock',*args])
    def fmt(args,template):return parse(docker(args+['--format',template]))
    versions=fmt(['version'],'{"client":{{json .Client.Version}},"engine":{{json .Server.Version}},"os":{{json .Server.Os}},"arch":{{json .Server.Arch}}}')
    print('Docker versions/platform: '+json.dumps(versions))
    check(versions.get('os')=='linux' and versions.get('arch')=='amd64','Unexpected daemon architecture/OS')
    check(type(versions.get('engine')) is str and versions['engine'].startswith('29.'),'Expected reviewed Engine 29.x')
    print('Compose: '+docker(['compose','version','--short']))
    endpoint=inspect_builder(docker(['buildx','inspect','default']))
    if endpoint=='default':
        contexts=parse(docker(['context','inspect','default']))
        if type(contexts) is not list or len(contexts)!=1:raise ValueError('Context metadata invalid')
        endpoint=contexts[0]['Endpoints']['docker']['Host']
    check(endpoint=='unix:///var/run/docker.sock','Builder is not the local Docker socket')
    # buildx version is standalone read-only; no bootstrap/creation.
    print('Buildx version: '+run(['docker','--host','unix:///var/run/docker.sock','buildx','version']))
    print('Builder: default; driver docker; one running node; linux/amd64 advertised; local socket '+str(endpoint=='unix:///var/run/docker.sock'))
    info=fmt(['info'],'{"root":{{json .DockerRootDir}},"memoryBytes":{{json .MemTotal}},"cpus":{{json .NCPU}}}')
    print('Daemon resources: '+json.dumps(info))
    for location in (archive.parent,Path(info['root'])):
        try:
            usage=shutil.disk_usage(location);print('Disk '+str(location)+': availableBytes='+str(usage.free)+' totalBytes='+str(usage.total))
        except OSError:check(False,'Cannot read Docker/staging disk capacity; operator must obtain read-only evidence')
    mem={line.split(':')[0]:line.split(':')[1].strip() for line in Path('/proc/meminfo').read_text().splitlines() if ':' in line}
    check('MemAvailable' in mem,'Available memory could not be determined')
    print('Available host memory: '+mem.get('MemAvailable','unknown'))
    template='{"id":{{json .Id}},"imageId":{{json .Image}},"status":{{json .State.Status}},"started":{{json .State.StartedAt}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"none"{{end}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"enabled":{{json (index .Config.Labels "traefik.enable")}},"network":{{json (index .Config.Labels "traefik.docker.network")}},"rule":{{json (index .Config.Labels "traefik.http.routers.passwordforge.rule")}},"entrypoint":{{json (index .Config.Labels "traefik.http.routers.passwordforge.entrypoints")}},"tls":{{json (index .Config.Labels "traefik.http.routers.passwordforge.tls")}},"routerService":{{json (index .Config.Labels "traefik.http.routers.passwordforge.service")}},"backendPort":{{json (index .Config.Labels "traefik.http.services.passwordforge.loadbalancer.server.port")}},"networks":{{json .NetworkSettings.Networks}}}'
    compose_path=Path(approved['productionComposePath'])
    check(not compose_path.is_symlink() and compose_path.is_file() and digest(compose_path)==approved['productionComposeSHA256'],'Production Compose checksum mismatch')
    prod=fmt(['container','inspect',approved['productionContainerName']],template)
    print('PasswordForge: '+json.dumps({k:prod[k] for k in ('id','imageId','status','started','health')}))
    check(prod.get('imageId')==PRODUCTION_ID and prod.get('id')==approved['productionContainerId'] and prod.get('started')==approved['productionStartedAt'],'Unexpected production immutable identity')
    check(prod['status']=='running' and prod['health']=='healthy','Existing PasswordForge is not running/healthy')
    for k,v in {'project':approved['composeProject'],'service':approved['composeService'],'enabled':'true','network':approved['proxyNetwork'],'rule':'Host(`'+approved['routerHost']+'`)','entrypoint':approved['httpsEntryPoint'],'tls':'true','routerService':'passwordforge','backendPort':'8080'}.items():check(prod.get(k)==v,'Existing production routing/project mismatch: '+k)
    check(type(prod['networks']) is dict and set(prod['networks'])=={approved['proxyNetwork']} and prod['networks'][approved['proxyNetwork']].get('NetworkID')==approved['proxyNetworkId'],'Production container missing proxy attachment')
    print('Routing: approved private routing / TLS / port 8080 labels checked; certificates/public HTTPS are NOT verified')
    image_template='{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}}}'
    current=fmt(['image','inspect',approved['productionImageTag']],image_template)
    print('Protected production/rollback tag identity: '+json.dumps(current));check(current['id']==prod['imageId']==PRODUCTION_ID and current.get('os')=='linux' and current.get('arch')=='amd64','Production tag identity/platform differs')
    tags=docker(['image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines()
    check(not any(t.startswith((candidate_tag,'passwordforge:dev-','passwordforge:validation','pfcheck','pfscan')) for t in tags),'Conflicting candidate/development/validation image tag')
    containers=docker(['container','ls','-a','--format','{{.ID}} {{.Names}} {{.Image}}']).splitlines()
    check(not any(re.search(r'\b(?:pfscan-|pfcheck-)',row) or (len(row.split())==3 and row.split()[2]==candidate_tag) for row in containers),'Existing candidate/validation container conflict')
    services=docker(['container','ls','-a','--no-trunc','--filter','label=com.docker.compose.project='+approved['composeProject'],'--filter','label=com.docker.compose.service='+approved['composeService'],'--format','{{.ID}}']).splitlines()
    check(services==[prod['id']],'Ambiguous production project/service container state')
    traefik=[row.split()[0] for row in containers if len(row.split())==3 and ('traefik' in row.split()[1].lower() or row.split()[2].split('/')[-1].startswith('traefik:'))]
    check(bool(traefik),'No existing Traefik container identified')
    for cid in traefik:
        t=fmt(['container','inspect',cid],'{"id":{{json .Id}},"imageId":{{json .Image}},"status":{{json .State.Status}},"networks":{{json .NetworkSettings.Networks}}}')
        print('Traefik: '+json.dumps({k:t[k] for k in ('id','imageId','status')}));check(t['status']=='running' and approved['proxyNetwork'] in t['networks'],'Traefik running/proxy attachment mismatch')
    net=fmt(['network','inspect',approved['proxyNetwork']],'{"id":{{json .Id}},"driver":{{json .Driver}},"scope":{{json .Scope}}}')
    check(net.get('id')==approved['proxyNetworkId'],'Approved proxy network identity mismatch')
    print('Existing proxy network identity verified')
    lock=Path.home()/'.cache/passwordforge-docker.lock';check(not lock.exists(),'Existing operator lock requires manual review; no removal permitted')
    for ref in refs+scanner:
        try:
            cached=fmt(['image','inspect','--platform','linux/amd64',ref],image_template)
            check(cached.get('os')=='linux' and cached.get('arch')=='amd64' and bool(re.fullmatch(r'sha256:[0-9a-f]{64}',cached.get('id',''))),'Cached pinned image has unexpected identity/platform')
            print('Cached pinned image: '+ref+' -> '+cached['id'])
        except Exception:check(False,'Pinned image absent/uninspectable: '+ref+'; acquisition needs separate approval')
    if shutil.which('ss'):
        listening=run(['ss','-H','-ltn','sport = :18080']);check(not listening,'Loopback validation port 18080 is already in use')
    check(fmt(['image','inspect',approved['productionImageTag']],image_template)==current,'Protected image identity changed during preflight')
    check(fmt(['container','inspect',approved['productionContainerName']],template)==prod,'Production metadata changed during inspection; review before proceeding')
    check(digest(compose_path)==approved['productionComposeSHA256'],'Production Compose changed during inspection')
    check(private_namespace['read_metadata'](sys.argv[3],sys.argv[4])==approved,'Private approval metadata changed during inspection')
    print('Capacity requires operator review; this inspection does not prove build/scanner memory or disk sufficiency.')
    print('STOP: no build, pull, scan, runtime, import, deployment or cleanup is authorized by this preflight.')
try:main()
except Exception as e:
    # Tool stderr and arbitrary metadata are never echoed; they may contain secrets.
    blockers.append('Incomplete preflight: '+type(e).__name__+'; required checksum, metadata or read-only command failed')
for reason in blockers:print('BLOCKER: '+reason)
print('Preflight blockers: '+str(len(blockers)))
sys.exit(2 if blockers else 0)
PY
