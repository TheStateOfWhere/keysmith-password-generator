#!/usr/bin/env python3
"""Explicit single-host stages. No automatic pulls, progression or deployment.

The operator trusts this checkout, target file and daemon. Hashes detect drift;
they are not signatures. One operator, no concurrent filesystem/daemon writers.
"""
import argparse
import collections
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import time
from urllib.parse import urlsplit
from security import require, valid_digest, SecurityError
from evidence_schema import strict_json, field, scan_schema
from builder_contract import inspect_builder
from build_identity import archive_config, verify as verify_identity
from checks import database, hardening, isolation
from scan_contract import combine

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = Path(__file__).resolve().parent
ENDPOINT = 'unix:///var/run/docker.sock'
OWNER = 'org.passwordforge.compose-run'
DOCKER = ['docker', '--host', ENDPOINT]
SCANNER = 'docker.io/aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa'
VERSION = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
HEX = r'[0-9a-f]{64}'
TARGET_KEYS = {'hostMachineId', 'dockerDaemonId', 'endpoint', 'project', 'service',
               'composeFile', 'composeSHA256', 'proxyNetwork', 'proxyNetworkId', 'httpsURL', 'evidenceRoot'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return strict_json(Path(path).read_bytes())


def safe_path(value, root=None, exists=True):
    p = Path(value)
    require(p.is_absolute() and '..' not in p.parts, 'PATH', 'Canonical absolute paths required.')
    for item in (p, *p.parents):
        require(not item.is_symlink() and not (hasattr(item, 'is_junction') and item.is_junction()),
                'PATH_LINK', 'Links and junctions are forbidden.')
    require(p.resolve(strict=exists) == p, 'PATH', 'Path is not canonical.')
    if root:
        require(root in p.parents and ROOT != p and ROOT not in p.parents,
                'EVIDENCE_PATH', 'Use a child of the private evidence root outside source.')
    return p


def target(path):
    p = safe_path(path)
    raw = p.read_bytes(); d = strict_json(raw)
    require(type(d) is dict and set(d) == TARGET_KEYS and all(type(v) is str and v for v in d.values()),
            'TARGET', 'Exact target fields and nonempty strings required.')
    require(re.fullmatch(r'[0-9a-f]{32}', d['hostMachineId']) and re.fullmatch(HEX, d['composeSHA256'])
            and re.fullmatch(HEX, d['proxyNetworkId']) and re.fullmatch(r'[A-Za-z0-9:_-]{1,128}', d['dockerDaemonId']),
            'TARGET', 'Invalid host, daemon, network or Compose identity.')
    require(d['endpoint'] == ENDPOINT and d['service'] == 'passwordforge'
            and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', d['project'])
            and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}', d['proxyNetwork']), 'TARGET', 'Invalid target scope.')
    u = urlsplit(d['httpsURL'])
    require(u.scheme == 'https' and u.hostname and not u.username and not u.password
            and u.path in ('', '/') and not u.query and not u.fragment and u.port in (None, 443),
            'TARGET_URL', 'Use an HTTPS origin without credentials.')
    compose = safe_path(d['composeFile'])
    require(compose.is_file() and sha(compose.read_bytes()) == d['composeSHA256'], 'COMPOSE_DRIFT', 'Private Compose changed.')
    evidence = safe_path(d['evidenceRoot'])
    require(evidence.is_dir() and ROOT != evidence and ROOT not in evidence.parents, 'EVIDENCE_PATH', 'Private evidence root required.')
    if os.name == 'posix':
        require(p.stat().st_uid == os.getuid() and p.stat().st_mode & 0o077 == 0
                and evidence.stat().st_uid == os.getuid() and evidence.stat().st_mode & 0o777 == 0o700,
                'PRIVATE_MODE', 'Target must be private; evidence root must be operator-owned mode 0700.')
    return d, sha(raw)


def command(args, *, data=None, log=None, include_stderr=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'BUILDX_', 'BUILDKIT_', 'COMPOSE_'))}
    p = subprocess.run(args, input=data, capture_output=True, cwd=ROOT, env=env, timeout=1200)
    if log:
        Path(log).write_bytes(p.stdout + p.stderr)
        write(Path(str(log)+'.status.json'), {'exitStatus': p.returncode})
    require(p.returncode == 0, 'COMMAND_FAILED', 'Command failed; review private logs. No later stage authorized.')
    return (p.stdout+p.stderr if include_stderr else p.stdout).decode('utf-8')


def docker(*args, **kw):
    return command(DOCKER + list(args), **kw)


def git(*args):
    return command(['git', '-C', str(ROOT), *args])


def source(commit, version, root=None):
    source_root = safe_path(root) if root is not None else ROOT
    source_git = (lambda *args: command(['git', '-C', str(source_root), *args])) if root is not None else git
    require(re.fullmatch(r'[0-9a-f]{40}', commit or '') and re.fullmatch(VERSION, version or ''),
            'SOURCE_INPUT', 'Reviewed full commit and semantic version required.')
    require(source_git('rev-parse', 'HEAD').strip() == commit and not source_git('status', '--porcelain').strip(),
            'SOURCE_DIRTY', 'Use clean committed reviewed source.')
    names = source_git('ls-files', '-z').split('\0')[:-1]
    inv = read(source_root/'RELEASE-INVENTORY.json')
    require(inv['version'] == version and inv['fileCount'] == len(names)
            and len(inv['files']) == len(names) and {x['path'] for x in inv['files']} == set(names),
            'SOURCE_INVENTORY', 'Exact release inventory required.')
    modes = {x['path']: x['mode'] for x in inv['files']}
    # Only these root development directories are outside the inventory/context.
    found = set()
    def walk(directory):
        for p in directory.iterdir():
            if directory == source_root and p.name in ('.git', 'node_modules', 'dist'):
                require(not p.is_symlink() and not (hasattr(p, 'is_junction') and p.is_junction()), 'SOURCE_LINK', 'Excluded root must not be a link.')
                continue
            require(not p.is_symlink() and not (hasattr(p, 'is_junction') and p.is_junction()), 'SOURCE_LINK', 'Source links forbidden.')
            if p.is_dir(): walk(p)
            else:
                require(p.is_file(), 'SOURCE_TYPE', 'Regular source files required.')
                found.add(p.relative_to(source_root).as_posix())
    walk(source_root)
    require(found == set(names), 'SOURCE_INVENTORY', 'Unexpected or missing source files.')
    blobs = {}
    for name in names:
        require(not name.startswith('/') and '\\' not in name and ':' not in name
                and all(x not in ('', '.', '..') for x in name.split('/')), 'SOURCE_PATH', 'Unsafe source path.')
        mode = source_git('ls-tree', commit, '--', name).split()[0]
        require(mode in ('100644', '100755') and modes[name] == ('0755' if mode == '100755' else '0644'),
                'SOURCE_MODE', 'Regular Git mode must match inventory.')
        raw = subprocess.check_output(['git', '-C', str(source_root), 'show', commit+':'+name])
        require((source_root/name).read_bytes() == raw, 'SOURCE_CHANGED', 'Working bytes differ from commit.')
        if os.name == 'posix':
            require((source_root/name).stat().st_mode & 0o777 == int(modes[name], 8), 'SOURCE_MODE', 'Source modes differ.')
        blobs[name] = (raw, int(modes[name], 8))
    require(strict_json(blobs['package.json'][0])['version'] == version, 'VERSION', 'Package version differs.')
    refs = re.findall(r'^FROM\s+(\S+)', blobs['Dockerfile'][0].decode(), re.M)
    require(len(refs) == 2 and refs[0].startswith('node:') and refs[1].startswith('nginx:') and all(re.fullmatch(r'(?:node|nginx):[^\s@]+@sha256:'+HEX, x) for x in refs),
            'BASES', 'Two digest-pinned Node/Nginx bases required.')
    require(re.search(r'org\.opencontainers\.image\.version="'+re.escape(version)+r'"', blobs['Dockerfile'][0].decode()),
            'VERSION', 'Docker label and package version must agree before building.')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        for name, (raw, mode) in sorted(blobs.items()):
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = mode
            tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue(), refs


def live(t):
    require(sys.platform == 'linux' and os.getuid() != 0
            and Path('/etc/machine-id').read_text().strip() == t['hostMachineId'], 'HOST', 'Wrong host or operator.')
    context = strict_json(docker('context', 'inspect', 'default'))
    require(type(context) is list and len(context) == 1 and context[0]['Name'] == 'default'
            and context[0]['Endpoints']['docker']['Host'] == ENDPOINT
            and context[0]['Endpoints']['docker']['SkipTLSVerify'] is False, 'ENDPOINT', 'Remote/unverified context forbidden.')
    require(strict_json(docker('info', '--format', '{{json .ID}}')) == t['dockerDaemonId'], 'DAEMON', 'Wrong daemon; stop.')
    require(docker('version', '--format', '{{.Server.Os}}/{{.Server.Arch}}').strip() == 'linux/amd64', 'PLATFORM', 'Wrong architecture.')
    inspect_builder(docker('buildx', 'inspect', 'default'))


@contextlib.contextmanager
def locked():
    path = Path.home()/'.cache/passwordforge-docker.lock'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700)  # Atomic; never clear or recover another lock.
    try: yield
    finally: path.rmdir()


def compose_args(t, override=None):
    args = ['compose', '--env-file', '/dev/null', '-p', t['project'], '-f', t['composeFile']]
    return args + (['-f', str(override)] if override else [])


def tmpfs_valid(value):
    if type(value) is not str or not value.startswith('/tmp:'):return False
    options=value[5:].split(',')
    if len(options)!=5 or len(set(options))!=5:return False
    flags={x for x in options if '=' not in x}
    values=dict(x.split('=',1) for x in options if '=' in x)
    return flags=={'rw','noexec','nosuid'} and set(values)=={'size','mode'} \
        and values['size'] in ('16m','16777216') and values['mode'] in ('1777','01777')


def compose_check(t, override=None, image=None):
    d = strict_json(docker(*compose_args(t, override), 'config', '--format', 'json'))
    require(d.get('name') == t['project'] and set(field(d, 'services', dict)) == {'passwordforge'}, 'COMPOSE_SCOPE', 'Dedicated service/project required.')
    require(set(d)=={'name','services','networks'}, 'COMPOSE_SCOPE', 'Unsupported top-level configuration.')
    s = field(d['services'],'passwordforge',dict)
    supported={'image','container_name','platform','pull_policy','restart','user','read_only','tmpfs','security_opt',
               'cap_drop','pids_limit','mem_limit','cpus','networks','labels','healthcheck','privileged','tty','stdin_open','command','entrypoint'}
    require(set(s)<=supported, 'COMPOSE_SCOPE', 'Unsupported service execution or isolation setting.')
    require(all(type(s[k]) is bool and s[k] is False for k in ('privileged','tty','stdin_open') if k in s),
            'COMPOSE_SCOPE', 'Only false normalized defaults are supported.')
    require(all(s[k] is None for k in ('command','entrypoint') if k in s),
            'COMPOSE_SCOPE', 'Only null inherited execution defaults are supported.')
    require(s.get('image') == image if image else (valid_digest(s.get('image')) or re.fullmatch(r'passwordforge:'+VERSION, s.get('image', '')) is not None),
            'COMPOSE_IMAGE', 'Unexpected effective image.')
    require(not any(s.get(k) for k in ('build', 'ports', 'volumes', 'depends_on', 'devices', 'configs', 'secrets', 'cap_add', 'privileged', 'network_mode')),
            'COMPOSE_SCOPE', 'Unexpected builds, dependencies, ports, mounts or privileges.')
    require(s.get('container_name') == 'passwordforge' and s.get('platform') == 'linux/amd64'
            and s.get('pull_policy') == 'never' and s.get('user') == '10001:10001' and s.get('read_only') is True
            and s.get('cap_drop') == ['ALL'] and s.get('security_opt') in (['no-new-privileges:true'],['no-new-privileges'])
            and type(s.get('pids_limit')) is int and s.get('pids_limit') == 128 and type(s.get('mem_limit')) in (int, str) and str(s.get('mem_limit')) == '134217728' and type(s.get('cpus')) in (int,float,str) and str(s.get('cpus')) in ('1','1.0'),
            'COMPOSE_HARDENING', 'Runtime hardening differs.')
    require(type(s.get('tmpfs')) is list and len(s['tmpfs'])==1 and tmpfs_valid(s['tmpfs'][0])
            and type(s.get('networks')) is dict and set(s['networks']) == {t['proxyNetwork']},
            'COMPOSE_HARDENING', 'Unexpected tmpfs/network.')
    attachment={} if s['networks'][t['proxyNetwork']] is None else field(s['networks'],t['proxyNetwork'],dict)
    require(set(attachment)<={'priority','gw_priority','aliases'}
            and all(type(attachment[k]) is int and attachment[k]==0 for k in ('priority','gw_priority') if k in attachment)
            and ('aliases' not in attachment or attachment['aliases'] in (None,[])), 'COMPOSE_NETWORK', 'Unsupported network attachment options.')
    net = field(d, 'networks', dict)
    require(set(net) == {t['proxyNetwork']}, 'COMPOSE_NETWORK', 'Only the approved proxy network is supported.')
    proxy=field(net,t['proxyNetwork'],dict)
    require(proxy.get('external') is True and proxy.get('name') == t['proxyNetwork']
            and {'name','external'} <= set(proxy) <= {'name','external','ipam'}
            and ('ipam' not in proxy or (type(proxy['ipam']) is dict and proxy['ipam']=={})),
            'COMPOSE_NETWORK', 'Private proxy must remain external with no IPAM configuration.')
    labels = field(s, 'labels', dict); host = urlsplit(t['httpsURL']).hostname
    expected = {'traefik.enable': 'true', 'traefik.docker.network': t['proxyNetwork'],
                'traefik.http.routers.passwordforge.rule': 'Host(`'+host+'`)',
                'traefik.http.routers.passwordforge.entrypoints': 'websecure',
                'traefik.http.routers.passwordforge.tls': 'true',
                'traefik.http.routers.passwordforge.service': 'passwordforge',
                'traefik.http.services.passwordforge.loadbalancer.server.port': '8080'}
    require(labels==expected, 'COMPOSE_ROUTING', 'Routing differs.')
    hc = field(s, 'healthcheck', dict)
    require(set(hc)=={'test','interval','timeout','start_period','retries'}
            and type(hc['retries']) is int and hc.get('test') == ['CMD', 'wget', '-q', '-O', '/dev/null', 'http://127.0.0.1:8080/healthz']
            and hc.get('interval') == '30s' and hc.get('timeout') == '3s' and hc.get('start_period') == '10s'
            and hc.get('retries') == 3 and s.get('restart') == 'unless-stopped', 'COMPOSE_HEALTH', 'Health/restart differs.')
    return d


def production(t):
    d = strict_json(docker('container', 'inspect', 'passwordforge'))
    require(type(d) is list and len(d) == 1, 'PRODUCTION', 'Missing production container.')
    d = d[0]; labels = field(field(d, 'Config', dict), 'Labels', dict)
    require(re.fullmatch(HEX, d['Id']) and valid_digest(d['Image']) and d['State']['Running'] is True
            and d['State']['Health']['Status'] == 'healthy' and labels.get('com.docker.compose.project') == t['project']
            and labels.get('com.docker.compose.service') == 'passwordforge', 'PRODUCTION', 'Unexpected production identity/state.')
    require(d['NetworkSettings']['Networks'][t['proxyNetwork']]['NetworkID'] == t['proxyNetworkId'], 'PRODUCTION_NETWORK', 'Proxy identity differs.')
    return {'containerId': d['Id'], 'imageId': d['Image'], 'startedAt': d['State']['StartedAt']}


def unrelated(exclude=()):
    ids=docker('container','ls','-aq','--no-trunc').splitlines()
    result=[]
    for cid in ids:
        if cid in exclude:continue
        require(re.fullmatch(HEX,cid),'CONTAINER_ID','Malformed inventory ID.')
        d=strict_json(docker('container','inspect',cid))[0]
        if d['Name']=='/passwordforge':continue
        state=field(d,'State',dict)
        require(d['Id']==cid and valid_digest(d['Image']) and type(state.get('Running')) is bool
                and type(state.get('Status')) is str and state['Status'] in ('created','running','paused','restarting','removing','exited','dead')
                and type(state.get('StartedAt')) is str, 'CONTAINER_STATE','Malformed unrelated state.')
        health=state.get('Health')
        require(health is None or (type(health) is dict and health.get('Status') in ('none','starting','healthy','unhealthy')),
                'CONTAINER_STATE','Malformed unrelated health.')
        result.append({'id':d['Id'],'image':d['Image'],'startedAt':state['StartedAt'],
                       'running':state['Running'],'status':state['Status'],'health':health['Status'] if health else None})
    return sorted(result,key=lambda x:x['id'])


def guard(t,rec,owned=()):
    require(sha(Path(t['composeFile']).read_bytes())==t['composeSHA256']
            and production(t)==rec['production'] and unrelated(owned)==rec['unrelated'],
            'PRODUCTION_DRIFT','Target or unrelated workload identity changed.')


def image(ref):
    d = strict_json(docker('image', 'inspect', '--platform', 'linux/amd64', ref))
    require(type(d) is list and len(d) == 1 and valid_digest(d[0]['Id']), 'IMAGE', 'Invalid image inspection.')
    d = d[0]
    require(d.get('Os') == 'linux' and d.get('Architecture') == 'amd64' and d.get('Variant') in (None, '', 'v1'), 'PLATFORM', 'Only linux/amd64.')
    return d


def index_image(ref):
    values = strict_json(docker('image','inspect',ref))
    require(type(values) is list and len(values)==1, 'EXPORT_REFERENCE','Missing top-level image.')
    d=values[0];desc=field(d,'Descriptor',dict)
    require(valid_digest(d.get('Id')) and field(desc,'digest',str)==d['Id']
            and field(desc,'mediaType',str)=='application/vnd.oci.image.index.v1+json'
            and field(desc,'size',int)>0, 'EXPORT_REFERENCE','Expected a digest-addressed OCI index.')
    return d


def manifest_descriptor(d):
    desc=field(d,'Descriptor',dict);platform=field(desc,'platform',dict)
    require(field(desc,'digest',str)==d['Id'] and field(desc,'mediaType',str)=='application/vnd.oci.image.manifest.v1+json'
            and field(desc,'size',int)>0 and platform.get('os')=='linux' and platform.get('architecture')=='amd64'
            and platform.get('variant') in (None,'','v1'), 'BUILD_MANIFEST','Unexpected selected manifest descriptor.')
    return desc


def export_binding(rec,metadata,iid,d):
    native=index_image(rec['candidate']);desc=field(metadata,'containerimage.descriptor',dict)
    require(native['Id']==field(metadata,'containerimage.digest',str)==iid
            and desc==native['Descriptor'], 'BUILD_INDEX','Buildx index, IID and Docker index differ.')
    manifest_descriptor(d)
    require(native['Config']['Labels']==d['Config']['Labels'] and native['RootFS']==d['RootFS'],
            'BUILD_INDEX','Top-level and selected runtime differ.')
    return native['Id']


def write(path, value):
    with path.open('x', encoding='utf-8') as f: json.dump(value, f, indent=2); f.write('\n')


def record_save(run, record):
    temp = run/'run.next.json'
    write(temp, record); os.replace(temp, run/'run.json')


def bind_files(run, directory):
    files={}
    for p in directory.rglob('*'):
        safe_path(str(p),run)
        if p.is_file():files[p.relative_to(run).as_posix()]=sha(p.read_bytes())
    return files


def validate_record(run, rec, target_sha, context_sha):
    require(type(rec) is dict and rec.get('schemaVersion') == 1 and type(rec.get('schemaVersion')) is int
            and rec.get('targetSHA256') == target_sha and rec.get('contextSHA256') == context_sha
            and re.fullmatch(r'[0-9a-f]{32}', rec.get('run', '')) and type(rec.get('stages')) is dict
            and re.fullmatch(r'passwordforge:'+VERSION+r'-candidate-[a-z0-9][a-z0-9-]{0,31}', rec.get('candidate','')),
            'RUN_BINDING', 'Run/source/target mismatch.')
    if 'recovery' in rec:
        recovery=field(rec,'recovery',dict)
        require(re.fullmatch(r'[0-9a-f]{32}',recovery.get('operationId','')) and recovery['operationId']!=rec['run'],
                'RECOVERY_IDENTITY','Missing distinct recovery identity.')
        original,origin_report,_,_,context,_,_=failed_export(recovery['failedRun'],recovery['failureManifestSHA256'],recovery['failureReportSHA256'],field(rec,'sourceDirectory',str))
        require(original['run']==rec['run'] and original['commit']==rec['commit'] and sha(context)==context_sha
                and sha((run/'preflight/baseline-review.json').read_bytes())==recovery['baselineReviewSHA256'],
                'RECOVERY_IDENTITY','Recovery origin/source/review differs.')
        if 'resourceEvidenceSHA256' in recovery:
            require(sha((run/'preflight/resource-evidence.json').read_bytes())==recovery['resourceEvidenceSHA256']
                    ==read(run/'preflight/baseline-review.json')['resourceReview']['evidenceSHA256'],
                    'RECOVERY_IDENTITY','Resource exception evidence changed.')
        if 'build' in rec['stages']:
            ids=origin_report['identities']
            require(rec.get('candidate')==original['candidate'] and rec.get('exportReference')==ids['nativeImageIndexId']
                    and rec.get('imageId')==ids['platformSelectedManifestId'] and rec.get('configId')==ids['configDigestReportedByBuildx'],
                    'RECOVERY_IDENTITY','Recovered identities differ from authenticated origin.')
            for name in ('context.tar','metadata.json','build.iid','build.log','build.log.status.json'):
                require((run/'build'/name).read_bytes()==(Path(recovery['failedRun'])/'build'/name).read_bytes(),
                        'RECOVERY_IDENTITY','Copied build proof differs from original attempt.')
    prod = field(rec,'production',dict)
    require(set(prod)=={'containerId','imageId','startedAt'} and re.fullmatch(HEX,prod['containerId'])
            and valid_digest(prod['imageId']) and type(prod['startedAt']) is str and prod['startedAt'],
            'RUN_BINDING','Production baseline missing or malformed.')
    require(type(rec.get('unrelated')) is list, 'RUN_BINDING', 'Unrelated baseline missing.')
    order=['preflight','build','scan','smoke','verify','deploy','cleanup']
    for name, stage in rec['stages'].items():
        require(name in order and all(x in rec['stages'] for x in order[:order.index(name)]), 'STAGE', 'Stage history is incomplete.')
        require(name in ('preflight','build','scan','smoke','verify','deploy','cleanup')
                and type(stage) is dict and stage.get('passed') is True and type(stage.get('files')) is dict,
                'STAGE', 'Incomplete stage.')
        actual=bind_files(run,safe_path(str(run/name),run))
        require(actual==stage['files'], 'EVIDENCE_CHANGED','Missing, extra or changed stage evidence.')
    if 'build' in rec['stages']:
        require(valid_digest(rec.get('imageId')) and valid_digest(rec.get('configId'))
                and type(rec.get('identities')) is dict, 'BUILD_PROOF','Missing image/config identities.')
        out=run/'build'; inspected=read(out/'inspection.json')
        require(inspected['Id']==rec['imageId'] and inspected['Config']['Labels'].get(OWNER)==rec['run']
                and inspected['Config']['Labels'].get('org.passwordforge.source')==context_sha
                and inspected['Config']['Labels'].get('org.opencontainers.image.version')==rec['version']
                and sha((out/'context.tar').read_bytes())==context_sha, 'BUILD_PROOF','Build/source/run binding differs.')
        config=archive_config(out/'image.tar',inspected)
        actual=verify_identity(out/'image.tar',read(out/'metadata.json'),inspected,(out/'build.iid').read_text().strip(),config)
        require(valid_digest(rec.get('exportReference')) and rec['exportReference']==actual['exportId'],
                'BUILD_PROOF','Missing or substituted export reference.')
        require(config==rec['configId'] and actual==rec['identities']
                and read(out/'identity.json')==dict(imageId=rec['imageId'],**actual), 'BUILD_PROOF','Export identity differs.')
    if 'scan' in rec['stages']:
        database(run/'scan/cache/db/metadata.json')
        counts,_=scan_gate(read(run/'scan/vulnerabilities.json'),rec['configId'])
        require(counts==rec.get('counts'),'SCAN_PROOF','Finding counts differ.')
    for name in ('smoke','deploy'):
        if name in rec['stages']:
            require(read(run/name/'runtime.json')=={'passed':True,'imageId':rec['imageId'],'version':rec['version']},
                    'RUNTIME_PROOF','Runtime/image binding differs.')


def candidate(rec):
    d = image(rec['candidate'])
    require(d['Id'] == rec['imageId'], 'IMAGE_DRIFT', 'Candidate tag changed.')
    labels = field(field(d, 'Config', dict), 'Labels', dict)
    require(labels.get(OWNER) == rec['run'] and labels.get('org.passwordforge.source') == rec['contextSHA256']
            and labels.get('org.opencontainers.image.version') == rec['version'], 'IMAGE_BINDING', 'Candidate labels differ.')
    if 'exportReference' in rec:
        native=index_image(rec['candidate']);manifest_descriptor(d)
        require(native['Id']==rec['exportReference'] and native['Config']['Labels']==d['Config']['Labels']
                and native['RootFS']==d['RootFS'], 'IMAGE_DRIFT','Candidate index changed.')
    return d


def remove_owned(cid, run):
    require(re.fullmatch(HEX, cid or ''), 'CLEANUP_ID', 'Captured full container ID required.')
    ids = docker('container', 'ls', '-aq', '--no-trunc').splitlines()
    if cid not in ids: return
    d = strict_json(docker('container', 'inspect', cid))
    require(type(d) is list and len(d) == 1 and d[0]['Id'] == cid
            and d[0]['Config']['Labels'].get(OWNER) == run, 'CLEANUP_OWNER', 'Unknown ownership; retain resource.')
    docker('container', 'rm', '-f', cid)


def build(t, run, rec, out, context, refs):
    require(rec['candidate'] not in docker('image', 'ls', '--format', '{{.Repository}}:{{.Tag}}').splitlines(), 'TAG_COLLISION', 'Tag occupied.')
    for ref in refs: image(ref)  # Cached only; no acquisition command.
    (out/'context.tar').write_bytes(context)
    guard(t,rec)
    docker('buildx', 'build', '--builder', 'default', '--platform', 'linux/amd64', '--pull=false', '--load',
           '--tag', rec['candidate'], '--iidfile', str(out/'build.iid'), '--metadata-file', str(out/'metadata.json'),
           '--label', OWNER+'='+rec['run'], '--label', 'org.passwordforge.source='+rec['contextSHA256'], '-',
           data=context, log=out/'build.log')
    d = image(rec['candidate']); rec['imageId'] = d['Id']; candidate(rec)
    metadata=read(out/'metadata.json');iid=(out/'build.iid').read_text().strip()
    rec['exportReference']=export_binding(rec,metadata,iid,d)
    candidate(rec)
    docker('image', 'save', '--output', str(out/'image.tar'), rec['exportReference'], log=out/'export.log')
    candidate(rec)
    write(out/'inspection.json', {'Id': d['Id'], 'RootFS': d['RootFS'], 'Config': {'Labels': d['Config']['Labels']}})
    config = archive_config(out/'image.tar', d)
    identities = verify_identity(out/'image.tar', read(out/'metadata.json'), d, (out/'build.iid').read_text().strip(), config)
    rec.update(configId=config, identities=identities)
    write(out/'identity.json', {'imageId': d['Id'], **identities})


def scan_gate(result, config):
    scan_schema(result)
    require(result['Metadata']['ImageID'] == config and any(r['Class'] == 'os-pkgs' and r['Packages'] for r in result['Results']),
            'SCAN_IDENTITY', 'Wrong runtime config or incomplete OS inventory.')
    counts = collections.Counter({s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')})
    findings = [v for r in result['Results'] for v in r['Vulnerabilities']]
    for v in findings: counts[v['Severity']] += 1
    require(not any(counts[s] for s in ('CRITICAL', 'HIGH', 'UNKNOWN')), 'VULNERABILITY_GATE', 'Unacceptable vulnerabilities.')
    return dict(counts), findings


def scan(t, run, rec, out):
    d = candidate(rec); scanner = image(SCANNER); owned = []; failure = None
    for name in ('input', 'output', 'cache'): (out/name).mkdir(mode=0o700)
    archive = out/'input/image.tar'
    docker('image', 'save', '--output', str(archive), rec['exportReference'])
    candidate(rec)
    verify_identity(archive,read(run/'build/metadata.json'),d,(run/'build/build.iid').read_text().strip(),archive_config(archive,d))
    require(archive_config(archive, d) == rec['configId'], 'SCAN_IDENTITY', 'Export runtime differs.')
    (out/'input/scan-contract.tpl').write_bytes((SCRIPTS/'scan-contract.tpl').read_bytes())
    def invoke(step, network, args):
        name = 'pfscan-'+rec['run']+'-'+step
        require(name not in docker('container', 'ls', '-a', '--format', '{{.Names}}').splitlines(), 'CONTAINER_COLLISION', 'Scanner name exists.')
        guard(t,rec,owned)
        cid = docker('create', '--pull', 'never', '--name', name, '--label', OWNER+'='+rec['run'], '--network', network,
                     '--read-only', '--user', str(os.getuid())+':'+str(os.getgid()), '--cap-drop', 'ALL',
                     '--security-opt', 'no-new-privileges:true', '--pids-limit', '128', '--memory', '1g', '--cpus', '1',
                     '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m,mode=1777', '--env', 'HOME=/tmp',
                     '--mount', f'type=bind,src={out}/input,dst=/input,readonly',
                     '--mount', f'type=bind,src={out}/output,dst=/output', '--mount', f'type=bind,src={out}/cache,dst=/cache',
                     scanner['Id'], '--cache-dir', '/cache', *args).strip()
        require(re.fullmatch(HEX, cid), 'CONTAINER_ID', 'Missing captured scanner ID; inspect manually.')
        owned.append(cid); write(out/(step+'-container.json'), {'id': cid})
        inspected=strict_json(docker('container','inspect',cid))[0]
        selected=dict(inspected['HostConfig'],User=inspected['Config']['User'],Networks=inspected['NetworkSettings']['Networks'],Mounts=inspected['Mounts'])
        write(out/(step+'-restrictions.json'),{k:selected[k] for k in ('NetworkMode','Networks','User','ReadonlyRootfs','Privileged','CapDrop','SecurityOpt','Memory','PidsLimit','NanoCpus','PortBindings','Mounts')})
        isolation(out/(step+'-restrictions.json'),network,str(os.getuid())+':'+str(os.getgid()),str(out))
        docker('start', '-a', cid, log=out/(step+'.log'))
        require(docker('inspect', '--format', '{{.State.ExitCode}}', cid).strip() == '0', 'SCANNER_EXIT', 'Scanner failed.')
        require(not re.search(r'\b(WARN|ERROR|FATAL)\b', (out/(step+'.log')).read_text()), 'SCANNER_LOG', 'Scanner warning/error requires review.')
    try:
        invoke('version', 'none', ['--version'])
        require('Version: 0.75.0' in (out/'version.log').read_text(), 'SCANNER_VERSION', 'Wrong scanner.')
        invoke('db', 'bridge', ['image', '--download-db-only', '--disable-telemetry', '--no-progress'])
        database(out/'cache/db/metadata.json')
        before = {str(p): sha(p.read_bytes()) for p in (archive, out/'cache/db/metadata.json', out/'cache/db/trivy.db')}
        args = ['image', '--input', '/input/image.tar', '--skip-db-update', '--skip-java-db-update', '--offline-scan',
                '--disable-telemetry', '--skip-version-check', '--scanners', 'vuln', '--pkg-types', 'os,library',
                '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--ignorefile', '/dev/null', '--exit-code', '0', '--no-progress', '--timeout', '15m']
        invoke('native', 'none', args+['--list-all-pkgs', '--format', 'json', '--output', '/output/native.json'])
        invoke('explicit', 'none', args+['--format', 'template', '--template', '@/input/scan-contract.tpl', '--output', '/output/explicit.json'])
        require(all(sha(Path(p).read_bytes()) == h for p, h in before.items()), 'SCAN_CHANGED', 'Input/database changed.')
        combine(out/'output/native.json', out/'output/explicit.json', out/'vulnerabilities.json')
        result=read(out/'vulnerabilities.json')
        write(out/'findings.json', [v for r in result['Results'] for v in r['Vulnerabilities']])
        counts, findings = scan_gate(result, rec['configId'])
        write(out/'summary.json', {'counts': counts, 'findings': findings, 'imageId': rec['imageId']})
        rec['counts'] = counts
    finally:
        for cid in owned:
            try: remove_owned(cid, rec['run'])
            except Exception as e: failure = e
        if failure: raise failure


def medium_review(run, rec, review):
    if rec['counts']['MEDIUM'] == 0: return
    require(review is not None, 'MEDIUM_REVIEW', 'Written disposition required before smoke/deployment.')
    d = read(safe_path(review)); result = run/'scan/vulnerabilities.json'
    expected = sorted({v['PkgName']+'|'+v['VulnerabilityID']+'|'+v['InstalledVersion']
                       for r in read(result)['Results'] for v in r['Vulnerabilities'] if v['Severity'] == 'MEDIUM'})
    require(type(d) is dict and set(d) == {'imageId', 'resultSHA256', 'dispositions'}
            and d['imageId'] == rec['imageId'] and d['resultSHA256'] == sha(result.read_bytes())
            and type(d['dispositions']) is dict and sorted(d['dispositions']) == expected
            and all(type(v) is str and v.strip() for v in d['dispositions'].values()), 'MEDIUM_REVIEW', 'Disposition binding differs.')


def security_headers(raw):
    """One ASCII curl header capture, framed strictly by CRLF; no text newline conversion."""
    require(type(raw) is bytes and len(raw)<=65536 and raw.endswith(b'\r\n\r\n'),
            'HTTP_HEADERS','One CRLF-terminated binary header block required.')
    lines=raw[:-4].split(b'\r\n')
    # Check framing and octets before any decoding. Bare CR/LF, DEL, other
    # controls and non-ASCII separators are outside the supported capture format.
    require(all(line and all(x==9 or 32<=x<=126 for x in line) for line in lines),
            'HTTP_HEADERS','Malformed header framing or unsupported octets.')
    require(re.fullmatch(rb'HTTP/(?:1\.[01]|2|3) [0-9]{3}(?: [^\r\n]*)?',lines[0]),
            'HTTP_HEADERS','One valid HTTP response required.')
    fields={}
    for line in lines[1:]:
        require(not line.startswith((b' ',b'\t')) and b':' in line,'HTTP_HEADERS','Malformed or folded header field.')
        name,value=line.split(b':',1)
        require(re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) and value.strip(b' \t'),
                'HTTP_HEADERS','Malformed header field.')
        fields.setdefault(name.decode('ascii').lower(),[]).append(value.strip(b' \t').decode('ascii'))
    required={'content-security-policy','x-content-type-options','referrer-policy','cache-control',
              'x-frame-options','permissions-policy','content-type'}
    require(all(k in fields and len(fields[k])==1 for k in required),'HTTP_HEADERS','Missing or duplicate required header.')
    values={k:v[0] for k,v in fields.items() if len(v)==1}
    directives={}
    for part in values['content-security-policy'].split(';'):
        tokens=part.split()
        if not tokens:continue
        name=tokens[0].lower()
        require(re.fullmatch(r'[a-z][a-z0-9-]*',name) and name not in directives and len(tokens)>1,
                'HTTP_CSP','Malformed or duplicate CSP directive.')
        directives[name]=tokens[1:]
    expected={k:["'self'"] for k in ('script-src','style-src','img-src','font-src')}
    expected.update({k:["'none'"] for k in ('default-src','connect-src','object-src','base-uri','form-action','frame-ancestors')})
    require(directives==expected,'HTTP_CSP','CSP differs from the complete approved policy.')
    require(all(values[k].lower()==v for k,v in {'x-content-type-options':'nosniff','referrer-policy':'no-referrer',
            'cache-control':'no-store','x-frame-options':'deny'}.items()),'HTTP_HEADERS','Incorrect security header value.')
    permissions=re.sub(r'\s+','',values['permissions-policy']).split(',')
    require(len(permissions)==3 and set(permissions)=={'camera=()','microphone=()','geolocation=()'},
            'HTTP_HEADERS','Permissions policy differs.')
    return values


def runtime_execution(d, expected):
    h=field(d,'HostConfig',dict);config=field(d,'Config',dict)
    for key,allowed in {'PidMode':('',),'IpcMode':('','private'),'UTSMode':('',),
                        'UsernsMode':('',),'CgroupnsMode':('private',)}.items():
        require(field(h,key,str) in allowed,'RUNTIME_EXECUTION','Unsupported runtime namespace.')
    require(h.get('Runtime') in ('runc','') and all(h.get(k) in (None,[]) for k in
            ('Devices','DeviceRequests','DeviceCgroupRules','Binds','VolumesFrom')),
            'RUNTIME_EXECUTION','Unsupported devices, mounts or runtime.')
    require(config.get('Entrypoint')==expected.get('Entrypoint') and config.get('Cmd')==expected.get('Cmd')
            and type(expected.get('Entrypoint')) is list and type(expected.get('Cmd')) is list
            and all(type(x) is str for x in expected['Entrypoint']+expected['Cmd']),
            'RUNTIME_EXECUTION','Execution differs from the immutable image.')


def runtime_check(cid, out, rec, https=None):
    for _ in range(30):
        state=strict_json(docker('container','inspect',cid))
        require(type(state) is list and len(state)==1,'RUNTIME','Missing container inspection.')
        d=state[0]
        if d['State'].get('Health',{}).get('Status')=='healthy':break
        if d['State'].get('Health',{}).get('Status')=='unhealthy':break
        time.sleep(2)
    require(d['Image']==rec['imageId'] and d['State']['Running'] is True
            and d['State'].get('Health',{}).get('Status')=='healthy','RUNTIME','Wrong image or unhealthy container.')
    h=d['HostConfig']; config=d['Config']
    runtime_execution(d,field(image(rec['imageId']),'Config',dict))
    require(config['User']=='10001:10001' and h['ReadonlyRootfs'] is True and h['Privileged'] is False
            and h['CapDrop']==['ALL'] and not h.get('CapAdd')
            and h['SecurityOpt'] in (['no-new-privileges'],['no-new-privileges:true'])
            and h['Memory']==134217728 and h['PidsLimit']==128 and h['NanoCpus']==1000000000
            and type(h['Tmpfs']) is dict and set(h['Tmpfs'])=={'/tmp'} and tmpfs_valid('/tmp:'+h['Tmpfs']['/tmp'])
            and all(m['Type']=='tmpfs' and m['Destination']=='/tmp' for m in d['Mounts']),
            'RUNTIME_HARDENING','Runtime restrictions differ.')
    if https:
        base=https.rstrip('/')
    else:
        require(h['NetworkMode']=='bridge' and set(d['NetworkSettings']['Networks'])=={'bridge'}
                and config['Labels'].get('traefik.enable')!='true', 'RUNTIME_NETWORK','Smoke must be isolated from proxy.')
        ports=d['NetworkSettings']['Ports']['8080/tcp']
        require(type(ports) is list and len(ports)==1 and ports[0]['HostIp']=='127.0.0.1'
                and re.fullmatch(r'[0-9]{1,5}',ports[0]['HostPort']), 'RUNTIME_PORT','Loopback-only port required.')
        base='http://127.0.0.1:'+ports[0]['HostPort']
    assets=['/','/theme.js','/app.js','/core.js','/dictionary.js','/profiles.js','/policy.js','/random-password.js',
            '/profile-output.js','/styles.css','/licenses/NOTICE.txt','/licenses/CC-BY-4.0.txt',
            '/licenses/ESDB-Copyright.txt','/licenses/esdb-provenance.json','/healthz',
            '/passwordforge-missing','/tests/browser-regeneration.mjs']
    for i,asset in enumerate(assets):
        headers=out/(str(i)+'.headers'); body=out/(str(i)+'.body')
        status=command(['curl','--noproxy','*','--silent','--show-error','--max-time','10',
                        '-D',str(headers),'-o',str(body),'-w','%{http_code}',base+asset]).strip()
        require(status==('404' if i>=15 else '200'),'HTTP','Asset/fixture delivery differs.')
        parsed=security_headers(headers.read_bytes())
        mime=parsed['content-type'].split(';',1)[0].strip().lower()
        if asset.endswith('.js') and i<15:
            require(mime in ('text/javascript','application/javascript'),'MIME','Incorrect JS MIME.')
        if asset=='/styles.css':require(mime=='text/css','MIME','Incorrect CSS MIME.')
        if asset=='/':require('class="version">v'+rec['version']+'</span>' in body.read_text(),'VERSION','Wrong HTML version.')
        if i<15:require(bool(body.read_bytes()),'HTTP','Empty required asset.')
        if asset=='/healthz':require(body.read_text().strip()=='ok','HEALTH','Health endpoint failed.')
    write(out/'runtime.json',{'passed':True,'imageId':rec['imageId'],'version':rec['version']})


def smoke(t, run, rec, out):
    name = 'pfsmoke-'+rec['run']; cid = None
    require(name not in docker('container', 'ls', '-a', '--format', '{{.Names}}').splitlines(), 'CONTAINER_COLLISION', 'Smoke name exists.')
    try:
        guard(t,rec)
        cid = docker('create', '--pull', 'never', '--name', name, '--label', OWNER+'='+rec['run'], '--network', 'bridge',
                     '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                     '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m,mode=1777', '--pids-limit', '128', '--memory', '128m',
                     '--cpus', '1', '--restart', 'no', '-p', '127.0.0.1::8080', rec['imageId']).strip()
        require(re.fullmatch(HEX, cid), 'CONTAINER_ID', 'Missing captured smoke ID.')
        write(out/'container.json', {'id': cid})
        docker('start', cid)
        runtime_check(cid, out, rec)
    finally:
        if cid: remove_owned(cid, rec['run'])


def cleanup_image(rec, ref):
    require(valid_digest(ref) and ref != rec['imageId'] and rec['stages'].get('deploy', {}).get('passed') is True,
            'CLEANUP_IMAGE', 'Only explicit superseded IDs after accepted deployment.')
    d = image(ref); tags = d.get('RepoTags'); digests = d.get('RepoDigests')
    require(d['Id'] == ref and type(tags) is list and tags and not digests
            and all(re.fullmatch(r'passwordforge:'+VERSION+r'(?:-candidate-[a-z0-9-]+)?', tag) for tag in tags),
            'CLEANUP_IMAGE', 'Shared, unknown or registry image retained.')
    labels=field(field(d,'Config',dict),'Labels',dict)
    require(labels.get('org.opencontainers.image.title')=='PasswordForge'
            and re.fullmatch(VERSION,labels.get('org.opencontainers.image.version','')),
            'CLEANUP_IMAGE','Image application metadata is not PasswordForge.')
    require(not docker('container', 'ls', '-aq', '--filter', 'ancestor='+ref).strip(), 'IMAGE_USED', 'Image is referenced.')
    for tag in tags:
        require(image(tag)['Id'] == ref and not docker('container', 'ls', '-aq', '--filter', 'ancestor='+ref).strip(), 'IMAGE_DRIFT', 'Cleanup identity/reference changed.')
        docker('image', 'rm', tag)  # No force, prune, immutable-ID bulk removal or unrelated aliases.


def failed_export(failed, manifest_sha, report_sha, source_root):
    require(re.fullmatch(HEX,manifest_sha or '') and re.fullmatch(HEX,report_sha or ''),
            'RECOVERY_INPUT','Explicit original evidence checksums required.')
    failed=safe_path(failed);origin=failed.parent.parent
    require(failed.parent==origin/'evidence', 'RECOVERY_INPUT','Use the original run beneath its evidence root.')
    mp=origin/'evidence/EVIDENCE-MANIFEST.json';rp=origin/'evidence/FINAL-BUILD-REPORT.json'
    require(sha(mp.read_bytes())==manifest_sha and sha(rp.read_bytes())==report_sha,
            'RECOVERY_EVIDENCE','Original evidence identity differs.')
    entries=field(read(mp),'files',list);names=set()
    for entry in entries:
        name=field(entry,'path',str);require(name not in names,'RECOVERY_EVIDENCE','Duplicate evidence path.');names.add(name)
        path=safe_path(str(origin/name),origin)
        require(path.is_file() and path.stat().st_size==field(entry,'bytes',int)
                and sha(path.read_bytes())==field(entry,'sha256',str),'RECOVERY_EVIDENCE','Original evidence changed.')
    needed=[failed/'run.json',origin/'evidence/baseline-before.json',rp]
    needed += [failed/'build'/n for n in ('context.tar','metadata.json','build.iid','build.log','build.log.status.json','export.log','export.log.status.json')]
    require(all(p.relative_to(origin).as_posix() in names for p in needed), 'RECOVERY_EVIDENCE','Incomplete failed-build evidence inventory.')
    rec=read(failed/'run.json');report=read(rp);out=failed/'build';metadata=read(out/'metadata.json');iid=(out/'build.iid').read_text().strip()
    require(rec.get('schemaVersion')==1 and type(rec['schemaVersion']) is int
            and set(rec['stages'])=={'preflight'} and rec['stages']['preflight']['passed'] is True
            and re.fullmatch(r'[0-9a-f]{32}',rec['run']), 'RECOVERY_CAUSE','Not a preflight-only failed build.')
    require(field(read(out/'build.log.status.json'),'exitStatus',int)==0 and field(read(out/'export.log.status.json'),'exitStatus',int)==1
            and field(report,'buildExitStatus',int)==0 and field(report,'exportExitStatus',int)==1 and report.get('result')=='HOLD'
            and report.get('commit')==rec['commit'] and report.get('candidate')==rec['candidate']
            and not (out/'image.tar').exists(), 'RECOVERY_CAUSE','Only the recorded successful build / failed export is recoverable.')
    identities=field(report,'identities',dict);index=field(identities,'nativeImageIndexId',str);manifest=field(identities,'platformSelectedManifestId',str)
    config=field(identities,'configDigestReportedByBuildx',str)
    require(all(valid_digest(x) for x in (index,manifest,config)) and len({index,manifest,config})==3
            and index==field(metadata,'containerimage.digest',str)==iid==identities['buildIID']==identities['buildExportDigest'],
            'RECOVERY_IDENTITY','Mixed build identities.')
    require((out/'export.log').read_text()=='Error response from daemon: No such image: '+manifest+'\n'
            and report['exportError']==(out/'export.log').read_text()
            and report.get('imageSourceRunVersionLabelsMatch') is True, 'RECOVERY_CAUSE','Unrelated export failure.')
    configs=set(re.findall(r'exporting config (sha256:[0-9a-f]{64})',(out/'build.log').read_text()))
    require(configs=={config},'RECOVERY_IDENTITY','Configuration evidence differs.')
    require(source_root==str(origin/'source/passwordforge'),'RECOVERY_SOURCE','Use the original approved source checkout.')
    context,refs=source(rec['commit'],rec['version'],source_root)
    require(sha(context)==rec['contextSHA256']==report['sourceFingerprint']
            and (out/'context.tar').read_bytes()==context, 'RECOVERY_SOURCE','Frozen source differs.')
    provenance=field(metadata,'buildx.build.provenance',dict)
    cs=provenance['invocation']['configSource']
    require(cs['digest']['sha256']==sha(context) and cs['entryPoint']=='Dockerfile'
            and provenance['invocation']['environment']['platform']=='linux/amd64', 'RECOVERY_SOURCE','Build provenance differs.')
    materials=field(provenance,'materials',list)
    require(all(any(m.get('digest',{}).get('sha256')==ref.split('@sha256:')[1]
                    and m.get('uri','').startswith('pkg:docker/'+ref.split(':',1)[0]+'@') for m in materials) for ref in refs),
            'RECOVERY_SOURCE','Pinned base provenance differs.')
    oldtarget=read(origin/'target.json');require(sha((origin/'target.json').read_bytes())==rec['targetSHA256'],
            'RECOVERY_EVIDENCE','Original target changed.')
    return rec,report,metadata,iid,context,oldtarget,origin


def container_baseline(values):
    require(type(values) is list and values,'BASELINE_REVIEW','Container baseline required.')
    keys={'name','id','image','running','status','startedAt','health','restartCount'};ids=set();names=set()
    for d in values:
        require(type(d) is dict and set(d)==keys and type(d['name']) is str and d['name'].startswith('/')
                and re.fullmatch(HEX,d['id']) and valid_digest(d['image']) and type(d['running']) is bool
                and d['status'] in ('created','running','paused','restarting','removing','exited','dead')
                and type(d['startedAt']) is str and bool(d['startedAt']) and d['health'] in (None,'none','starting','healthy','unhealthy')
                and type(d['restartCount']) is int and d['restartCount']>=0
                and d['id'] not in ids and d['name'] not in names,'BASELINE_REVIEW','Malformed container baseline.')
        ids.add(d['id']);names.add(d['name'])
    require(sum(d['name']=='/passwordforge' for d in values)==1,'BASELINE_REVIEW','Production baseline missing.')
    return sorted(values,key=lambda x:x['name'])


def baseline_differences(old,new,replacements=()):
    old=container_baseline(old);new=container_baseline(new)
    require([x['name'] for x in old]==[x['name'] for x in new],'BASELINE_REVIEW','Container set changed.')
    require(type(replacements) in (list,tuple) and len(replacements)<=1,'BASELINE_EXCEPTION','Only one exact Homarr exception is supported.')
    approvals={}
    for entry in replacements:
        require(type(entry) is dict and set(entry)=={'name','before','now'} and entry['name']=='/homarr',
                'BASELINE_EXCEPTION','Protected or unsupported replacement.')
        for key in ('before','now'):
            value=entry[key]
            require(type(value) is dict and set(value)=={'id','image'} and re.fullmatch(HEX,value['id']) and valid_digest(value['image']),
                    'BASELINE_EXCEPTION','Exact container and image identities required.')
        approvals[entry['name']]=entry
    differences=[];used=set()
    for before,after in zip(old,new):
        changes={k:{'before':before[k],'now':after[k]} for k in before if before[k]!=after[k]}
        allowed={'startedAt','restartCount'}
        if before['name'] in approvals:
            entry=approvals[before['name']]
            require(entry['before']=={k:before[k] for k in ('id','image')} and entry['now']=={k:after[k] for k in ('id','image')}
                    and before['id']!=after['id'] and before['image']!=after['image']
                    and after['running'] is True and after['status']=='running' and after['health'] in (None,'healthy'),
                    'BASELINE_EXCEPTION','Replacement identities or live state differ.')
            allowed.update(('id','image'));used.add(before['name'])
        require(set(changes)<=allowed,'BASELINE_REVIEW','Unreviewed or protected container change.')
        if changes:differences.append({'name':before['name'],'changes':changes})
    require(used==set(approvals),'BASELINE_EXCEPTION','Unused replacement approval.')
    return differences


def current_baseline():
    ids=docker('container','ls','-aq','--no-trunc').splitlines();require(ids,'BASELINE_REVIEW','No containers.')
    values=strict_json(docker('container','inspect',*ids));result=[]
    for d in values:
        state=d['State'];result.append({'name':d['Name'],'id':d['Id'],'image':d['Image'],'running':state['Running'],
            'status':state['Status'],'startedAt':state['StartedAt'],'health':state.get('Health',{}).get('Status'),'restartCount':d['RestartCount']})
    return container_baseline(result)


NETWORK_CONFIG=('Driver','Scope','Internal','Attachable','Ingress','EnableIPv4','EnableIPv6','IPAM','Options','Labels','ConfigOnly','ConfigFrom')


def network_records(values, historical_bridge=None):
    require(type(values) is list and values,'RESOURCE_EVIDENCE','Network configuration evidence required.')
    result={};ids=set()
    for n in values:
        require(type(n) is dict and set(n)=={'id','name','configuration'} and re.fullmatch(HEX,n['id'])
                and type(n['name']) is str and n['name'] and n['name'] not in result and n['id'] not in ids,
                'RESOURCE_EVIDENCE','Malformed or duplicate network identity.')
        if n['configuration'] is None:
            require(n['name']=='bridge' and n['id']==historical_bridge,'RESOURCE_EVIDENCE','Only the exact reviewed historical bridge may lack configuration.')
            result[n['name']]=n;ids.add(n['id']);continue
        cfg=field(n,'configuration',dict)
        require(set(cfg)==set(NETWORK_CONFIG) and type(cfg['Driver']) is str and type(cfg['Scope']) is str
                and all(type(cfg[k]) is bool for k in ('Internal','Attachable','Ingress','EnableIPv4','EnableIPv6','ConfigOnly'))
                and type(cfg['IPAM']) is dict and type(cfg['ConfigFrom']) is dict
                and all(cfg[k] is None or type(cfg[k]) is dict for k in ('Options','Labels')),
                'RESOURCE_EVIDENCE','Incomplete network configuration evidence.')
        result[n['name']]=n;ids.add(n['id'])
    return result


def protection(d):
    labels=d['Config'].get('Labels') or {}
    return {'labels':{k:v for k,v in labels.items() if k in ('com.docker.compose.project','com.docker.compose.service') or k.startswith('traefik.')},
            'networks':{k:v['NetworkID'] for k,v in d['NetworkSettings']['Networks'].items()}}


def resource_snapshot():
    ids=docker('network','ls','--no-trunc','--format','{{.ID}}').splitlines()
    networks=strict_json(docker('network','inspect',*ids)) if ids else []
    names=docker('volume','ls','--format','{{.Name}}').splitlines()
    volumes=strict_json(docker('volume','inspect',*names)) if names else []
    containers=docker('container','ls','-aq','--no-trunc').splitlines()
    values=strict_json(docker('container','inspect',*containers))
    return {'networks':[{'id':n['Id'],'name':n['Name'],'configuration':{k:n[k] for k in NETWORK_CONFIG}} for n in networks],
            'volumes':[{'name':v['Name'],'driver':v['Driver'],'scope':v['Scope'],'mountpoint':v['Mountpoint'],
                        'optionsSHA256':sha(json.dumps(v.get('Options'),sort_keys=True).encode()),
                        'labelsSHA256':sha(json.dumps(v.get('Labels'),sort_keys=True).encode())} for v in volumes],
            'protection':{v['Name']:protection(v) for v in values}}


def resource_review(review,old,t):
    spec=field(review,'resourceReview',dict)
    require(set(spec)=={'evidencePath','evidenceSHA256','containerReplacements','bridgeReplacement'},'RESOURCE_EVIDENCE','Exact resource review required.')
    path=safe_path(field(spec,'evidencePath',str));raw=path.read_bytes()
    require(sha(raw)==field(spec,'evidenceSHA256',str),'RESOURCE_EVIDENCE','Independent resource evidence checksum differs.')
    evidence=strict_json(raw)
    require(type(evidence) is dict and set(evidence)=={'hostMachineId','dockerDaemonId','observedAt','originalBaselineSHA256',
            'networksBefore','networksNow','volumesBefore','volumesNow','protectionBefore','protectionNow','watchtowerEvents'}
            and evidence['hostMachineId']==t['hostMachineId'] and evidence['dockerDaemonId']==t['dockerDaemonId']
            and evidence['originalBaselineSHA256']==review['originalBaselineSHA256'],'RESOURCE_EVIDENCE','Resource evidence origin differs.')
    try:
        observed=dt.datetime.fromisoformat(evidence['observedAt']);reviewed=dt.datetime.fromisoformat(review['reviewedAt'])
        fresh=observed.tzinfo is not None and observed<=reviewed and reviewed-observed<=dt.timedelta(hours=1)
    except (TypeError,ValueError):fresh=False
    require(fresh,'RESOURCE_EVIDENCE','Resource observation is stale or future-dated.')
    # Recovery-only historical exception: never infer the old bridge configuration.
    bridge=spec['bridgeReplacement']
    if bridge is not None:
        require(type(bridge) is dict and set(bridge)=={'before','now','acknowledged','historicalEquivalence'}
                and valid_digest('sha256:'+field(bridge,'before',str)) and valid_digest('sha256:'+field(bridge,'now',str))
                and bridge['before']!=bridge['now'] and bridge['acknowledged'] is True
                and bridge['historicalEquivalence']=='not-established','RESOURCE_EVIDENCE','Exact acknowledged bridge change with unverified history required.')
    before=network_records(evidence['networksBefore'],bridge['before'] if bridge else None)
    now=network_records(evidence['networksNow'])
    require(set(before)==set(now) and {n['id'] for n in before.values()}==set(old['networkIds'].splitlines()),
            'RESOURCE_EVIDENCE','Original network inventory differs.')
    used=False
    for name,n in before.items():
        current=now[name]
        if n['id']!=current['id']:
            cfg=current['configuration']
            require(name=='bridge' and bridge is not None and n['id']==bridge['before'] and current['id']==bridge['now']
                    and n['configuration'] is None and cfg['Driver']=='bridge' and cfg['Scope']=='local'
                    and cfg['Internal'] is False and cfg['EnableIPv4'] is True and cfg['ConfigOnly'] is False
                    and (cfg['Options'] or {}).get('com.docker.network.bridge.default_bridge')=='true',
                    'RESOURCE_EVIDENCE','Only the exact acknowledged default-bridge replacement is supported.')
            used=True
        else:require(n['configuration']==current['configuration'],'RESOURCE_EVIDENCE','Protected network configuration changed.')
    require(used==(bridge is not None) and now[t['proxyNetwork']]['id']==t['proxyNetworkId'],
            'RESOURCE_EVIDENCE','Unused bridge approval or protected proxy replacement.')
    volumes=evidence['volumesBefore'];current=evidence['volumesNow']
    require(type(volumes) is list and type(current) is list,'RESOURCE_EVIDENCE','Volume evidence required.')
    keys={'name','driver','scope','mountpoint','optionsSHA256','labelsSHA256'}
    for v in volumes+current:
        require(type(v) is dict and set(v)==keys and all(type(x) is str and x for x in v.values())
                and re.fullmatch(HEX,v['optionsSHA256']) and re.fullmatch(HEX,v['labelsSHA256']),'RESOURCE_EVIDENCE','Malformed volume evidence.')
    require(len({v['name'] for v in volumes})==len(volumes) and {v['name'] for v in volumes}==set(old['volumeNames'].splitlines())
            and sorted(volumes,key=lambda x:x['name'])==sorted(current,key=lambda x:x['name']),
            'RESOURCE_EVIDENCE','Protected volume identity/configuration changed.')
    previous=field(evidence,'protectionBefore',dict);protected=field(evidence,'protectionNow',dict)
    require(set(previous)==set(protected)=={d['name'] for d in review['containers']},'RESOURCE_EVIDENCE','Incomplete protected configuration inventory.')
    for name,v in previous.items():
        require(type(v) is dict and set(v)=={'labels','networks'} and type(v['labels']) is dict and type(v['networks']) is dict
                and type(protected[name]) is dict and set(protected[name])=={'labels','networks'},'RESOURCE_EVIDENCE','Malformed protection record.')
        expected=json.loads(json.dumps(v))
        if bridge is not None and name!='/passwordforge' and expected['networks'].get('bridge')==bridge['before']:
            expected['networks']['bridge']=bridge['now']
        require(expected==protected[name],'RESOURCE_EVIDENCE','Routing, Compose ownership or protected attachment changed.')
    replacements=spec['containerReplacements']
    baseline_differences(old['containers'],review['containers'],replacements)
    if replacements:
        require('/watchtower' in previous,'RESOURCE_EVIDENCE','Watchtower identity evidence required.')
        entry=replacements[0];events=field(evidence,'watchtowerEvents',list)
        require(len(events)==3 and all(type(e) is dict and set(e)=={'time','message'} and type(e['message']) is str for e in events),
                'RESOURCE_EVIDENCE','Three independent Watchtower update events required.')
        a,b,c=events
        require(re.fullmatch(r'Found new ghcr\.io/homarr-labs/homarr:[A-Za-z0-9_.-]+ image \('+entry['now']['image'][7:19]+r'\)',a['message'])
                and b['message']=='Stopping /homarr ('+entry['before']['id'][:12]+') with SIGTERM'
                and c['message']=='Creating /homarr','RESOURCE_EVIDENCE','Watchtower activity does not support this replacement.')
        try:
            times=[dt.datetime.fromisoformat(e['time']) for e in events]
            started=dt.datetime.fromisoformat(next(d['startedAt'] for d in review['containers'] if d['name']=='/homarr'))
            coherent=all(x.tzinfo is not None for x in times) and times[0]<=times[1]<=times[2]<=observed and abs(started-times[2])<=dt.timedelta(minutes=2)
        except (TypeError,ValueError):coherent=False
        require(coherent,'RESOURCE_EVIDENCE','Update event times do not match the replacement.')
    else:require(evidence['watchtowerEvents']==[],'RESOURCE_EVIDENCE','Unexpected update evidence.')
    review['_resourceEvidence']=evidence;review['_resourceEvidenceRaw']=raw
    return replacements


def live_resource_guard(review,old):
    if 'resourceReview' not in review:
        require(set(docker('network','ls','--no-trunc','--format','{{.ID}}').splitlines())==set(old['networkIds'].splitlines())
                and set(docker('volume','ls','--format','{{.Name}}').splitlines())==set(old['volumeNames'].splitlines()),
                'RESOURCE_EVIDENCE','Unreviewed network or volume change.')
        return
    evidence=review['_resourceEvidence'];actual=resource_snapshot()
    require(network_records(actual['networks'])==network_records(evidence['networksNow'])
            and sorted(actual['volumes'],key=lambda x:x['name'])==sorted(evidence['volumesNow'],key=lambda x:x['name'])
            and actual['protection']==evidence['protectionNow'],'RESOURCE_EVIDENCE','Resources changed after review.')
    if review['resourceReview']['containerReplacements']:
        watch=next(d for d in review['containers'] if d['name']=='/watchtower')
        text=docker('logs','--since','24h',watch['id'],include_stderr=True)
        observed=[]
        for line in text.splitlines():
            time=re.search(r'time="([^"]+)"',line);message=re.search(r'msg="([^"]+)"',line)
            if time and message:observed.append({'time':time[1],'message':message[1]})
        require(all(e in observed for e in evidence['watchtowerEvents']),'RESOURCE_EVIDENCE','Independent Watchtower events no longer verifiable.')


def recovery_review(path,checksum,t,target_sha,origin,manifest_sha,report_sha):
    require(re.fullmatch(HEX,checksum or ''),'BASELINE_REVIEW','Checksummed operator baseline review required.')
    path=safe_path(path);raw=path.read_bytes();require(sha(raw)==checksum,'BASELINE_REVIEW','Baseline review checksum differs.')
    review=strict_json(raw)
    require(type(review) is dict and set(review)-{'resourceReview'}=={'schemaVersion','failureManifestSHA256','failureReportSHA256',
            'originalBaselineSHA256','targetSHA256','toolSHA256','reviewedAt','expiresAt','containers','differences'}
            and type(review['schemaVersion']) is int and review['schemaVersion']==1
            and review['failureManifestSHA256']==manifest_sha and review['failureReportSHA256']==report_sha
            and review['targetSHA256']==target_sha and review['toolSHA256']==sha(Path(__file__).read_bytes()),
            'BASELINE_REVIEW','Review is not bound to this recovery evidence, target and tool.')
    now=dt.datetime.now(dt.timezone.utc)
    try:
        start=dt.datetime.fromisoformat(review['reviewedAt']);end=dt.datetime.fromisoformat(review['expiresAt'])
        fresh=start.tzinfo is not None and end.tzinfo is not None and start<=now<end and end-start<=dt.timedelta(hours=1)
    except (TypeError,ValueError):fresh=False
    require(fresh,'BASELINE_REVIEW','Review is stale, future-dated or lacks timezone.')
    baseline_raw=(origin/'evidence/baseline-before.json').read_bytes();old=strict_json(baseline_raw)
    require(review['originalBaselineSHA256']==sha(baseline_raw) and old['composeSHA256']==t['composeSHA256'],
            'BASELINE_REVIEW','Original baseline or Compose differs.')
    replacements=resource_review(review,old,t) if 'resourceReview' in review else ()
    require(review['differences']==baseline_differences(old['containers'],review['containers'],replacements),
            'BASELINE_REVIEW','Explicit restart difference review required.')
    return review,raw


def recover_export(args,t,target_sha,run):
    require(all(type(x) is str and x for x in (args.failed_run,args.source,args.baseline_review)),
            'RECOVERY_INPUT','Original run, source and reviewed baseline paths required.')
    require(not run.exists(),'RUN_EXISTS','Recovery evidence must be new.')
    require(Path(args.failed_run) not in run.parents,'EVIDENCE_PATH','Never write inside the failed run.')
    rec,report,metadata,iid,context,oldtarget,origin=failed_export(args.failed_run,args.failure_manifest_sha256,args.failure_report_sha256,args.source)
    require(all(t[k]==oldtarget[k] for k in TARGET_KEYS-{'evidenceRoot'}),'BASELINE_REVIEW','Host, daemon, Compose or network identity changed.')
    require(Path(args.source) not in run.parents and Path(args.source) not in Path(t['evidenceRoot']).parents,
            'EVIDENCE_PATH','Recovery must remain outside original source.')
    review,raw_review=recovery_review(args.baseline_review,args.baseline_review_sha256,t,target_sha,origin,args.failure_manifest_sha256,args.failure_report_sha256)
    require(sys.platform=='linux' and os.getuid()!=0 and Path('/etc/machine-id').read_text().strip()==t['hostMachineId'],'HOST','Wrong recovery host.')
    lock=Path.home()/'.cache/passwordforge-docker.lock'
    try:lock.lstat()
    except FileNotFoundError:pass
    else:raise FileExistsError('Operation lock conflict; never auto-recover.')
    with locked():
        live(t);compose_check(t)
        require(current_baseline()==container_baseline(review['containers']),'BASELINE_REVIEW','Fresh baseline changed after operator review.')
        original_baseline=read(origin/'evidence/baseline-before.json');live_resource_guard(review,original_baseline)
        baseline=production(t);others=unrelated();operation=secrets.token_hex(16)
        require(operation!=rec['run'],'RECOVERY_IDENTITY','Recovery identity must differ from build ownership.')
        rec=dict(rec,stages={},targetSHA256=target_sha,production=baseline,unrelated=others,sourceDirectory=args.source,
                 recovery={'operationId':operation,'failedRun':args.failed_run,'failureManifestSHA256':args.failure_manifest_sha256,
                           'failureReportSHA256':args.failure_report_sha256,'baselineReviewSHA256':sha(raw_review),'toolSHA256':sha(Path(__file__).read_bytes())})
        d=image(rec['candidate']);rec['imageId']=d['Id'];rec['exportReference']=export_binding(rec,metadata,iid,d)
        require(d['Id']==report['identities']['platformSelectedManifestId'] and d['Descriptor']==report['identities']['selectedDescriptor'],
                'RECOVERY_IDENTITY','Selected manifest differs from failed build.')
        candidate(rec);require(os.statvfs(t['evidenceRoot']).f_bavail*os.statvfs(t['evidenceRoot']).f_frsize>=4*1024**3,'DISK','Insufficient export capacity.')
        run.mkdir(mode=0o700);pre=run/'preflight';pre.mkdir(mode=0o700);out=run/'build';out.mkdir(mode=0o700)
        (pre/'baseline-review.json').write_bytes(raw_review)
        if 'resourceReview' in review:
            (pre/'resource-evidence.json').write_bytes(review['_resourceEvidenceRaw'])
            rec['recovery']['resourceEvidenceSHA256']=sha(review['_resourceEvidenceRaw'])
        write(pre/'recovery.json',rec['recovery'])
        write(pre/'original-run.json',read(Path(args.failed_run)/'run.json'))
        rec['stages']['preflight']={'passed':True,'files':bind_files(run,pre)}
        old=Path(args.failed_run)/'build'
        for name in ('context.tar','metadata.json','build.iid','build.log','build.log.status.json'):(out/name).write_bytes((old/name).read_bytes())
        for name in ('export.log','export.log.status.json'):(out/('failed-'+name)).write_bytes((old/name).read_bytes())
        guard(t,rec);candidate(rec);live_resource_guard(review,original_baseline)
        require(current_baseline()==container_baseline(review['containers']),'BASELINE_REVIEW','New container change before export.')
        docker('image','save','--output',str(out/'image.tar'),rec['exportReference'],log=out/'export.log');candidate(rec)
        config=archive_config(out/'image.tar',d);identities=verify_identity(out/'image.tar',metadata,d,iid,config)
        require(config==report['identities']['configDigestReportedByBuildx'] and identities['exportId']==rec['exportReference'],
                'RECOVERY_IDENTITY','Recovered graph differs from original build.')
        rec.update(configId=config,identities=identities)
        write(out/'inspection.json',{'Id':d['Id'],'RootFS':d['RootFS'],'Config':{'Labels':d['Config']['Labels']}})
        write(out/'identity.json',dict(imageId=d['Id'],**identities))
        failed_export(args.failed_run,args.failure_manifest_sha256,args.failure_report_sha256,args.source)
        require(current_baseline()==container_baseline(review['containers']),'BASELINE_REVIEW','Baseline changed during recovery.')
        guard(t,rec);candidate(rec);live_resource_guard(review,original_baseline);rec['stages']['build']={'passed':True,'files':bind_files(run,out)}
        validate_record(run,rec,target_sha,sha(context));record_save(run,rec)
    print('PASS recover-export; STOP. No scan or later stage authorized.')
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage', choices=('preflight', 'build', 'scan', 'smoke', 'verify', 'deploy', 'cleanup', 'recover-export'))
    p.add_argument('--target', required=True); p.add_argument('--evidence', required=True)
    p.add_argument('--commit'); p.add_argument('--version'); p.add_argument('--candidate'); p.add_argument('--medium-review')
    p.add_argument('--image-id'); p.add_argument('--authorize-deploy', action='store_true'); p.add_argument('--accept-deployment', action='store_true')
    p.add_argument('--failed-run');p.add_argument('--failure-manifest-sha256');p.add_argument('--failure-report-sha256')
    p.add_argument('--source');p.add_argument('--baseline-review');p.add_argument('--baseline-review-sha256')
    args = p.parse_args(argv)
    try:
        t, target_sha = target(args.target)
        run = safe_path(args.evidence, Path(t['evidenceRoot']), exists=args.stage not in ('preflight','recover-export'))
        if args.stage=='recover-export':
            return recover_export(args,t,target_sha,run)
        if args.stage == 'preflight':
            require(not run.exists(), 'RUN_EXISTS', 'Never reuse evidence directories.')
            context, refs = source(args.commit, args.version)
            require(re.fullmatch(r'passwordforge:'+re.escape(args.version)+r'-candidate-[a-z0-9][a-z0-9-]{0,31}', args.candidate or ''), 'CANDIDATE', 'Unique versioned candidate tag required.')
            rec = {'schemaVersion': 1, 'run': secrets.token_hex(16), 'commit': args.commit, 'version': args.version,
                   'candidate': args.candidate, 'contextSHA256': sha(context), 'targetSHA256': target_sha, 'stages': {}}
        else:
            rec = read(run/'run.json'); context, refs = source(rec.get('commit'), rec.get('version'),rec.get('sourceDirectory') if 'recovery' in rec else None)
            validate_record(run, rec, target_sha, sha(context))
            require(args.stage not in rec['stages'] and not (run/args.stage).exists(), 'STAGE_EXISTS', 'Interrupted/completed stage cannot be replayed.')
            needed = {'build': 'preflight', 'scan': 'build', 'smoke': 'scan', 'verify': 'smoke', 'deploy': 'verify', 'cleanup': 'deploy'}[args.stage]
            require(rec['stages'].get(needed, {}).get('passed') is True, 'PREREQUISITE', 'Required earlier stage is incomplete.')
            if args.stage in ('smoke', 'verify', 'deploy'): medium_review(run, rec, args.medium_review)
            if args.stage == 'deploy': require(args.authorize_deploy, 'DEPLOY_APPROVAL', 'Separate explicit deployment approval required.')
            if args.stage == 'cleanup':
                require(args.accept_deployment and valid_digest(args.image_id) and args.image_id != rec['imageId'], 'CLEANUP_APPROVAL', 'Explicit acceptance and unused image ID required.')
        require(sys.platform == 'linux' and os.getuid() != 0 and Path('/etc/machine-id').read_text().strip() == t['hostMachineId'], 'HOST', 'Verify intended non-root host before contact/writes.')
        lock = Path.home()/'.cache/passwordforge-docker.lock'
        try: lock.lstat()
        except FileNotFoundError: pass
        else: raise FileExistsError('Operation lock conflict; never auto-recover.')
        with locked():
            live(t); compose_check(t)
            baseline = production(t)
            others = unrelated()
            if args.stage != 'preflight':
                require(others == rec['unrelated'], 'UNRELATED_DRIFT', 'Unrelated workloads changed.')
                require(baseline == rec['production'], 'PRODUCTION_DRIFT', 'Production changed since preflight.')
                if 'build' in rec['stages']: candidate(rec)
            else:
                for ref in (*refs, SCANNER): image(ref)
                require(rec['candidate'] not in docker('image', 'ls', '--format', '{{.Repository}}:{{.Tag}}').splitlines(), 'TAG_COLLISION', 'Candidate occupied.')
                require(os.statvfs(t['evidenceRoot']).f_bavail * os.statvfs(t['evidenceRoot']).f_frsize >= 4*1024**3, 'DISK', 'At least 4 GiB free required; review capacity.')
                rec['production'] = baseline; rec['unrelated'] = others; run.mkdir(mode=0o700)
            out = run/args.stage; out.mkdir(mode=0o700)
            if args.stage == 'build': build(t, run, rec, out, context, refs)
            elif args.stage == 'scan': scan(t, run, rec, out)
            elif args.stage == 'smoke': smoke(t, run, rec, out)
            elif args.stage == 'deploy':
                override = out/'image.yaml'; override.write_text('services:\n  passwordforge:\n    image: '+rec['imageId']+'\n')
                compose_check(t, override, rec['imageId']); candidate(rec)
                require(production(t) == baseline and sha(Path(t['composeFile']).read_bytes()) == t['composeSHA256'], 'PRODUCTION_DRIFT', 'Recheck immediately before replacement.')
                docker(*compose_args(t, override), 'up', '-d', '--no-build', '--pull', 'never', '--no-deps', '--force-recreate', 'passwordforge', log=out/'deploy.log')
                runtime_check('passwordforge', out, rec, t['httpsURL'])
                rec['production'] = production(t)
                require(rec['production']['imageId'] == rec['imageId'], 'DEPLOY_IDENTITY', 'Running wrong image.')
            elif args.stage == 'cleanup': cleanup_image(rec, args.image_id)
            elif args.stage == 'verify': candidate(rec)
            require(sha(source(rec['commit'], rec['version'],rec.get('sourceDirectory') if 'recovery' in rec else None)[0]) == rec['contextSHA256'], 'SOURCE_CHANGED', 'Source changed during operation.')
            if args.stage != 'deploy': require(production(t) == baseline, 'PRODUCTION_DRIFT', 'Production changed; stop.')
            require(unrelated() == others, 'UNRELATED_DRIFT', 'Unrelated workloads changed during operation.')
            if 'imageId' in rec: candidate(rec)
            rec['stages'][args.stage] = {'passed': True, 'files': bind_files(run, out)}
            record_save(run, rec)
        print('PASS '+args.stage+'; STOP. No next stage authorized.')
        return 0
    except Exception as e:
        print('STOP ['+(e.code if isinstance(e, SecurityError) else 'IO_OR_SCHEMA')+']; preserve evidence; no later stage authorized.', file=sys.stderr)
        return 2


if __name__ == '__main__': sys.exit(main())
