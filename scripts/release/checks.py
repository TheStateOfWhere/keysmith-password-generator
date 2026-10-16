"""Strict database/container checks; no Docker operations or secret output."""
import datetime as dt
import pathlib
import sys
from security import require, SecurityError
from evidence_schema import field, text, strict_json, security_types

def load(path):
    return strict_json(pathlib.Path(path).read_text())

def database(path):
    data = load(path)
    field(data, "Version", int); text(data, "UpdatedAt"); text(data, "NextUpdate")
    now = dt.datetime.now(dt.timezone.utc)
    updated = dt.datetime.fromisoformat(data['UpdatedAt'].replace('Z', '+00:00'))
    expiry = dt.datetime.fromisoformat(data['NextUpdate'].replace('Z', '+00:00'))
    require(data['Version'] == 2 and updated <= now < expiry, 'DATABASE_CHECK_1', 'Database expired, future-dated or wrong schema')
    require(now - updated <= dt.timedelta(hours=48), 'DATABASE_CHECK_2', 'Database older than handoff freshness policy (48 hours)')
    return data

def isolation(path, network, uid, work):
    d = load(path)
    security_types(d, scanner=True)
    require(network in ('none', 'bridge') and d['NetworkMode'] == network, 'ISOLATION_CHECK_1', 'isolation security requirement 1 failed.')
    require(not d['Networks'] or set(d['Networks']) <= {network}, 'ISOLATION_CHECK_2', 'isolation security requirement 2 failed.')
    require(d['User'] == uid and d['ReadonlyRootfs'] and (not d['Privileged']), 'ISOLATION_CHECK_3', 'isolation security requirement 3 failed.')
    require(d['CapDrop'] == ['ALL'] and any((x in ('no-new-privileges','no-new-privileges:true') for x in d['SecurityOpt'])), 'ISOLATION_CHECK_4', 'isolation security requirement 4 failed.')
    require(d['Memory'] == 1073741824 and d['PidsLimit'] == 128 and (d['NanoCpus'] == 1000000000), 'ISOLATION_CHECK_5', 'isolation security requirement 5 failed.')
    require(not d['PortBindings'], 'ISOLATION_CHECK_6', 'isolation security requirement 6 failed.')
    base = pathlib.Path(work).resolve()
    for mount in d['Mounts']:
        if mount['Type'] == 'tmpfs':
            require(mount['Destination'] == '/tmp', 'ISOLATION_CHECK_10', 'isolation security requirement 10 failed.')
            continue
        require(mount['Type'] == 'bind', 'ISOLATION_CHECK_7', 'isolation security requirement 7 failed.')
        source = pathlib.Path(mount['Source']).resolve()
        require(source.parent == base and source.name in ('input', 'output', 'cache'), 'ISOLATION_CHECK_8', 'isolation security requirement 8 failed.')
        require(mount['Destination'] == '/' + source.name, 'ISOLATION_CHECK_9', 'isolation security requirement 9 failed.')
        if source.name == 'input':
            require(not mount['RW'], 'ISOLATION_CHECK_11', 'isolation security requirement 11 failed.')

def hardening(path, port):
    d = load(path)
    h = d['HostConfig']
    hc = field(d, 'Healthcheck', dict)
    field(d, 'User', str); field(d, 'Networks', dict)
    security_types(dict(h, User=d['User']))
    require(h.get('CapAdd') is None or type(h['CapAdd']) is list, 'SCHEMA_CAPADD', 'Malformed CapAdd.')
    for key in ['Interval','Timeout','StartPeriod','Retries']: field(hc,key,int)
    require(all(type(x) is str for x in field(hc,'Test',list)), 'SCHEMA_HEALTH', 'Malformed health test.')
    field(h,'RestartPolicy',dict); field(h['RestartPolicy'],'Name',str)
    field(h,'Tmpfs',dict); text(h['Tmpfs'],'/tmp')
    require(d['User'] == '10001:10001' and h['ReadonlyRootfs'] and (not h['Privileged']), 'RUNTIME_HARDENING_1', 'Runtime hardening requirement 1 failed.')
    require(h['CapDrop'] == ['ALL'] and (not h['CapAdd']), 'RUNTIME_HARDENING_2', 'Runtime hardening requirement 2 failed.')
    require(any((x in ('no-new-privileges','no-new-privileges:true') for x in h['SecurityOpt'])), 'RUNTIME_HARDENING_3', 'Runtime hardening requirement 3 failed.')
    require(h['PidsLimit'] == 128 and h['Memory'] == 134217728 and (h['NanoCpus'] == 1000000000), 'RUNTIME_HARDENING_4', 'Runtime hardening requirement 4 failed.')
    require(h['RestartPolicy']['Name'] == 'no', 'RUNTIME_HARDENING_5', 'Runtime hardening requirement 5 failed.')
    require(h['NetworkMode'] == 'bridge' and set(d['Networks']) == {'bridge'}, 'RUNTIME_HARDENING_6', 'Runtime hardening requirement 6 failed.')
    require(h['PortBindings'] == {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': port}]}, 'RUNTIME_HARDENING_7', 'Runtime hardening requirement 7 failed.')
    require(all((x in h['Tmpfs']['/tmp'].split(',') for x in ['rw', 'noexec', 'nosuid', 'size=16m', 'mode=1777'])), 'RUNTIME_HARDENING_8', 'Runtime hardening requirement 8 failed.')
    require(hc['Interval'] == 30000000000 and hc['Timeout'] == 3000000000, 'RUNTIME_HARDENING_9', 'Runtime hardening requirement 9 failed.')
    require(hc['StartPeriod'] == 10000000000 and hc['Retries'] == 3, 'RUNTIME_HARDENING_10', 'Runtime hardening requirement 10 failed.')
    require('http://127.0.0.1:8080/healthz' in ' '.join(hc['Test']), 'RUNTIME_HARDENING_11', 'Runtime hardening requirement 11 failed.')

if __name__=='__main__':
    try:
        name,*args=sys.argv[1:]
        {'database':database,'isolation':isolation,'hardening':hardening}[name](*args)
    except Exception as error:
        print('Validation failed ['+(error.code if isinstance(error,SecurityError) else 'IO_OR_SCHEMA')+']; stop.',file=sys.stderr)
        sys.exit(2)
