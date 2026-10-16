"""Exercise real parsers in normal and optimized interpreters; fixtures contain no secrets."""
import ast
import copy
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class OptimizationTests(unittest.TestCase):
    def invoke(self, command, evidence, *args):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.json'
            path.write_text(json.dumps(evidence))
            return [subprocess.run([sys.executable, '-B', *flags, str(ROOT/'checks.py'), command, str(path), *args],
                                   capture_output=True, text=True)
                    for flags in ([], ['-O'])]

    def test_no_python_assert_in_release_code(self):
        for path in [ROOT/name for name in ('docker-release.py','checks.py','security.py','evidence_schema.py','scan_contract.py','builder_contract.py','build_identity.py')]:
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(path.read_text()))), path.name)
        self.assertNotIn('assert ', (ROOT/'runtime-check.sh').read_text())

    def test_database_freshness_and_schema_survive_optimization(self):
        now = dt.datetime.now(dt.timezone.utc)
        good = {'Version':2, 'UpdatedAt':(now-dt.timedelta(hours=1)).isoformat(), 'NextUpdate':(now+dt.timedelta(hours=2)).isoformat()}
        for result in self.invoke('database', good): self.assertEqual(result.returncode, 0, result.stderr)
        for key, value in [('Version',1), ('UpdatedAt',(now-dt.timedelta(hours=49)).isoformat()),
                           ('UpdatedAt',(now+dt.timedelta(hours=1)).isoformat()), ('NextUpdate',(now-dt.timedelta(seconds=1)).isoformat())]:
            bad = dict(good); bad[key] = value
            for result in self.invoke('database',bad):
                self.assertEqual(result.returncode,2)
                self.assertIn('DATABASE_CHECK_',result.stderr)

    def test_scanner_isolation_survives_optimization(self):
        good = {'NetworkMode':'none','Networks':{},'User':'1000:1000','ReadonlyRootfs':True,'Privileged':False,
                'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,'PidsLimit':128,
                'NanoCpus':1000000000,'PortBindings':{},'Mounts':[]}
        for result in self.invoke('isolation',good,'none','1000:1000','/tmp/owned'): self.assertEqual(result.returncode,0,result.stderr)
        for key, value in [('NetworkMode','proxy'),('User','0'),('ReadonlyRootfs',False),('Privileged',True),
                           ('CapDrop',[]),('Memory',0),('PidsLimit',0),('NanoCpus',0),('PortBindings',{'8080':[]}),
                           ('Mounts',[{'Type':'bind','Source':'/var/run/docker.sock','Destination':'/input','RW':False}])]:
            bad = dict(good); bad[key] = value
            for result in self.invoke('isolation',bad,'none','1000:1000','/tmp/owned'):
                self.assertEqual(result.returncode,2)
                self.assertIn('ISOLATION_CHECK_',result.stderr)

    def test_runtime_hardening_survives_optimization(self):
        good = {'User':'10001:10001','Networks':{'bridge':{}},'HostConfig':{
            'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],
            'PidsLimit':128,'Memory':134217728,'NanoCpus':1000000000,'RestartPolicy':{'Name':'no'},'NetworkMode':'bridge',
            'PortBindings':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'18080'}]},
            'Tmpfs':{'/tmp':'rw,noexec,nosuid,size=16m,mode=1777'}},'Healthcheck':{
            'Interval':30000000000,'Timeout':3000000000,'StartPeriod':10000000000,'Retries':3,
            'Test':['CMD','wget','http://127.0.0.1:8080/healthz']}}
        for result in self.invoke('hardening',good,'18080'): self.assertEqual(result.returncode,0,result.stderr)
        for section,key,value in [(None,'User','0'),(None,'Networks',{'proxy':{}}),('HostConfig','ReadonlyRootfs',False),
                                 ('HostConfig','CapAdd',['SYS_ADMIN']),('HostConfig','SecurityOpt',[]),('HostConfig','Memory',0),
                                 ('HostConfig','PortBindings',{'8080/tcp':[{'HostIp':'0.0.0.0','HostPort':'18080'}]}),
                                 ('HostConfig','Tmpfs',{}),('Healthcheck','Retries',0),('Healthcheck','Test',[])]:
            bad = copy.deepcopy(good); (bad[section] if section else bad)[key] = value
            for result in self.invoke('hardening',bad,'18080'):
                self.assertEqual(result.returncode,2)
                self.assertIn('Validation failed',result.stderr)

if __name__ == '__main__': unittest.main()
