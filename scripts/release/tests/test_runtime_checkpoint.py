"""Actual precreation shell boundary with public identities and mocked tools."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_docker_release import ROOT, release
from test_publication import approved
from runtime_inputs import prepare_inputs


class ProductionInspectionTests(unittest.TestCase):
    def execute(self, scenario='correct', conditional=False):
        baseline={'containerId':'b'*64,'imageId':'sha256:'+'c'*64,
            'startedAt':'2026-01-01T00:00:00Z','name':'/passwordforge',
            'project':'passwordforge','service':'passwordforge'}
        inspected=dict(baseline,status='running',health='healthy')
        if scenario=='wrong-image':inspected['imageId']='sha256:'+'d'*64
        if scenario=='wrong-container':inspected['containerId']='d'*64
        if scenario=='wrong-start':inspected['startedAt']='2026-01-02T00:00:00Z'
        if scenario=='incomplete':del inspected['containerId']
        if scenario=='unhealthy':inspected['health']='unhealthy'
        if scenario=='wrong-project':inspected['project']='different-project'
        if scenario=='wrong-service':inspected['service']='different-service'
        if scenario=='wrong-type':inspected['status']=True
        raw='' if scenario=='empty' else 'garbage' if scenario=='malformed' else json.dumps(inspected)
        source=(ROOT/'runtime-check.sh').read_text()
        prefix=source.split('if docker_cmd run',1)[0]
        script=r'''
set -Eeuo pipefail
containers=(); project=pfcheck-public-fixture
note(){ :; }
ss(){ return 0; }
docker_cmd(){
 if [[ $1 == container ]]; then return 1; fi
 if [[ $scenario == failed ]]; then return 1; fi
 printf '%s' "$inspection"
}
python3(){ "$TEST_PYTHON" "$@"; }
'''+prefix+'printf "CREATION_REACHED\\n"; return 0\n}\n'
        script+=('if runtime_check "$target"; then exit 0; else exit $?; fi\n' if conditional
                 else 'runtime_check "$target"\n')
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);(base/'runtime').mkdir()
            (base/'runtime-inputs.json').write_text(json.dumps({'version':'0.6.0','production':baseline}))
            path=base/'probe.sh';path.write_text(script,encoding='utf-8',newline='\n')
            env=dict(os.environ,scenario=scenario,inspection=raw,root=ROOT.as_posix(),
                evidence=(base/'runtime').as_posix(),TEST_PYTHON=sys.executable,
                target=baseline['imageId'] if scenario=='same-image' else 'sha256:'+'a'*64)
            bash=shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'
            return subprocess.run([bash,'--noprofile','--norc',str(path)],env=env,text=True,capture_output=True)

    def test_failed_empty_malformed_inspection_blocks_before_creation(self):
        for conditional in (False,True):
            for scenario in ('failed','empty','malformed','incomplete'):
                with self.subTest(scenario=scenario,conditional=conditional):
                    result=self.execute(scenario,conditional)
                    self.assertNotEqual(result.returncode,0)
                    self.assertNotIn('CREATION_REACHED',result.stdout)

    def test_incorrect_protected_identity_blocks_before_creation(self):
        for conditional in (False,True):
            for scenario in ('wrong-image','wrong-container','wrong-start','unhealthy','wrong-project','wrong-service','wrong-type','same-image'):
                with self.subTest(scenario=scenario,conditional=conditional):
                    result=self.execute(scenario,conditional)
                    self.assertNotEqual(result.returncode,0)
                    self.assertNotIn('CREATION_REACHED',result.stdout)

    def test_correct_protected_identity_reaches_creation_boundary(self):
        for conditional in (False,True):
            result=self.execute(conditional=conditional)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('CREATION_REACHED',result.stdout)


class RuntimeVersionTests(unittest.TestCase):
    def test_multiple_versions_bind_approval_package_tag_and_image(self):
        for version in ('0.6.0','1.0.0','2.3.4'):
            data=approved();data['releaseVersion']=version
            image={'Config':{'Labels':{'org.opencontainers.image.version':version}}}
            self.assertEqual(prepare_inputs('passwordforge:'+version,{'version':version},image,data)['version'],version)

    def test_missing_malformed_and_inconsistent_versions_fail(self):
        for value in (None,False,'','1.0','v1.0.0','1.0.0'):
            with self.subTest(value=value),self.assertRaises(Exception):
                prepare_inputs('passwordforge:0.6.0',{'version':'0.6.0'},
                    {'Config':{'Labels':{'org.opencontainers.image.version':'0.6.0'}}},
                    dict(approved(),releaseVersion=value))
        for package,image,ref in [({}, {'Config':{'Labels':{}}}, 'passwordforge:0.6.0'),
            ({'version':'1.0.0'},{'Config':{'Labels':{'org.opencontainers.image.version':'0.6.0'}}},'passwordforge:0.6.0'),
            ({'version':'0.6.0'},{'Config':{'Labels':{'org.opencontainers.image.version':'1.0.0'}}},'passwordforge:0.6.0'),
            ({'version':'0.6.0'},{'Config':{'Labels':{'org.opencontainers.image.version':'0.6.0'}}},'passwordforge:1.0.0')]:
            with self.assertRaises(Exception):prepare_inputs(ref,package,image,approved())

    def test_runtime_missing_or_bad_approval_never_invokes_wrapper(self):
        with tempfile.TemporaryDirectory() as folder:
            out=Path(folder);(out/'package.json').write_text('{"version":"0.6.0"}')
            private=out/'approval.json';private.write_text(json.dumps(approved()))
            image={'Id':'sha256:'+'a'*64,'Config':{'Labels':{'org.opencontainers.image.version':'0.6.0'}}}
            with patch.object(release,'SOURCE',out),patch.object(release,'passed_scan',return_value=(image,{})),patch.object(release,'command') as command:
                for args in ((),(private,'0'*64)):
                    with self.assertRaises(Exception):release.runtime('passwordforge:0.6.0',out,*args)
                self.assertFalse((out/'runtime-started.json').exists());command.assert_not_called()

    def test_runtime_mismatched_version_stops_before_evidence_and_wrapper(self):
        with tempfile.TemporaryDirectory() as folder:
            out=Path(folder);(out/'package.json').write_text('{"version":"0.6.0"}')
            data=approved();data['releaseVersion']='1.0.0'
            private=out/'approval.json';private.write_text(json.dumps(data))
            image={'Id':'sha256:'+'a'*64,'Config':{'Labels':{'org.opencontainers.image.version':'0.6.0'}}}
            with patch.object(release,'SOURCE',out),patch.object(release,'passed_scan',return_value=(image,{})),patch.object(release,'command') as command:
                with self.assertRaises(Exception):release.runtime('passwordforge:0.6.0',out,private,hashlib.sha256(private.read_bytes()).hexdigest())
                self.assertFalse((out/'runtime-started.json').exists());command.assert_not_called()
