"""Execute the canonical read-only preflight with mock host/tool metadata only."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from test_docker_release import ROOT
from test_builder_compatibility import GOOD

class HostPreflightTests(unittest.TestCase):
    def execute(self,scenario='valid'):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);archive=folder/'fixture.tar.gz'
            source={name:(ROOT/name).read_bytes() for name in ('builder_contract.py','docker-release.py','private_metadata.py','source_approval.py','security.py','evidence_schema.py')}
            source={'passwordforge/scripts/release/'+name:data for name,data in source.items()}
            source['passwordforge/Dockerfile']=(ROOT.parents[1]/'Dockerfile').read_bytes()
            source['passwordforge/package.json']=json.dumps({'version':'0.5.0' if scenario=='old-source' else '0.6.0'}).encode()
            files=[{'path':name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'mode':'0644'} for name,data in source.items()]
            source['SOURCE-MANIFEST.json']=json.dumps({'version':'0.5.0' if scenario=='old-manifest' else '0.6.0','sourceCommit':'c'*40,'files':files,'fileCount':len(files)}).encode()
            with tarfile.open(archive,'w:gz') as tar:
                for name,data in source.items():
                    m=tarfile.TarInfo(name);m.size=len(data);m.mode=0o644;tar.addfile(m,io.BytesIO(data))
            expected=hashlib.sha256(archive.read_bytes()).hexdigest()
            staged=folder/'staged';staged.mkdir()
            for name,data in source.items():
                if name.startswith('passwordforge/'):
                    path=staged/name[len('passwordforge/'):];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            if scenario=='changed-staged':(staged/'package.json').write_text('changed')
            if scenario=='extra-staged':(staged/'unexpected.txt').write_text('extra')
            compose=folder/'compose.yaml';compose.write_bytes(b'private fixture configuration')
            approved={'releaseVersion':'0.6.0','sourceCommit':'c'*40,'sourceArchiveSHA256':expected,'sourceManifestSHA256':hashlib.sha256(source['SOURCE-MANIFEST.json']).hexdigest(),'productionContainerId':'a'*64,
                'productionImageId':'sha256:'+'d'*64,'productionImageTag':'passwordforge:0.5.0',
                'productionStartedAt':'2026-01-01T00:00:00Z','productionComposePath':'/private/compose.yaml',
                'productionComposeSHA256':hashlib.sha256(compose.read_bytes()).hexdigest(),
                'composeProject':'passwordforge','composeService':'passwordforge','productionContainerName':'passwordforge',
                'proxyNetwork':'proxy','proxyNetworkId':'c'*64,'routerHost':'password.example.invalid','httpsEntryPoint':'websecure'}
            if scenario=='missing-identity':approved.pop('productionImageId')
            if scenario=='bad-identity':approved['productionImageId']='sha256'
            if scenario=='wrong-source-commit':approved['sourceCommit']='d'*40
            private=folder/'approval.json';private.write_text(json.dumps(approved))
            private_sha=hashlib.sha256(private.read_bytes()).hexdigest()
            if scenario=='bad-metadata-sha':private_sha='0'*64
            code=(ROOT/'host-preflight.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY\n',1)[0]
            ast.parse(code);calls=[];original=Path.read_text
            def run(args,**kwargs):
                calls.append(args)
                if args[0]=='ss':return subprocess.CompletedProcess(args,0,'','')
                if args[:3]!=['docker','--host','unix:///var/run/docker.sock']:raise RuntimeError('Unexpected tool')
                a=args[3:];op=a[:2]
                if a[0]=='version':d={'client':'29.8.2','engine':'29.8.2','os':'linux','arch':'amd64'}
                elif a[0]=='info':d={'root':'/var/lib/docker','memoryBytes':8589934592,'cpus':4}
                elif op==['compose','version']:return subprocess.CompletedProcess(args,0,'5.6.0','')
                elif op==['buildx','version']:return subprocess.CompletedProcess(args,0,'v0.fixture','')
                elif op==['buildx','inspect']:
                    if '--format' in a:return subprocess.CompletedProcess(args,1,'','unknown flag: --format')
                    raw='malformed' if scenario=='malformed-builder' else GOOD
                    if scenario=='no-amd64':raw=raw.replace('linux/amd64, linux/amd64/v2, linux/amd64/v3, linux/arm64','linux/arm64')
                    return subprocess.CompletedProcess(args,0,raw,'')
                elif op==['context','inspect']:d=[{'Endpoints':{'docker':{'Host':'ssh://remote' if scenario=='remote-context' else 'unix:///var/run/docker.sock'}}}]
                elif op==['image','ls']:return subprocess.CompletedProcess(args,0,'passwordforge:0.5.0'+('\npasswordforge:0.6.0' if scenario=='candidate-image' else ''),'')
                elif op==['image','inspect']:
                    if scenario=='missing-cache' and '--platform' in a:return subprocess.CompletedProcess(args,1,'','PRIVATE-CREDENTIAL-FIXTURE')
                    d={'id':'sha256:'+'d'*64,'os':'linux','arch':'amd64'}
                    if scenario=='wrong-production':d['id']='sha256:'+'a'*64
                elif op==['container','ls'] and '--filter' in a:return subprocess.CompletedProcess(args,0,'a'*64+('\n'+'d'*64 if scenario=='ambiguous-production' else ''),'')
                elif op==['container','ls']:return subprocess.CompletedProcess(args,0,'a passwordforge passwordforge:0.5.0\nb traefik traefik:fixture'+('\nc pfscan-fixture trivy:fixture' if scenario=='conflict' else '\nc candidate passwordforge:0.6.0' if scenario=='candidate-container' else ''),'')
                elif op==['container','inspect']:
                    if a[2]=='passwordforge':d={'id':'a'*64,'imageId':'sha256:'+'d'*64,'status':'running','started':'2026-01-01T00:00:00Z','health':'healthy','project':'passwordforge','service':'passwordforge','enabled':'true','network':'proxy','rule':'Host(`password.example.invalid`)','entrypoint':'websecure','tls':'true','routerService':'passwordforge','backendPort':'8080','networks':{'proxy':{'NetworkID':'c'*64}}}
                    else:d={'id':'b'*64,'imageId':'sha256:'+'b'*64,'status':'running','networks':{'proxy':{'NetworkID':'c'*64}}}
                elif op==['network','inspect']:d={'id':'c'*64,'driver':'bridge','scope':'local'}
                else:raise RuntimeError('Unexpected Docker operation')
                return subprocess.CompletedProcess(args,0,json.dumps(d),'')
            def read(p,*args,**kwargs):
                if p.as_posix()=='/etc/os-release':return 'ID=ubuntu\nVERSION_ID="24.04"\n'
                if p.as_posix()=='/proc/meminfo':return 'MemAvailable: 4194304 kB\n'
                return original(p,*args,**kwargs)
            old_file=Path.is_file;old_bytes=Path.read_bytes;old_open=Path.open
            def open_file(path,*args,**kwargs):return old_open(compose,*args,**kwargs) if path.as_posix()=='/private/compose.yaml' else old_open(path,*args,**kwargs)
            def is_file(path):return True if path.as_posix()=='/private/compose.yaml' else old_file(path)
            def read_bytes(path):return compose.read_bytes() if path.as_posix()=='/private/compose.yaml' else old_bytes(path)
            capture=io.StringIO()
            with patch('stat.S_IMODE',return_value=0o644),patch.object(sys,'argv',['preflight',str(archive),expected,str(private),private_sha,str(staged)]),patch.object(sys,'platform','linux'),patch.object(os,'getuid',return_value=1000,create=True),patch.object(platform,'machine',return_value='x86_64'),patch.object(platform,'node',return_value='fixture-host'),patch.object(Path,'read_text',read),patch.object(Path,'open',open_file),patch.object(Path,'is_file',is_file),patch.object(Path,'read_bytes',read_bytes),patch.object(Path,'home',return_value=folder/'unused-home'),patch.object(shutil,'which',side_effect=lambda t:None if t in ('node','npm') else '/fixture/tool'),patch.object(shutil,'disk_usage',return_value=shutil._ntuple_diskusage(100000000000,1000000000,99000000000)),patch.object(subprocess,'run',side_effect=run),contextlib.redirect_stdout(capture):
                try:exec(compile(code,'mock-preflight','exec'),{})
                except SystemExit as error:status=error.code
            self.assertNotIn('PRIVATE-CREDENTIAL-FIXTURE',capture.getvalue())
            return status,calls,capture.getvalue()
    def test_host_without_node_npm_and_buildx_without_format_passes(self):
        status,calls,text=self.execute();self.assertEqual(status,0,text)
        self.assertFalse(any(c[0] in ('node','npm') for c in calls))
        self.assertFalse(any('buildx' in c and '--format' in c for c in calls))
        self.assertFalse(any('--bootstrap' in c for c in calls))
    def test_changed_staged_source_blocks_before_docker(self):
        status,calls,_=self.execute('changed-staged');self.assertEqual(status,2);self.assertEqual(calls,[])
    def test_extra_staged_source_blocks_before_docker(self):
        status,calls,_=self.execute('extra-staged');self.assertEqual(status,2);self.assertEqual(calls,[])
    def test_remote_default_context_blocks(self):self.assertEqual(self.execute('remote-context')[0],2)
    def test_missing_amd64_blocks(self):self.assertEqual(self.execute('no-amd64')[0],2)
    def test_malformed_builder_blocks(self):self.assertEqual(self.execute('malformed-builder')[0],2)
    def test_missing_pinned_cache_blocks_without_pull_or_error_leak(self):self.assertEqual(self.execute('missing-cache')[0],2)
    def test_existing_validation_resource_blocks_without_cleanup(self):self.assertEqual(self.execute('conflict')[0],2)

    def test_unexpected_production_image_blocks(self):self.assertEqual(self.execute('wrong-production')[0],2)
    def test_candidate_image_blocks(self):self.assertEqual(self.execute('candidate-image')[0],2)
    def test_candidate_container_blocks(self):self.assertEqual(self.execute('candidate-container')[0],2)
    def test_ambiguous_project_service_blocks(self):self.assertEqual(self.execute('ambiguous-production')[0],2)

    def test_old_source_package_blocks(self):self.assertEqual(self.execute('old-source')[0],2)
    def test_old_manifest_version_blocks(self):self.assertEqual(self.execute('old-manifest')[0],2)

    def test_private_metadata_missing_identity_stops_before_docker(self):
        status,calls,_=self.execute('missing-identity');self.assertEqual(status,2);self.assertEqual(calls,[])
    def test_malformed_private_identity_stops_before_docker(self):
        status,calls,_=self.execute('bad-identity');self.assertEqual(status,2);self.assertEqual(calls,[])
    def test_private_checksum_mismatch_stops_before_docker(self):
        status,calls,_=self.execute('bad-metadata-sha');self.assertEqual(status,2);self.assertEqual(calls,[])
    def test_approved_source_commit_must_match(self):
        status,calls,_=self.execute('wrong-source-commit');self.assertEqual(status,2);self.assertEqual(calls,[])
