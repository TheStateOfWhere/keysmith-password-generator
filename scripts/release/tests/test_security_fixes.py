"""Focused local regression fixtures; all Docker commands are mocked."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from unittest.mock import patch
from test_docker_release import Fixtures, release, ROOT

BASH=shutil.which('bash') if os.name!='nt' else r'C:\Program Files\Git\bin\bash.exe'

class IdentityTests(Fixtures):
    def candidate_fixture(self):
        from test_approval_binding import approved_source,mode_observation,complete_proof
        source,approved=approved_source(self.out)
        self.enterContext(mode_observation(approved,source));self.enterContext(patch.object(release,'SOURCE',source))
        self.enterContext(patch.object(release,'APPROVAL',approved))
        d,record=complete_proof(self.out,approved);self.target=d['Id']
        self.scan['Metadata']['ImageID']=record['configId'];self.put('vulnerabilities.json',self.scan)
        return d,record
    def test_candidate_rejects_stale_malformed_and_missing_image_id(self):
        d,record=self.candidate_fixture()
        with patch.object(release,'image',return_value=d),patch.object(release,'source_hash',return_value='fixture'):
            release.candidate(record['image'],self.out)
            for value in ('sha256:'+'b'*64,'garbage',''):
                (self.out/'image.id').write_text(value)
                with self.assertRaises(Exception):release.candidate(record['image'],self.out)
            (self.out/'image.id').unlink()
            with self.assertRaises(Exception):release.candidate(record['image'],self.out)
    def scan_fixture(self):
        d,record=self.candidate_fixture()
        gate={**release.build_proof.continuity(record),'imageId':self.target,'configId':record['configId'],'resultSHA256':release.sha(self.out/'vulnerabilities.json'),
              'metadataSHA256':release.sha(self.out/'database-metadata.json'),'counts':release.scan_gate(self.out,record['configId'])[0],'findings':[]}
        self.put('scan.json',gate);self.put('scan-started.json',{'imageId':self.target,**release.build_proof.continuity(record)})
        return d,record,gate
    def test_mixed_scan_config_cannot_authorize_runtime(self):
        d,record,gate=self.scan_fixture();other='sha256:'+'b'*64
        self.scan['Metadata']['ImageID']=other;self.put('vulnerabilities.json',self.scan)
        gate.update(configId=other,resultSHA256=release.sha(self.out/'vulnerabilities.json'));self.put('scan.json',gate)
        with patch.object(release,'image',return_value=d),patch.object(release,'source_hash',return_value='fixture'),patch.object(release,'command') as command:
            with self.assertRaises(Exception):release.runtime(record['image'],self.out)
            command.assert_not_called();self.assertFalse((self.out/'runtime-started.json').exists())
    def test_altered_build_config_rejects_original_scan(self):
        d,record,_=self.scan_fixture();record['configId']='sha256:'+'b'*64;self.put('build.json',record)
        with patch.object(release,'image',return_value=d),patch.object(release,'source_hash',return_value='fixture'):
            with self.assertRaises(Exception):release.passed_scan(record['image'],self.out)
    def test_check_returns_only_authoritative_identity(self):
        d,record,_=self.scan_fixture();(self.out/'runtime').mkdir()
        self.put('runtime/runtime-validation.json',{'imageId':self.target,'status':'passed','version':'0.4.0'})
        self.put('runtime-started.json',{'imageId':self.target,**release.build_proof.continuity(record)})
        self.put('runtime.json',{**release.build_proof.continuity(record),'imageId':self.target,'resultSHA256':release.sha(self.out/'runtime/runtime-validation.json')})
        with patch.object(release,'image',return_value=d),patch.object(release,'source_hash',return_value='fixture'):
            self.assertEqual(release.check(record['image'],self.out),self.target)
            (self.out/'image.id').write_text('sha256:'+'b'*64)
            with self.assertRaises(Exception):release.check(record['image'],self.out)

class DeploymentTests(Fixtures):
    def execute(self,failure=None,existing_override=False,conditional=False):
        text=(ROOT/'OPERATOR-RUNBOOK.md').read_text()
        block=text.split('## 5. Deploy',1)[1].split('```bash\n',1)[1].split('```',1)[0]
        self.assertTrue(block.startswith('(\nset -Eeuo pipefail'))
        if existing_override:(self.out/'deploy-image.yaml').write_text('original')
        (self.out/'production.yaml').write_text('public fixture')
        env=dict(os.environ,PRIVATE_METADATA='unused-private.json',PRIVATE_METADATA_SHA256='a'*64,EVIDENCE=self.out.as_posix(),SOURCE='/unused-source',IMAGE='passwordforge:0.4.0',FAIL=failure or '')
        mocks="""python3() { case ${@: -1} in productionComposePath) printf '%s\n' "$EVIDENCE/production.yaml"; return;; productionComposeSHA256) sha256sum "$EVIDENCE/production.yaml" | cut -d ' ' -f1; return;; composeProject) printf 'passwordforge\n'; return;; esac; if [[ $FAIL == check ]]; then return 2; fi; if [[ $FAIL == malformed ]]; then printf 'garbage\n'; else printf 'sha256:%064d\n' 0; fi; }
docker() { printf '%s\n' "$*" >> "$EVIDENCE/calls"; if [[ $FAIL == config && $* == *'config --quiet'* ]]; then return 2; fi; }
"""
        if conditional:block='if '+block+'; then :; fi\n'
        result=subprocess.run([BASH,'--noprofile','--norc','-s'],input=mocks+block,text=True,capture_output=True,env=env)
        calls=(self.out/'calls').read_text() if (self.out/'calls').exists() else ''
        return result,calls
    def test_failed_validation_stops_pasted_block(self):
        result,calls=self.execute('check');self.assertNotEqual(result.returncode,0);self.assertEqual(calls,'')
    def test_malformed_validation_identity_stops_pasted_block(self):
        result,calls=self.execute('malformed');self.assertNotEqual(result.returncode,0);self.assertEqual(calls,'')
    def test_override_failure_stops_pasted_block(self):
        result,calls=self.execute(existing_override=True);self.assertNotEqual(result.returncode,0);self.assertEqual(calls,'')
        self.assertEqual((self.out/'deploy-image.yaml').read_text(),'original')
    def test_compose_validation_failure_prevents_up(self):
        result,calls=self.execute('config');self.assertNotEqual(result.returncode,0);self.assertNotIn('up -d',calls)
    def test_fail_closed_even_when_outer_conditional_disables_errexit(self):
        for failure in ('check','config'):
            if (self.out/'calls').exists():(self.out/'calls').unlink()
            if (self.out/'deploy-image.yaml').exists():(self.out/'deploy-image.yaml').unlink()
            _,calls=self.execute(failure,conditional=True);self.assertNotIn('up -d',calls)
    def test_success_uses_validated_id_and_explicit_no_pull_build(self):
        result,calls=self.execute();self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('up -d --no-build --pull never passwordforge',calls)
        self.assertIn('sha256:'+'0'*64,(self.out/'deploy-image.yaml').read_text())

class ArchiveTests(Fixtures):
    def archive(self,layer=b'public layer bytes',compressed=False,omit=False,reference='layer.tar',symlink=False):
        packed=gzip.compress(layer) if compressed else layer
        diff='sha256:'+hashlib.sha256(b'public layer bytes').hexdigest()
        raw=json.dumps({'os':'linux','architecture':'amd64','rootfs':{'diff_ids':[diff]}}).encode()
        path=self.out/'archive.tar'
        with tarfile.open(path,'w') as tar:
            for name,data in [('manifest.json',json.dumps([{'Config':'config.json','Layers':[reference]}]).encode()),('config.json',raw)]:
                m=tarfile.TarInfo(name);m.size=len(data);tar.addfile(m,io.BytesIO(data))
            if not omit:
                m=tarfile.TarInfo(reference)
                if symlink:m.type=tarfile.SYMTYPE;m.linkname='config.json';tar.addfile(m)
                else:m.size=len(packed);tar.addfile(m,io.BytesIO(packed))
        return path,{'RootFS':{'Layers':[diff]}}
    def test_raw_and_gzip_layer_bytes_verified(self):
        for compressed in (False,True):
            path,d=self.archive(compressed=compressed);self.assertTrue(release.archive_config(path,d).startswith('sha256:'))
    def test_missing_changed_or_nonregular_layers_rejected(self):
        for args in ({'omit':True},{'layer':b'altered'},{'symlink':True},{'reference':'../escape'}):
            path,d=self.archive(**args)
            with self.assertRaises(Exception):release.archive_config(path,d)
    def test_content_addressed_layer_digest_verified(self):
        layer=b'public layer bytes';path,d=self.archive(reference='blobs/sha256/'+hashlib.sha256(layer).hexdigest())
        release.archive_config(path,d)
        path,d=self.archive(reference='blobs/sha256/'+'b'*64)
        with self.assertRaises(Exception):release.archive_config(path,d)
    def test_unsupported_compression_fails_closed(self):
        path,d=self.archive(layer=b'\x28\xb5\x2f\xfdrest')
        with self.assertRaises(Exception):release.archive_config(path,d)

class CleanupTests(Fixtures):
    def test_name_or_wrong_immutable_id_never_deleted(self):
        with patch.object(release,'command') as command:
            with self.assertRaises(Exception):release.owned_remove('reused-name','run')
            command.assert_not_called()
        cid='c'*64
        with patch.object(release,'command',side_effect=[cid,json.dumps({'Id':'d'*64,'Labels':{release.LABEL:'run'}})]) as command:
            with self.assertRaises(Exception):release.owned_remove(cid,'run')
            self.assertEqual(command.call_count,2)
    def test_all_cleanup_attempts_and_partial_output_preserved(self):
        work=self.out/'scanner';(work/'output').mkdir(parents=True)
        (work/'output/native.json').write_text('{partial')
        ids=['c'*64,'d'*64]
        with patch.object(release,'owned_remove',side_effect=[RuntimeError('fixture'),None]) as remove:
            with self.assertRaises(Exception):release.scanner_cleanup(work,self.out,ids,'run')
            self.assertEqual([c.args[0] for c in remove.call_args_list],ids)
        self.assertEqual((self.out/'native.json').read_text(),'{partial')
        self.assertTrue(work.exists());self.assertEqual(json.loads((self.out/'scanner-cleanup.json').read_text())['status'],'failed')

class RuntimeBoundaryTests(Fixtures):
    def setup_boundary(self):
        source=self.out/'source';out=source/'validation-results'/'fixture';out.mkdir(parents=True)
        (out/'runtime').mkdir();token='e'*64
        self.home=self.out/'home';lock=self.home/'.cache/passwordforge-docker.lock';lock.mkdir(parents=True)
        (lock/'owner.json').write_text(json.dumps({'pid':os.getpid()}))
        from test_publication import approved
        from runtime_inputs import prepare_inputs
        d={'Config':{'Labels':{'org.opencontainers.image.version':'0.6.0'}}}
        inputs=prepare_inputs('passwordforge:0.6.0',{'version':'0.6.0'},d,approved())
        (out/'runtime-inputs.json').write_text(json.dumps(inputs))
        (out/'runtime-boundary.json').write_text(json.dumps({'parentPID':os.getpid(),'tokenSHA256':hashlib.sha256(token.encode()).hexdigest(),'inputsSHA256':release.sha(out/'runtime-inputs.json')}))
        (out/'runtime-started.json').write_text(json.dumps({'imageId':self.target}))
        (out/'build.json').write_text(json.dumps({'image':'passwordforge:0.4.0'}))
        from test_approval_binding import approved_source
        _,approved=approved_source(self.out/'approved')
        self.bound=approved
        record={'image':'passwordforge:0.4.0','run':'20261010t190558z-ef9ece7212345678','approval':dict(approved.identity)}
        (out/'build.json').write_text(json.dumps(record))
        (out/'runtime-started.json').write_text(json.dumps({'imageId':self.target,**release.build_proof.continuity(record)}))
        boundary=json.loads((out/'runtime-boundary.json').read_text());boundary.update(approvalArchive=str(approved.archive),approvalPrivate=str(approved.private),approvalChecksum=approved.checksum)
        (out/'runtime-boundary.json').write_text(json.dumps(boundary))
        return source,out,token
    def test_missing_or_wrong_capability_cannot_write_evidence(self):
        source,out,token=self.setup_boundary()
        with patch.object(release,'protected'),patch.object(release,'APPROVAL',None),patch.object(release,'SOURCE',source),patch.object(release.Path,'home',return_value=self.home),patch.object(release.os,'kill'),patch.object(release,'passed_scan') as gate:
            for bad in ('','f'*64):
                with self.assertRaises(Exception):release.runtime_guard(self.target,out,bad)
            gate.assert_not_called();self.assertFalse((out/'runtime-consumed.json').exists())
    def test_capability_one_use_and_existing_evidence_protected(self):
        source,out,token=self.setup_boundary()
        with patch.object(release,'protected'),patch.object(release,'APPROVAL',None),patch.object(release,'SOURCE',source),patch.object(release.Path,'home',return_value=self.home),patch.object(release.os,'kill'),patch.object(release,'passed_scan',return_value=({'Id':self.target},json.loads((out/'build.json').read_text()))):
            release.runtime_guard(self.target,out,token)
            with self.assertRaises(Exception):release.runtime_guard(self.target,out,token)
            (out/'runtime-consumed.json').unlink();(out/'runtime/runtime-validation.json').write_text('original')
            with self.assertRaises(Exception):release.runtime_guard(self.target,out,token)
            self.assertEqual((out/'runtime/runtime-validation.json').read_text(),'original')
    def test_missing_lock_or_expired_boundary_rejects_runtime(self):
        source,out,token=self.setup_boundary()
        with patch.object(release,'protected'),patch.object(release,'APPROVAL',None),patch.object(release,'SOURCE',source),patch.object(release.Path,'home',return_value=self.home),patch.object(release.os,'kill'):
            (self.home/'.cache/passwordforge-docker.lock/owner.json').unlink()
            with self.assertRaises(Exception):release.runtime_guard(self.target,out,token)
            (out/'runtime-boundary.json').unlink()
            with self.assertRaises(Exception):release.runtime_guard(self.target,out,token)

    def test_dead_parent_cannot_authorize_runtime(self):
        source,out,token=self.setup_boundary()
        with patch.object(release,'protected'),patch.object(release,'APPROVAL',None),patch.object(release,'SOURCE',source),patch.object(release.Path,'home',return_value=self.home),patch.object(release.os,'kill',side_effect=ProcessLookupError),patch.object(release,'passed_scan') as gate:
            with self.assertRaises(Exception):release.runtime_guard(self.target,out,token)
            gate.assert_not_called();self.assertFalse((out/'runtime-consumed.json').exists())

    def test_direct_shell_wrapper_cannot_overwrite_existing_evidence(self):
        source=self.out/'source';root=source/'scripts/release';root.mkdir(parents=True)
        shutil.copyfile(ROOT/'runtime.sh',root/'runtime.sh')
        run='20261010t190558z-ef9ece7212345678';out=source/'validation-results'/run/'runtime';out.mkdir(parents=True)
        sentinel=out/'runtime-validation.json';sentinel.write_text('original')
        result=subprocess.run([BASH,'--noprofile','--norc',str(root/'runtime.sh'),out.as_posix(),run,self.target],input='',text=True,capture_output=True)
        self.assertNotEqual(result.returncode,0);self.assertEqual(sentinel.read_text(),'original')
        self.assertEqual(sorted(p.name for p in out.iterdir()),['runtime-validation.json'])
