"""Buildx 0.37 Docker-driver compatibility and fail-closed recovery; mocked Docker."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from build_identity import verify, digest
from security import SecurityError
from identity_fixture import fixture,write
spec=importlib.util.spec_from_file_location('metadata_release',ROOT/'docker-release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)

class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'image.tar'
        self.metadata,self.d,self.config,self.blobs=fixture(self.path,with_config=False,attestation=True)
    def tearDown(self):self.tmp.cleanup()
    def check(self,metadata=None,d=None,iid=None):
        inspected=d or self.d
        config=release.archive_config(self.path,inspected)
        return verify(self.path,self.metadata if metadata is None else metadata,inspected,iid or inspected['Id'],config)
    def test_missing_config_digest_oci_index(self):
        result=self.check();self.assertEqual(result['imageIdKind'],'index');self.assertEqual(result['configId'],self.config)
        self.assertNotEqual(result['configId'],result['manifestId']);self.assertNotEqual(result['manifestId'],result['exportId'])
    def test_explicit_config_digest_oci_index(self):
        self.assertEqual(self.check(dict(self.metadata,**{'containerimage.config.digest':self.config}))['configId'],self.config)
    def test_image_manifest_and_classic_config_id(self):
        self.metadata,self.d,self.config,self.blobs=fixture(self.path,index=False)
        result=self.check();self.assertEqual(result['imageIdKind'],'config');self.assertEqual(result['exportId'],result['manifestId'])
    def test_config_id_and_iid_are_authenticated_separately(self):
        d=dict(self.d,Id=self.config);result=self.check(d=d,iid=self.metadata['containerimage.digest'])
        self.assertEqual(result['imageIdKind'],'config');self.assertEqual(result['iidKind'],'index')
    def test_wrong_optional_config_digest_rejected(self):
        with self.assertRaises(SecurityError):self.check(dict(self.metadata,**{'containerimage.config.digest':'sha256:'+'f'*64}))
    def test_malformed_optional_config_types_rejected(self):
        for value in (None,False,0,[],{}):
            with self.subTest(value=value),self.assertRaises(SecurityError):self.check(dict(self.metadata,**{'containerimage.config.digest':value}))
    def test_unrelated_daemon_identity_rejected(self):
        with self.assertRaises(SecurityError):self.check(d=dict(self.d,Id='sha256:'+'f'*64))
    def test_unrelated_iid_rejected(self):
        with self.assertRaises(SecurityError):self.check(iid='sha256:'+'f'*64)
    def test_config_digest_cannot_masquerade_as_export_digest(self):
        with self.assertRaises(SecurityError):self.check(dict(self.metadata,**{'containerimage.digest':self.config}))
    def test_malformed_export_digest_rejected(self):
        for value in (False,None,'sha256:short',self.config.upper()):
            with self.subTest(value=value),self.assertRaises(SecurityError):self.check(dict(self.metadata,**{'containerimage.digest':value}))
    def test_descriptor_digest_type_and_size_mismatch_rejected(self):
        for key,value in [('digest',self.config),('mediaType','config'),('size',True),('size',0)]:
            bad=copy.deepcopy(self.metadata);bad['containerimage.descriptor'][key]=value
            with self.subTest(key=key),self.assertRaises(SecurityError):self.check(bad)
    def test_missing_or_modified_export_blob_rejected(self):
        key='blobs/sha256/'+self.metadata['containerimage.digest'][7:]
        for value in (None,b'{}',b'{'):
            blobs=dict(self.blobs)
            if value is None:del blobs[key]
            else:blobs[key]=value
            write(self.path,blobs)
            with self.subTest(value=value),self.assertRaises(SecurityError):self.check()
    def test_platform_malformed_or_multiple_runtimes_rejected(self):
        for platform in ({'os':'linux'},{'os':False,'architecture':'amd64'},{'os':'linux','architecture':'arm64'},{'os':'linux','architecture':'amd64','variant':'v8'}):
            self.metadata,self.d,self.config,self.blobs=fixture(self.path,platform=platform)
            with self.subTest(platform=platform),self.assertRaises(SecurityError):self.check()
    def rewrite_index(self,change):
        old=self.metadata['containerimage.digest'];root=json.loads(self.blobs['blobs/sha256/'+old[7:]])
        change(root);raw=json.dumps(root,separators=(',',':')).encode();identity=digest(raw)
        self.blobs['blobs/sha256/'+identity[7:]]=raw;write(self.path,self.blobs)
        self.metadata['containerimage.digest']=identity
        self.metadata['containerimage.descriptor']=dict(self.metadata['containerimage.descriptor'],digest=identity,size=len(raw))
        self.d['Id']=identity
    def test_multiple_runtime_manifests_rejected(self):
        self.rewrite_index(lambda root:root['manifests'].append(copy.deepcopy(root['manifests'][0])))
        with self.assertRaises(SecurityError):self.check()
    def test_attestation_wrong_runtime_subject_rejected(self):
        self.rewrite_index(lambda root:root['manifests'][1]['annotations'].update({'vnd.docker.reference.digest':'sha256:'+'f'*64}))
        with self.assertRaises(SecurityError):self.check()
    def test_unrecognized_attestation_platform_rejected(self):
        self.rewrite_index(lambda root:root['manifests'][1]['annotations'].clear())
        with self.assertRaises(SecurityError):self.check()
    def test_truncated_attestation_blob_rejected(self):
        index=json.loads(self.blobs['blobs/sha256/'+self.metadata['containerimage.digest'][7:]])
        key='blobs/sha256/'+index['manifests'][1]['digest'][7:];self.blobs[key]=b'{}';write(self.path,self.blobs)
        with self.assertRaises(SecurityError):self.check()
    def test_failure_keeps_owned_export_and_never_publishes_build(self):
        out=self.root/'attempt';out.mkdir();run='20261011t120000z-0123456789abcdef';fingerprint='a'*64
        labels={release.LABEL:run,'org.passwordforge.source':fingerprint,'org.opencontainers.image.version':'0.4.0'}
        metadata,d,_,_=fixture(self.path,labels,with_config=False)
        metadata['containerimage.digest']='sha256:'+'f'*64
        (out/'build-metadata.json').write_text(json.dumps(metadata));(out/'build.iid').write_text(d['Id'])
        def command(args,*_):Path(args[args.index('--output')+1]).write_bytes(self.path.read_bytes());return ''
        with patch.object(release,'approval') as approved,patch.object(release,'command',side_effect=command),self.assertRaises(SecurityError):
            approved.return_value.fingerprint=fingerprint
            release.validate_build('passwordforge:0.4.0',out,d,fingerprint,run)
        self.assertTrue((out/'build-identity.tar').exists());self.assertFalse((out/'build.json').exists());self.assertFalse((out/'image.id').exists())
    def test_labels_and_layer_identity_must_match_daemon(self):
        d=copy.deepcopy(self.d);d['Config']['Labels']={'changed':'yes'}
        with self.assertRaises(SecurityError):self.check(d=d)
        d=copy.deepcopy(self.d);d['RootFS']['Layers']=[]
        with self.assertRaises(SecurityError):self.check(d=d)
    def test_provenance_malformed_type_rejected(self):
        for value in (False,[],None,'false'):
            with self.subTest(value=value),self.assertRaises(SecurityError):self.check(dict(self.metadata,**{'buildx.build.provenance':value}))
    def test_runtime_external_tools_propagate_original_source(self):
        record={'run':'20261011t120000z-0123456789abcdef'};out=self.root/'operation';out.mkdir()
        from test_docker_release import runtime_approval
        from test_approval_binding import approved_source,mode_observation
        source,bound=approved_source(self.root);approval=(bound.private,bound.checksum)
        record.update(approval=dict(bound.identity))
        d={'Id':'sha256:'+'a'*64,'Config':{'Labels':{'org.opencontainers.image.version':'0.4.0'}}};calls=[]
        def command(args,*_,**kwargs):
            calls.append(args)
            (out/'runtime/runtime-validation.json').write_text(json.dumps({'imageId':d['Id'],'status':'passed','version':'0.4.0'}))
            return ''
        with mode_observation(bound,source),patch.object(release,'APPROVAL',bound),patch.object(release,'protected'),patch.object(release,'SOURCE',source),patch.object(release,'passed_scan',return_value=(d,record)),patch.object(release,'command',side_effect=command):
            release.runtime('passwordforge:0.4.0',out,*approval)
        self.assertEqual(calls[0][-1],str(source))
        self.assertTrue((out/'runtime.json').exists())
    def test_edited_identity_report_or_metadata_blocks_candidate(self):
        run='20261011t120000z-0123456789abcdef';fingerprint='a'*64
        labels={release.LABEL:run};d=dict(self.d,Config={'Labels':labels})
        record={'image':'passwordforge:0.4.0','imageId':d['Id'],'configId':self.config,'manifestId':self.config,
                'run':run,'sourceSHA256':fingerprint,'exportId':d['Id'],'metadataSHA256':'0'*64}
        (self.root/'build.json').write_text(json.dumps(record));(self.root/'image.id').write_text(d['Id'])
        (self.root/'build-identity.json').write_text(json.dumps(record));(self.root/'build-metadata.json').write_text('{}')
        with patch.object(release,'source_hash',return_value=fingerprint),patch.object(release,'image',return_value=d),self.assertRaises(SecurityError):
            release.candidate(record['image'],self.root)
    def test_recovery_preserves_original_and_never_builds(self):
        self.recover()
    def test_recovery_wrong_image_stops_without_saving(self):
        self.recover(wrong=True)
    def test_recovery_failed_build_status_stops(self):
        self.recover(failed=True)
    def test_recovery_source_and_ownership_mismatch_stops(self):
        self.recover(changed=True)
    def recover(self,wrong=False,failed=False,changed=False):
        source=self.root/'source';source.mkdir();(source/'package.json').write_text('{"version":"0.4.0"}')
        run='20261011t120000z-0123456789abcdef';old=source/'validation-results'/run;old.mkdir(parents=True)
        fingerprint='a'*64
        labels={release.LABEL:run,'org.passwordforge.source':fingerprint,'org.opencontainers.image.version':'0.4.0'}
        metadata,d,_,_=fixture(self.path,labels,with_config=False,attestation=True)
        for name,value in [('build-started.json',{'image':'passwordforge:0.4.0','run':run}),('build-metadata.json',metadata),('build.log.status.json',{'exitCode':1 if failed else 0,'timedOut':False})]:
            (old/name).write_text(json.dumps(value))
        (old/'build.iid').write_text(d['Id']);(old/'build.log').write_text('public successful build fixture')
        original={p.name:p.read_bytes() for p in old.iterdir()};calls=[]
        def command(args,*_):
            calls.append(args)
            if 'save' in args:Path(args[args.index('--output')+1]).write_bytes(self.path.read_bytes())
            return ''
        with patch.object(release,'SOURCE',source),patch.object(release,'builder'),patch.object(release,'source_hash',return_value='b'*64 if changed else fingerprint),patch.object(release,'image',return_value=d),patch.object(release,'command',side_effect=command):
            with self.assertRaises(SecurityError) as error:release.verify_existing('0.4.0',old,'sha256:'+'f'*64 if wrong else d['Id'])
            self.assertEqual(error.exception.code,'REBUILD_REQUIRED')
            self.assertEqual(calls,[])
        self.assertEqual(original,{p.name:p.read_bytes() for p in old.iterdir()})
        self.assertFalse(any(x in c for c in calls for x in ('build','pull','load','tag','rm','up')))

if __name__=='__main__':unittest.main()
