"""Independent approval/evidence regressions. Docker is always mocked."""
import json
import copy
import hashlib
import io
import tarfile
import sys
from pathlib import Path
from test_docker_release import Fixtures, release
import source_approval
import build_proof
from identity_fixture import fixture
from test_publication import approved
from unittest.mock import patch
from test_docker_release import Fixtures, release


class OriginalBypassTests(Fixtures):
    def test_other_tooling_copy_cannot_drive_approved_source(self):
        with patch.object(sys,'argv',['docker-release.py','--source',str(self.out),'build','0.4.0']),patch.object(release,'SOURCE',release.SOURCE),patch.object(release,'command') as command:
            self.assertEqual(release.main(),2)
            command.assert_not_called()
    def test_unapproved_working_source_never_reaches_builder(self):
        (self.out/'package.json').write_text('{"version":"0.4.0"}')
        (self.out/'Dockerfile').write_text('FROM fixture@sha256:'+'a'*64+'\nFROM fixture@sha256:'+'b'*64+'\n')
        (self.out/'changed-source.txt').write_text('Not in the approved archive')
        calls=[]
        def command(args,*_,**kwargs):
            calls.append(args)
            if 'build' in args: raise RuntimeError('unauthorized builder reached')
            return ''
        with patch.object(release,'SOURCE',self.out),patch.object(release,'builder'),patch.object(release,'cached_image'),patch.object(release,'source_hash',return_value='a'*64),patch.object(release,'command',side_effect=command):
            with self.assertRaises(Exception): release.build('0.4.0')
        self.assertFalse(any('build' in c for c in calls),'Unapproved source reached Docker build')

    def test_incomplete_build_proof_never_authorizes_candidate(self):
        run='20261010t190558z-ef9ece7212345678'
        record={'image':'passwordforge:0.4.0','imageId':self.target,'configId':self.target,
                'manifestId':self.target,'run':run,'sourceSHA256':'fixture'}
        self.put('build.json',record);(self.out/'image.id').write_text(self.target)
        d={'Id':self.target,'Os':'linux','Architecture':'amd64','Config':{'Labels':{release.LABEL:run}}}
        with patch.object(release,'image',return_value=d),patch.object(release,'source_hash',return_value='fixture'):
            with self.assertRaises(Exception): release.candidate(record['image'],self.out)


def approved_source(folder, version='0.4.0', source=None):
    source=source or folder/'source';source.mkdir(parents=True,exist_ok=True)
    if not (source/'package.json').exists():(source/'package.json').write_text(json.dumps({'version':version}))
    if not (source/'Dockerfile').exists():(source/'Dockerfile').write_text('FROM example@sha256:'+'a'*64+'\nFROM example@sha256:'+'b'*64+'\n')
    if not (source/'compose.yaml').exists():(source/'compose.yaml').write_text('services: {}\n')
    if not (source/'scripts/build.mjs').exists():
        (source/'scripts').mkdir(exist_ok=True);(source/'scripts/build.mjs').write_text('// public fixture')
    files={p.relative_to(source).as_posix():(p.read_bytes(),0o755 if p.name.endswith('.sh') else 0o644) for p in source.rglob('*') if p.is_file()}
    manifest=json.dumps({'version':version,'sourceCommit':'c'*40,'fileCount':len(files),'files':[
        {'path':'passwordforge/'+name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':format(mode,'04o')} for name,(raw,mode) in files.items()]}).encode()
    archive=folder/'approved-source.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:
        for name,(raw,mode) in dict({'SOURCE-MANIFEST.json':(manifest,0o644)},**{'passwordforge/'+n:v for n,v in files.items()}).items():
            m=tarfile.TarInfo(name);m.mode=mode;m.size=len(raw);tar.addfile(m,io.BytesIO(raw))
    data=approved();data.update(releaseVersion=version,sourceArchiveSHA256=hashlib.sha256(archive.read_bytes()).hexdigest(),sourceManifestSHA256=hashlib.sha256(manifest).hexdigest())
    private=folder/'private-metadata.json';private.write_text(json.dumps(data));checksum=hashlib.sha256(private.read_bytes()).hexdigest()
    return source,source_approval.Approval(archive,private,checksum)


def mode_observation(approval, source):
    return patch.object(source_approval,'permissions',side_effect=lambda p:approval.files[p.relative_to(source).as_posix()][1])


def complete_proof(out, approval, target=None, version='0.4.0'):
    run='20261010t190558z-ef9ece7212345678'
    labels={release.LABEL:run,'org.passwordforge.source':approval.fingerprint,'org.opencontainers.image.version':version}
    metadata,d,config,_=fixture(out/'build-identity.tar',labels,index=True,with_config=False,attestation=True)
    (out/'approval.json').write_text(json.dumps(dict(approval.identity)))
    (out/'example-compose.yaml').write_bytes(approval.files['compose.yaml'][0]);(out/'SOURCE-MANIFEST.json').write_bytes(approval.manifest);(out/'build-context.tar').write_bytes(approval.context)
    started={'schemaVersion':1,'image':'passwordforge:'+version,'run':run,'approval':dict(approval.identity),'sourceSHA256':approval.fingerprint}
    (out/'build-started.json').write_text(json.dumps(started))
    (out/'build.log').write_text('public successful mock build')
    (out/'build.log.status.json').write_text('{"exitCode":0,"timedOut":false}')
    (out/'build-metadata.json').write_text(json.dumps(metadata));(out/'build.iid').write_text(d['Id'])
    identities=release.verify_build_identity(out/'build-identity.tar',metadata,d,d['Id'],config)
    record=dict(started,imageId=d['Id'],metadataSHA256=release.sha(out/'build-metadata.json'),identityArchiveSHA256=release.sha(out/'build-identity.tar'),**identities,artifacts=build_proof.hashes(out))
    (out/'build.json').write_text(json.dumps(record));(out/'build-identity.json').write_text(json.dumps(record));(out/'image.id').write_text(d['Id'])
    return d,record


class SourceIntegrityTests(Fixtures):
    def setUp(self):
        super().setUp();self.source,self.approved=approved_source(self.out)
        self.enterContext(mode_observation(self.approved,self.source))
    def test_valid_source_and_frozen_context(self):
        self.approved.verify_tree(self.source)
        context=self.approved.context
        (self.source/'package.json').write_text('altered after snapshot')
        self.assertEqual(self.approved.context,context)
        with tarfile.open(fileobj=io.BytesIO(context)) as tar:
            self.assertEqual(json.loads(tar.extractfile('package.json').read())['version'],'0.4.0')
        with self.assertRaises(Exception):self.approved.refresh(self.source)
    def test_changed_source_dockerfile_and_build_script(self):
        for name in ('package.json','Dockerfile','scripts/build.mjs'):
            p=self.source/name;original=p.read_bytes();p.write_bytes(original+b'changed')
            with self.subTest(name=name),self.assertRaises(Exception):self.approved.verify_tree(self.source)
            p.write_bytes(original)
    def test_missing_added_and_unsafe_source(self):
        p=self.source/'package.json';raw=p.read_bytes();p.unlink()
        with self.assertRaises(Exception):self.approved.verify_tree(self.source)
        p.write_bytes(raw);extra=self.source/'extra.txt';extra.write_text('extra')
        with self.assertRaises(Exception):self.approved.verify_tree(self.source)
        extra.unlink()
        with patch.object(Path,'is_symlink',side_effect=lambda:True),self.assertRaises(Exception):self.approved.verify_tree(self.source)
    def test_changed_executable_mode(self):
        with patch.object(source_approval,'permissions',return_value=0o755),self.assertRaises(Exception):self.approved.verify_tree(self.source)
    def test_approval_from_another_archive_rejected(self):
        self.approved.archive.write_bytes(b'changed')
        with self.assertRaises(Exception):self.approved.refresh(self.source)
    def test_missing_or_changed_manifest_approval_rejected(self):
        data=approved();data.update(sourceArchiveSHA256=self.approved.identity['archiveSHA256'],sourceManifestSHA256='0'*64,releaseVersion='0.4.0')
        self.approved.private.write_text(json.dumps(data))
        with self.assertRaises(Exception):source_approval.Approval(self.approved.archive,self.approved.private,release.sha(self.approved.private))
    def test_source_failures_precede_all_docker_calls(self):
        (self.source/'Dockerfile').write_text('altered')
        with patch.object(release,'APPROVAL',self.approved),patch.object(release,'SOURCE',self.source),patch.object(release,'command') as command:
            with self.assertRaises(Exception):release.build('0.4.0')
            command.assert_not_called()


class MandatoryProofTests(SourceIntegrityTests):
    def setUp(self):
        super().setUp();self.proof=self.out/'proof';self.proof.mkdir();self.d,self.record=complete_proof(self.proof,self.approved)
        self.enterContext(patch.object(release,'APPROVAL',self.approved));self.enterContext(patch.object(release,'SOURCE',self.source))
        self.enterContext(patch.object(release,'image',return_value=self.d))
    def test_complete_proof_and_export_graph_pass(self):
        self.assertEqual(release.candidate(self.record['image'],self.proof)[0]['Id'],self.d['Id'])
    def test_every_mandatory_field_rejected_if_missing(self):
        for name in self.record:
            bad=dict(self.record);del bad[name];(self.proof/'build.json').write_text(json.dumps(bad))
            with self.subTest(name=name),self.assertRaises(Exception):release.candidate(self.record['image'],self.proof)
    def test_every_required_identity_artifact_rejected_if_missing(self):
        for name in (*build_proof.ARTIFACTS,'build-identity.json','image.id'):
            p=self.proof/name;raw=p.read_bytes();p.unlink()
            with self.subTest(name=name),self.assertRaises(Exception):release.candidate(self.record['image'],self.proof)
            p.write_bytes(raw)
    def test_corruption_mixed_attempt_and_schema_fail_before_mutation(self):
        for key,value in [('schemaVersion',True),('schemaVersion',2),('exportId','garbage'),('run','20261011t120000z-0123456789abcdef'),('sourceSHA256','f'*64),('approval',dict(self.approved.identity,metadataSHA256='f'*64))]:
            bad=dict(self.record,**{key:value});(self.proof/'build.json').write_text(json.dumps(bad))
            with self.subTest(key=key),patch.object(release,'command') as command,self.assertRaises(Exception):release.scan(self.record['image'],self.proof)
            command.assert_not_called()
        (self.proof/'build.json').write_text(json.dumps(self.record));(self.proof/'build-metadata.json').write_text('{}')
        with self.assertRaises(Exception):release.candidate(self.record['image'],self.proof)
    def test_receipts_reject_mixed_approval_and_build(self):
        good=build_proof.continuity(self.record);build_proof.same_attempt(good,self.record)
        for key in good:
            bad=dict(good,**{key:False})
            with self.subTest(key=key),self.assertRaises(Exception):build_proof.same_attempt(bad,self.record)


class ArchiveSafetyTests(Fixtures):
    def test_unsafe_members_duplicate_and_modes_rejected(self):
        source,bound=approved_source(self.out)
        original=bound.archive.read_bytes()
        for kind in ('traversal','symlink','duplicate','mode','absolute','hardlink','special'):
            with tarfile.open(fileobj=io.BytesIO(original),mode='r:gz') as tar:
                entries=[(copy.copy(m),tar.extractfile(m).read()) for m in tar.getmembers()]
            path='passwordforge/extra.txt'
            extra=tarfile.TarInfo(path);extra.mode=0o644;extra.size=0
            if kind=='traversal':extra.name='passwordforge/../escape'
            if kind=='absolute':extra.name='/escape'
            if kind=='symlink':extra.type=tarfile.SYMTYPE;extra.linkname='package.json'
            if kind=='hardlink':extra.type=tarfile.LNKTYPE;extra.linkname='passwordforge/package.json'
            if kind=='special':extra.type=tarfile.FIFOTYPE
            if kind=='duplicate':extra=copy.copy(entries[0][0]);extra.size=0
            if kind=='mode':extra.mode=0o777
            with tarfile.open(bound.archive,'w:gz') as tar:
                for m,raw in entries:tar.addfile(m,io.BytesIO(raw))
                tar.addfile(extra,io.BytesIO(b''))
            data=dict(bound.metadata);data['sourceArchiveSHA256']=release.sha(bound.archive)
            bound.private.write_text(json.dumps(data))
            with self.subTest(kind=kind),self.assertRaises(Exception):source_approval.Approval(bound.archive,bound.private,release.sha(bound.private))
    def test_archive_from_other_approved_attempt_cannot_replace_receipt(self):
        source,bound=approved_source(self.out)
        other=self.out/'other';other.mkdir();other_source,other_bound=approved_source(other)
        (other_source/'package.json').write_text('altered staged bytes')
        with mode_observation(bound,source):
            bound.verify_tree(source)
        proof=self.out/'proof';proof.mkdir();d,record=complete_proof(proof,bound)
        other_identity=dict(other_bound.identity);other_identity['sourceCommit']='d'*40
        record['approval']=other_identity
        with self.assertRaises(Exception):build_proof.validate(proof,record,bound)


class ProtectedIdentityTests(Fixtures):
    def setUp(self):
        super().setUp();self.source,self.bound=approved_source(self.out)
        self.enterContext(mode_observation(self.bound,self.source));self.enterContext(patch.object(release,'SOURCE',self.source))
        self.enterContext(patch.object(release,'APPROVAL',self.bound))
    def observations(self):
        m=self.bound.metadata
        return {'containerId':m['productionContainerId'],'imageId':m['productionImageId'],'startedAt':m['productionStartedAt'],
            'name':'/passwordforge','status':'running','health':'healthy','project':m['composeProject'],'service':'passwordforge'}
    def test_correct_baseline_and_candidate_owned_resources_are_allowed(self):
        m=self.bound.metadata
        with patch.object(release,'command',side_effect=[json.dumps(self.observations()),json.dumps(m['proxyNetworkId']),json.dumps({m['proxyNetwork']:{'NetworkID':m['proxyNetworkId']}})]),patch.object(release,'image',return_value={'Id':m['productionImageId']}),patch.object(release,'sha',return_value=m['productionComposeSHA256']):
            release.protected()
    def test_missing_failed_or_drifted_baseline_blocks_before_build(self):
        for raw in ('','{}','{',json.dumps(dict(self.observations(),containerId='f'*64)),json.dumps(dict(self.observations(),health='unhealthy'))):
            with patch.object(release,'command',return_value=raw) as command,patch.object(release,'builder'):
                with self.subTest(raw=raw),self.assertRaises(Exception):release.build('0.4.0')
                self.assertFalse(any('build' in c.args[0] for c in command.call_args_list))
        with patch.object(release,'command',side_effect=RuntimeError('mock Docker inspection failed')),self.assertRaises(Exception):release.protected()
    def test_production_tag_compose_and_network_drift_block(self):
        m=self.bound.metadata
        for kind in ('tag','compose','network','membership'):
            outputs=[json.dumps(self.observations()),json.dumps('f'*64 if kind=='network' else m['proxyNetworkId']),json.dumps({} if kind=='membership' else {m['proxyNetwork']:{'NetworkID':m['proxyNetworkId']}})]
            with patch.object(release,'command',side_effect=outputs),patch.object(release,'image',return_value={'Id':'sha256:'+'f'*64 if kind=='tag' else m['productionImageId']}),patch.object(release,'sha',return_value='f'*64 if kind=='compose' else m['productionComposeSHA256']),self.subTest(kind=kind),self.assertRaises(Exception):release.protected()
    def test_cleanup_stops_on_production_drift_without_removing_anything(self):
        cid='c'*64
        with patch.object(release,'command',side_effect=[cid,json.dumps({'Id':cid,'Labels':{release.LABEL:'owned'}})]) as command,patch.object(release,'protected',side_effect=ValueError('baseline drift')):
            with self.assertRaises(Exception):release.owned_remove(cid,'owned')
            self.assertFalse(any('rm' in c.args[0] for c in command.call_args_list))


class SnapshotRaceTests(Fixtures):
    def test_mutation_after_validation_cannot_change_submitted_context(self):
        source,bound=approved_source(self.out);calls=[]
        def command(args,log=None,*_,**kwargs):
            calls.append(args)
            if 'build' in args:
                # This mutation happens at the exact check/build boundary.
                (source/'Dockerfile').write_text('malicious live replacement')
                self.assertEqual(kwargs['input_bytes'],bound.context)
                self.assertEqual(args[-1],'-')
                with tarfile.open(fileobj=io.BytesIO(kwargs['input_bytes'])) as tar:
                    self.assertEqual(tar.extractfile('Dockerfile').read(),bound.files['Dockerfile'][0])
            return ''
        with mode_observation(bound,source),patch.object(release,'APPROVAL',bound),patch.object(release,'SOURCE',source),patch.object(release,'builder'),patch.object(release,'protected',side_effect=lambda:release.approval()),patch.object(release,'cached_image'),patch.object(release,'command',side_effect=command):
            with self.assertRaises(Exception):release.build('0.4.0')
        self.assertTrue(any('build' in c for c in calls))
        self.assertFalse(any((source/'validation-results').glob('*/build.json')))
