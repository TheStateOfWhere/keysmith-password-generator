"""Public temporary fixtures, mocked transport only. Never authorizes a Docker host."""
import contextlib
import datetime as dt
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import tarfile
import subprocess
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
spec=importlib.util.spec_from_file_location('compose_release',Path(__file__).resolve().parents[1]/'compose-release.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
from security import SecurityError
from identity_fixture import fixture as image_fixture


class ComposeRelease(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        real_command=c.command
        def offline_command(args,**kw):
            if args and Path(args[0]).name.lower() in ('docker','docker.exe','ssh','ssh.exe'):
                raise AssertionError('Unmocked external transport is forbidden in local tests')
            return real_command(args,**kw)
        safety=patch.object(c,'command',side_effect=offline_command);safety.start();self.addCleanup(safety.stop)
        self.compose=self.root/'compose.yaml';self.compose.write_text('public fixture only')
        self.evidence=self.root/'evidence';self.evidence.mkdir(mode=0o700)
        self.target={'hostMachineId':'a'*32,'dockerDaemonId':'fixture-daemon','endpoint':c.ENDPOINT,
                     'project':'passwordforge','service':'passwordforge','composeFile':str(self.compose),
                     'composeSHA256':c.sha(self.compose.read_bytes()),'proxyNetwork':'proxy','proxyNetworkId':'b'*64,
                     'httpsURL':'https://password.example.invalid','evidenceRoot':str(self.evidence)}
        self.path=self.root/'target.json';self.path.write_text(json.dumps(self.target));self.path.chmod(0o600)
        self.rec={'run':'c'*32,'candidate':'passwordforge:0.6.0-candidate-test','version':'0.6.0',
                  'imageId':'sha256:'+'d'*64,'configId':'sha256:'+'e'*64,'contextSHA256':'f'*64,'stages':{}}

    def rejects(self,code,fn):
        with self.assertRaises(SecurityError) as caught:fn()
        self.assertEqual(caught.exception.code,code)

    def offline_cli(self,args,code):
        before={str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(c,'docker',side_effect=AssertionError('Docker prohibited')) as transport, \
             patch.object(c,'live',side_effect=AssertionError('Live prohibited')) as live, \
             patch.object(c,'locked',side_effect=AssertionError('Lock prohibited')) as lock, \
             contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(c.main(args),2);self.assertIn('STOP ['+code+'];',err.getvalue())
            transport.assert_not_called();live.assert_not_called();lock.assert_not_called()
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def args(self,stage='build'):
        return [stage,'--target',str(self.path),'--evidence',str(self.evidence/'new')]

    def test_invalid_target_before_contact(self):
        for key,value in [('endpoint','ssh://production'),('service','other'),('hostMachineId','invalid'),('httpsURL','https://secret@host')]:
            with self.subTest(key=key):
                data=dict(self.target);data[key]=value;self.path.write_text(json.dumps(data))
                self.offline_cli(self.args('preflight'),'TARGET_URL' if key=='httpsURL' else 'TARGET')

    def test_compose_drift_before_contact(self):
        self.compose.write_text('changed');self.offline_cli(self.args('preflight'),'COMPOSE_DRIFT')

    def test_bad_version_before_contact(self):
        self.offline_cli(self.args('preflight')+['--version','INVALID','--commit','a'*40],'SOURCE_INPUT')

    def test_traversal_before_contact(self):
        args=self.args('preflight');args[-1]=str(self.evidence/'..'/'escape')
        self.offline_cli(args,'PATH')

    def test_no_evidence_no_deployment(self):
        self.offline_cli(self.args('deploy'),'IO_OR_SCHEMA')

    def test_frozen_tar_matches_committed_bytes(self):
        # A public fake checkout; no Git mutation or Docker transport.
        files={'package.json':b'{"version":"0.6.0"}', 'Dockerfile':b'FROM node:24@sha256:'+b'a'*64+b'\nFROM nginx:1@sha256:'+b'b'*64+b'\nLABEL org.opencontainers.image.version="0.6.0"\n', 'public.txt':b'public original'}
        inventory={'version':'0.6.0','fileCount':4,'files':[{'path':n,'mode':'0644'} for n in [*files,'RELEASE-INVENTORY.json']]}
        files['RELEASE-INVENTORY.json']=json.dumps(inventory).encode()
        root=self.root/'source';root.mkdir()
        for name,raw in files.items():(root/name).write_bytes(raw)
        def git(*args):
            if args[0]=='rev-parse':return 'a'*40
            if args[0]=='status':return ''
            if args[0]=='ls-files':return '\0'.join(files)+'\0'
            if args[0]=='ls-tree':return '100644 blob public'
            raise AssertionError(args)
        with patch.object(c,'ROOT',root),patch.object(c,'git',side_effect=git),patch.object(c.subprocess,'check_output',side_effect=lambda args:files[args[-1].split(':',1)[1]]):
            frozen,_=c.source('a'*40,'0.6.0')
            (root/'public.txt').write_bytes(b'public mutation')
            self.rejects('SOURCE_CHANGED',lambda:c.source('a'*40,'0.6.0'))
        with c.tarfile.open(fileobj=io.BytesIO(frozen)) as tar:
            self.assertEqual(tar.extractfile('public.txt').read(),b'public original')

    def test_dirty_source(self):
        with patch.object(c,'git',side_effect=['a'*40,' M file']):
            self.rejects('SOURCE_DIRTY',lambda:c.source('a'*40,'0.6.0'))

    def result(self,severity=None):
        row={'Class':'os-pkgs','Target':'fixture','Packages':[{'Name':'fixture'}],'Vulnerabilities':[]}
        if severity:row['Vulnerabilities']=[{'Severity':severity,'PkgName':'fixture','VulnerabilityID':'PUBLIC-CVE','InstalledVersion':'1'}]
        return {'SchemaVersion':2,'ArtifactType':'container_image','Metadata':{'ImageID':self.rec['configId']},'Results':[row]}

    def test_vulnerability_gates(self):
        for severity in ('HIGH','CRITICAL','UNKNOWN'):
            with self.subTest(severity=severity):self.rejects('VULNERABILITY_GATE',lambda:c.scan_gate(self.result(severity),self.rec['configId']))
        counts,_=c.scan_gate(self.result('MEDIUM'),self.rec['configId']);self.assertEqual(counts['MEDIUM'],1)

    def test_invalid_vulnerability_types(self):
        for value in (False,'false',None,{}):
            d=self.result();d['Results'][0]['Vulnerabilities']=value
            self.rejects('SCHEMA_FIELD',lambda:c.scan_gate(d,self.rec['configId']))

    def test_scan_wrong_image(self):
        self.rejects('SCAN_IDENTITY',lambda:c.scan_gate(self.result(),'sha256:'+'1'*64))

    def test_medium_requires_disposition(self):
        self.rec['counts']={'MEDIUM':1};self.rejects('MEDIUM_REVIEW',lambda:c.medium_review(self.root,self.rec,None))

    def test_candidate_tag_drift(self):
        with patch.object(c,'image',return_value={'Id':'sha256:'+'0'*64}):
            self.rejects('IMAGE_DRIFT',lambda:c.candidate(self.rec))

    def test_candidate_labels(self):
        d={'Id':self.rec['imageId'],'Config':{'Labels':{c.OWNER:self.rec['run'],'org.passwordforge.source':self.rec['contextSHA256'],'org.opencontainers.image.version':'0.6.0'}}}
        with patch.object(c,'image',return_value=d):self.assertEqual(c.candidate(self.rec),d)
        d['Config']['Labels'][c.OWNER]='0'*32
        with patch.object(c,'image',return_value=d):self.rejects('IMAGE_BINDING',lambda:c.candidate(self.rec))

    def test_remove_requires_captured_identity_and_owner(self):
        cid='a'*64
        with patch.object(c,'docker',side_effect=[cid,json.dumps([{'Id':cid,'Config':{'Labels':{c.OWNER:'other'}}}])]) as docker:
            self.rejects('CLEANUP_OWNER',lambda:c.remove_owned(cid,self.rec['run']));self.assertEqual(docker.call_count,2)
        self.rejects('CLEANUP_ID',lambda:c.remove_owned('name',self.rec['run']))

    def test_remove_owned_uses_id(self):
        cid='a'*64
        with patch.object(c,'docker',side_effect=[cid,json.dumps([{'Id':cid,'Config':{'Labels':{c.OWNER:self.rec['run']}}}]),'']) as docker:
            c.remove_owned(cid,self.rec['run']);self.assertEqual(docker.call_args.args,('container','rm','-f',cid))

    def test_cleanup_rejects_active_and_shared_images(self):
        self.rec['stages']['deploy']={'passed':True}
        self.rejects('CLEANUP_IMAGE',lambda:c.cleanup_image(self.rec,self.rec['imageId']))
        old='sha256:'+'a'*64
        with patch.object(c,'image',return_value={'Id':old,'RepoTags':['other:latest'],'RepoDigests':[]}):
            self.rejects('CLEANUP_IMAGE',lambda:c.cleanup_image(self.rec,old))

    def test_cleanup_rejects_used_image(self):
        self.rec['stages']['deploy']={'passed':True};old='sha256:'+'a'*64
        with patch.object(c,'image',return_value={'Id':old,'RepoTags':['passwordforge:0.5.0'],'RepoDigests':[],'Config':{'Labels':{'org.opencontainers.image.title':'PasswordForge','org.opencontainers.image.version':'0.5.0'}}}),patch.object(c,'docker',return_value='container') as docker:
            self.rejects('IMAGE_USED',lambda:c.cleanup_image(self.rec,old));self.assertEqual(docker.call_count,1)

    def test_compose_command_scope(self):
        args=c.DOCKER+c.compose_args(self.target,self.root/'image.yaml')+['up','-d','--no-build','--pull','never','--no-deps','--force-recreate','passwordforge']
        self.assertEqual(args[:3],['docker','--host',c.ENDPOINT]);self.assertIn('--env-file',args)
        self.assertEqual(args[-8:],['up','-d','--no-build','--pull','never','--no-deps','--force-recreate','passwordforge'])
        self.assertIn('--no-deps',args);self.assertEqual(args[-1],'passwordforge');self.assertNotIn('down',args)

    def test_command_failure_fails_closed(self):
        with patch.object(c.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b'public failure')):
            self.rejects('COMMAND_FAILED',lambda:c.command(['mock']))

    def test_run_binding_before_contact(self):
        rec={'schemaVersion':True,'stages':{}}
        self.rejects('RUN_BINDING',lambda:c.validate_record(self.root,rec,'a'*64,'b'*64))

    def test_smoke_name_collision_before_create(self):
        with patch.object(c,'docker',return_value='pfsmoke-'+self.rec['run']) as docker:
            self.rejects('CONTAINER_COLLISION',lambda:c.smoke(self.target,self.root,self.rec,self.root))
            self.assertEqual(docker.call_count,1)

    def test_smoke_cleanup_after_runtime_failure(self):
        cid='a'*64
        with patch.object(c,'guard'),patch.object(c,'docker',side_effect=['',cid,'']),patch.object(c,'runtime_check',side_effect=SecurityError('RUNTIME','public failure')),patch.object(c,'remove_owned') as cleanup:
            self.rejects('RUNTIME',lambda:c.smoke(self.target,self.root,self.rec,self.root))
            cleanup.assert_called_once_with(cid,self.rec['run'])

    def scan_fixture(self, warning=False, cleanup_failure=False):
        out=self.root/'scan';out.mkdir();mapping={};counter=[]
        build=self.root/'build';build.mkdir()
        metadata,d,config,_=image_fixture(build/'image.tar',attestation=True)
        archive=(build/'image.tar').read_bytes();self.rec.update(imageId=d['Id'],exportReference=metadata['containerimage.digest'],configId=config)
        (build/'metadata.json').write_text(json.dumps(metadata));(build/'build.iid').write_text(metadata['containerimage.digest'])
        def docker(*args,**kw):
            if args[:2]==('image','save'):
                self.assertEqual(args[-1],self.rec['exportReference']);self.assertNotIn('--platform',args)
                Path(args[args.index('--output')+1]).write_bytes(archive);return ''
            if args[:2]==('container','ls'):return ''
            if args[0]=='create':
                step=args[args.index('--name')+1].rsplit('-',1)[1]
                cid=('%064x'%(len(mapping)+1));mapping[cid]=step;return cid
            if args[:2]==('container','inspect'):
                return json.dumps([{'HostConfig':{k:None for k in ('NetworkMode','ReadonlyRootfs','Privileged','CapDrop','SecurityOpt','Memory','PidsLimit','NanoCpus','PortBindings')},'Config':{'User':'1000:1000'},'NetworkSettings':{'Networks':{}},'Mounts':[]}])
            if args[0]=='start':
                step=mapping[args[-1]];counter.append(step)
                text='Version: 0.75.0' if step=='version' else ('WARN public scanner fixture' if warning and step=='native' else 'public successful scanner fixture')
                Path(kw['log']).write_text(text)
                if step=='db':
                    db=out/'cache/db';db.mkdir();(db/'metadata.json').write_text('{}');(db/'trivy.db').write_bytes(b'public database')
                if step=='native':(out/'output/native.json').write_text(json.dumps(self.result()))
                if step=='explicit':(out/'output/explicit.json').write_text(json.dumps(self.result()['Results']))
                return ''
            if args[0]=='inspect':return '0'
            raise AssertionError(args)
        with patch.object(c.os,'getuid',return_value=1000,create=True),patch.object(c.os,'getgid',return_value=1000,create=True),patch.object(c,'docker',side_effect=docker),patch.object(c,'candidate',return_value=d), \
             patch.object(c,'image',return_value={'Id':'sha256:'+'1'*64}),patch.object(c,'guard'),patch.object(c,'isolation'),patch.object(c,'database'), \
             patch.object(c,'remove_owned',side_effect=SecurityError('CLEANUP_OWNER','public cleanup failure') if cleanup_failure else None) as cleanup:
            if warning or cleanup_failure:
                self.rejects('CLEANUP_OWNER' if cleanup_failure else 'SCANNER_LOG',lambda:c.scan(self.target,self.root,self.rec,out))
            else:c.scan(self.target,self.root,self.rec,out)
            self.assertEqual(cleanup.call_count,len(mapping))
        self.assertTrue((out/'output/native.json').is_file())
        return out,counter

    def test_two_pass_scan_and_complete_inventory(self):
        out,steps=self.scan_fixture();self.assertEqual(steps,['version','db','native','explicit'])
        self.assertEqual(c.read(out/'vulnerabilities.json')['Results'][0]['Packages'],[{'Name':'fixture'}])
        self.assertEqual(self.rec['counts']['HIGH'],0)

    def test_scanner_warning_blocks_and_preserves_evidence(self):
        out,steps=self.scan_fixture(warning=True)
        self.assertEqual(steps,['version','db','native']);self.assertIn('WARN',(out/'native.log').read_text())
        self.assertNotIn('counts',self.rec)

    def test_cleanup_attempts_all_owned_ids_after_failure(self):
        out,steps=self.scan_fixture(cleanup_failure=True)
        self.assertTrue((out/'vulnerabilities.json').exists());self.assertEqual(len(steps),4)

    def test_stage_missing_scan_before_contact(self):
        run=self.evidence/'run';run.mkdir();(run/'run.json').write_text(json.dumps({'commit':'a'*40,'version':'0.6.0'}))
        args=self.args('smoke');args[-1]=str(run)
        with patch.object(c,'source',return_value=(b'public context',[])),patch.object(c,'validate_record'), \
             patch.object(c,'docker',side_effect=AssertionError('Docker prohibited')) as docker,patch.object(c,'locked') as lock, \
             contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(c.main(args),2);self.assertIn('STOP [IO_OR_SCHEMA];',err.getvalue())
            docker.assert_not_called();lock.assert_not_called()

    def test_unauthorized_deploy_before_contact(self):
        run=self.evidence/'run';run.mkdir();rec=dict(self.rec,commit='a'*40,stages={'verify':{'passed':True}},counts={'MEDIUM':0})
        (run/'run.json').write_text(json.dumps(rec));args=self.args('deploy');args[-1]=str(run)
        with patch.object(c,'source',return_value=(b'public context',[])),patch.object(c,'validate_record'), \
             patch.object(c,'docker',side_effect=AssertionError('Docker prohibited')) as docker,patch.object(c,'locked') as lock, \
             contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(c.main(args),2);self.assertIn('STOP [DEPLOY_APPROVAL];',err.getvalue())
            docker.assert_not_called();lock.assert_not_called()

    def deployment_fixture(self,config_failure=False):
        run=self.evidence/'run';run.mkdir();baseline={'containerId':'a'*64,'imageId':'sha256:'+'b'*64,'startedAt':'public-before'}
        rec=dict(self.rec,commit='a'*40,contextSHA256=c.sha(b'public context'),production=baseline,unrelated=[],counts={'MEDIUM':0},
                 stages={n:{'passed':True,'files':{}} for n in ('preflight','build','scan','smoke','verify')})
        (run/'run.json').write_text(json.dumps(rec));args=self.args('deploy');args[-1]=str(run);args+=['--authorize-deploy']
        original=Path.read_text
        def readtext(path,*a,**kw):
            if path.as_posix()=='/etc/machine-id':return self.target['hostMachineId']
            return original(path,*a,**kw)
        after={'containerId':'e'*64,'imageId':rec['imageId'],'startedAt':'public-after'}
        with patch.object(c,'source',return_value=(b'public context',[])),patch.object(c,'validate_record'),patch.object(c,'live'), \
             patch.object(c,'locked',return_value=contextlib.nullcontext()),patch.object(c.sys,'platform','linux'), \
             patch.object(c.os,'getuid',return_value=1000,create=True),patch.object(Path,'read_text',readtext), \
             patch.object(c,'candidate'),patch.object(c,'unrelated',return_value=[]), \
             patch.object(c,'production',side_effect=[baseline,baseline,after]),patch.object(c,'runtime_check'), \
             patch.object(c,'compose_check',side_effect=[{},SecurityError('COMPOSE_HARDENING','public invalid config')] if config_failure else [{},{}]), \
             patch.object(c,'docker',return_value='') as docker,contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(c.main(args),2 if config_failure else 0)
            if config_failure:
                self.assertIn('STOP [COMPOSE_HARDENING];',err.getvalue());docker.assert_not_called()
            else:
                self.assertEqual(docker.call_count,1)
                self.assertEqual(docker.call_args.args[-8:],('up','-d','--no-build','--pull','never','--no-deps','--force-recreate','passwordforge'))
                self.assertIn(self.target['composeFile'],docker.call_args.args)
        self.assertEqual(self.compose.read_text(),'public fixture only')

    def test_actual_deploy_dispatch_scopes_service(self):
        self.deployment_fixture()

    def test_compose_failure_mechanically_blocks_up(self):
        self.deployment_fixture(config_failure=True)

    def oci_pair(self,labels=None):
        path=self.root/'graph.tar'
        metadata,native,config,blobs=image_fixture(path,labels=labels,attestation=True,with_config=False)
        native['Descriptor']=metadata['containerimage.descriptor']
        index=json.loads(blobs['blobs/sha256/'+native['Id'][7:]])
        selected=copy.deepcopy(native);selected['Id']=index['manifests'][0]['digest'];selected['Descriptor']=index['manifests'][0]
        return metadata,native,selected,config,path.read_bytes()

    def test_index_export_reference_is_distinct_from_selected_manifest(self):
        metadata,native,selected,config,_=self.oci_pair()
        with patch.object(c,'docker',return_value=json.dumps([native])):
            reference=c.export_binding(self.rec,metadata,native['Id'],selected)
        self.assertEqual(reference,native['Id']);self.assertEqual(len({reference,selected['Id'],config}),3)
        self.assertNotEqual(reference,selected['Id'])

    def test_manifest_cannot_be_the_export_reference(self):
        metadata,native,selected,config,_=self.oci_pair()
        with patch.object(c,'docker',return_value=json.dumps([selected])):
            self.rejects('EXPORT_REFERENCE',lambda:c.export_binding(self.rec,metadata,native['Id'],selected))
        del native['Descriptor']
        with patch.object(c,'docker',return_value=json.dumps([native])):
            self.rejects('SCHEMA_FIELD',lambda:c.export_binding(self.rec,metadata,metadata['containerimage.digest'],selected))

    def recovery_fixture(self):
        origin=self.root/'failed';source=origin/'source/passwordforge';source.mkdir(parents=True)
        files={'package.json':json.dumps({'version':'0.6.0'}),'Dockerfile':
          'FROM node:24-alpine@sha256:'+('a'*64)+' AS build\nFROM nginx:1-alpine@sha256:'+('b'*64)+'\nLABEL org.opencontainers.image.version="0.6.0"\n'}
        inv={'version':'0.6.0','fileCount':3,'files':[{'path':p,'mode':'0644'} for p in (*files,'RELEASE-INVENTORY.json')]}
        files['RELEASE-INVENTORY.json']=json.dumps(inv)
        for name,raw in files.items():(source/name).write_bytes(raw.encode());(source/name).chmod(0o644)
        for args in (['init'],['config','user.name','Public Fixture'],['config','user.email','fixture@example.invalid'],['add','.'],['commit','-m','public fixture']):
            subprocess.run(['git','-C',str(source),*args],check=True,capture_output=True)
        commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD']).decode().strip()
        context,refs=c.source(commit,'0.6.0',str(source));contextsha=c.sha(context)
        labels={c.OWNER:self.rec['run'],'org.passwordforge.source':contextsha,'org.opencontainers.image.version':'0.6.0'}
        metadata,native,selected,config,archive=self.oci_pair(labels)
        metadata['buildx.build.provenance']={'materials':[{'uri':'pkg:docker/'+r.split(':')[0]+'@fixture','digest':{'sha256':r.split('@sha256:')[1]}} for r in refs],
            'invocation':{'configSource':{'digest':{'sha256':contextsha},'entryPoint':'Dockerfile'},'environment':{'platform':'linux/amd64'}}}
        oldtarget=dict(self.target,evidenceRoot=str(origin/'evidence'));(origin/'target.json').write_text(json.dumps(oldtarget))
        failed=origin/'evidence/run-original';build=failed/'build';build.mkdir(parents=True)
        record=dict(self.rec,commit=commit,contextSHA256=contextsha,targetSHA256=c.sha((origin/'target.json').read_bytes()),
                    schemaVersion=1,stages={'preflight':{'passed':True,'files':{}}})
        for key in ('imageId','configId','exportReference'):record.pop(key,None)
        c.write(failed/'run.json',record)
        old={'name':'/passwordforge','id':'a'*64,'image':'sha256:'+'b'*64,'running':True,'status':'running','startedAt':'old-public-start','health':'healthy','restartCount':0}
        fresh=dict(old,startedAt='new-public-start')
        c.write(origin/'evidence/baseline-before.json',{'containers':[old],'composeSHA256':self.target['composeSHA256'],'networkIds':self.target['proxyNetworkId']+'\n','volumeNames':''})
        (build/'context.tar').write_bytes(context);c.write(build/'metadata.json',metadata);(build/'build.iid').write_text(native['Id'])
        (build/'build.log').write_text('exporting config '+config+'\n');c.write(build/'build.log.status.json',{'exitStatus':0})
        error='Error response from daemon: No such image: '+selected['Id']+'\n';(build/'export.log').write_text(error);c.write(build/'export.log.status.json',{'exitStatus':1})
        report={'result':'HOLD','commit':commit,'candidate':record['candidate'],'buildExitStatus':0,'exportExitStatus':1,'exportError':error,
                'sourceFingerprint':contextsha,'imageSourceRunVersionLabelsMatch':True,'identities':{'nativeImageIndexId':native['Id'],
                'platformSelectedManifestId':selected['Id'],'configDigestReportedByBuildx':config,'buildIID':native['Id'],
                'buildExportDigest':native['Id'],'selectedDescriptor':selected['Descriptor']}}
        c.write(origin/'evidence/FINAL-BUILD-REPORT.json',report)
        fixture={'origin':origin,'failed':failed,'source':source,'native':native,'selected':selected,'metadata':metadata,
                 'config':config,'archive':archive,'old':old,'fresh':fresh,'report':report,'record':record}
        self.refresh_recovery(fixture)
        return fixture

    def refresh_recovery(self,f):
        evidence=f['origin']/'evidence';manifest=evidence/'EVIDENCE-MANIFEST.json'
        entries=[{'path':p.relative_to(f['origin']).as_posix(),'bytes':p.stat().st_size,'sha256':c.sha(p.read_bytes())}
                 for p in evidence.rglob('*') if p.is_file() and p!=manifest]
        manifest.write_text(json.dumps({'files':entries}))
        msha=c.sha(manifest.read_bytes());rsha=c.sha((evidence/'FINAL-BUILD-REPORT.json').read_bytes())
        now=dt.datetime.now(dt.timezone.utc)
        review={'schemaVersion':1,'failureManifestSHA256':msha,'failureReportSHA256':rsha,
            'originalBaselineSHA256':c.sha((evidence/'baseline-before.json').read_bytes()),'targetSHA256':c.sha(self.path.read_bytes()),
            'toolSHA256':c.sha(Path(c.__file__).read_bytes()),'reviewedAt':now.isoformat(),'expiresAt':(now+dt.timedelta(minutes=30)).isoformat(),
            'containers':[f['fresh']],'differences':c.baseline_differences([f['old']],[f['fresh']])}
        reviewpath=self.root/'review.json';reviewpath.write_text(json.dumps(review));f['review']=review;f['reviewpath']=reviewpath
        f['args']=['recover-export','--target',str(self.path),'--evidence',str(self.evidence/'recovered'),
            '--failed-run',str(f['failed']),'--failure-manifest-sha256',msha,'--failure-report-sha256',rsha,
            '--source',str(f['source']),'--baseline-review',str(reviewpath),'--baseline-review-sha256',c.sha(reviewpath.read_bytes())]

    def recovery_dispatch(self,f,expected=None,drift=None,archive=None):
        calls=[];save=[];realread=Path.read_text
        prod={'Id':f['fresh']['id'],'Name':'/passwordforge','Image':f['fresh']['image'],'RestartCount':0,
            'State':{'Running':True,'Status':'running','StartedAt':f['fresh']['startedAt'],'Health':{'Status':'healthy'}},
            'Config':{'Labels':{'com.docker.compose.project':'passwordforge','com.docker.compose.service':'passwordforge'}},
            'NetworkSettings':{'Networks':{'proxy':{'NetworkID':self.target['proxyNetworkId']}}}}
        def readtext(p,*a,**kw):return self.target['hostMachineId'] if p.as_posix()=='/etc/machine-id' else realread(p,*a,**kw)
        def docker(*a,**kw):
            calls.append(a)
            if a[:2]==('context','inspect'):return json.dumps([{'Name':'default','Endpoints':{'docker':{'Host':c.ENDPOINT,'SkipTLSVerify':False}}}])
            if a[0]=='info':return json.dumps(self.target['dockerDaemonId'])
            if a[0]=='version':return 'linux/amd64'
            if a[:2]==('buildx','inspect'):return 'Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: unix:///var/run/docker.sock\nStatus: running\nPlatforms: linux/amd64\n'
            if a[0]=='compose':return json.dumps(self.compose56_fixture())
            if a[:2]==('network','ls'):return self.target['proxyNetworkId']+'\n'
            if a[:2]==('volume','ls'):return ''
            if a[:2]==('container','ls'):return prod['Id']
            if a[:2]==('container','inspect'):return json.dumps([prod])
            if a[:2]==('image','inspect'):
                value=f['selected'] if '--platform' in a else f['native']
                if drift=='before' or (drift=='after' and save):value=dict(value,Id='sha256:'+'f'*64)
                return json.dumps([value])
            if a[:2]==('image','save'):
                save.append(a);self.assertEqual(a[-1],f['native']['Id']);self.assertNotIn('--platform',a)
                Path(a[a.index('--output')+1]).write_bytes(f['archive'] if archive is None else archive)
                Path(kw['log']).write_bytes(b'');c.write(Path(str(kw['log'])+'.status.json'),{'exitStatus':0});return ''
            raise AssertionError(a)
        before={str(p):p.read_bytes() for p in f['origin'].rglob('*') if p.is_file()}
        with patch.object(c,'docker',side_effect=docker),patch.object(c.sys,'platform','linux'),patch.object(c.os,'getuid',return_value=1000,create=True), \
             patch.object(Path,'read_text',readtext),patch.object(Path,'home',return_value=self.root/'operator'), \
             patch.object(c.os,'statvfs',return_value=SimpleNamespace(f_bavail=8*1024**3,f_frsize=1),create=True),contextlib.redirect_stderr(io.StringIO()) as err:
            status=c.main(f['args']);self.assertEqual(status,2 if expected else 0,err.getvalue())
            if expected:self.assertIn('STOP ['+expected+'];',err.getvalue())
        self.assertEqual(before,{str(p):p.read_bytes() for p in f['origin'].rglob('*') if p.is_file()})
        return calls,save

    def test_successful_failed_export_recovery_preserves_original_bytes(self):
        f=self.recovery_fixture();calls,save=self.recovery_dispatch(f);self.assertEqual(len(save),1)
        rec=c.read(self.evidence/'recovered/run.json');self.assertEqual(rec['commit'],f['record']['commit']);self.assertEqual(rec['run'],f['record']['run'])
        self.assertNotEqual(rec['recovery']['operationId'],rec['run']);self.assertEqual(rec['exportReference'],f['native']['Id'])
        self.assertEqual(rec['identities']['manifestId'],f['selected']['Id']);self.assertEqual(rec['configId'],f['config'])
        calls,save=self.recovery_dispatch(f,'RUN_EXISTS');self.assertEqual(calls,[]);self.assertEqual(save,[])

    def test_recovery_rejects_unrelated_build_failure_before_contact(self):
        f=self.recovery_fixture();(f['failed']/'build/build.log.status.json').write_text(json.dumps({'exitStatus':1}));self.refresh_recovery(f)
        calls,save=self.recovery_dispatch(f,'RECOVERY_CAUSE');self.assertEqual(calls,[])

    def test_recovery_rejects_corrupted_original_evidence_before_contact(self):
        f=self.recovery_fixture();(f['failed']/'build/context.tar').write_bytes(b'altered')
        calls,save=self.recovery_dispatch(f,'RECOVERY_EVIDENCE');self.assertEqual(calls,[])

    def test_recovery_rejects_stale_or_unapproved_baseline_before_contact(self):
        for kind in ('stale','unapproved','differences'):
            with self.subTest(kind=kind):
                f=self.recovery_fixture() if kind=='stale' else f
                review=dict(f['review'])
                if kind=='stale':review['expiresAt']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=1)).isoformat()
                elif kind=='unapproved':review['toolSHA256']='f'*64
                else:review['differences']=[]
                f['reviewpath'].write_text(json.dumps(review));f['args'][-1]=c.sha(f['reviewpath'].read_bytes())
                calls,save=self.recovery_dispatch(f,'BASELINE_REVIEW');self.assertEqual(calls,[])

    def test_recovery_rejects_tag_substitution_before_export(self):
        f=self.recovery_fixture();calls,save=self.recovery_dispatch(f,'EXPORT_REFERENCE',drift='before');self.assertEqual(save,[])

    def test_recovery_rejects_tag_substitution_after_export(self):
        f=self.recovery_fixture();calls,save=self.recovery_dispatch(f,'IMAGE_DRIFT',drift='after');self.assertEqual(len(save),1)
        self.assertFalse((self.evidence/'recovered/run.json').exists())

    def test_recovery_rejects_wrong_reported_configuration(self):
        f=self.recovery_fixture();f['report']['identities']['configDigestReportedByBuildx']='sha256:'+'e'*64
        (f['origin']/'evidence/FINAL-BUILD-REPORT.json').write_text(json.dumps(f['report']));self.refresh_recovery(f)
        calls,save=self.recovery_dispatch(f,'RECOVERY_IDENTITY');self.assertEqual(calls,[])

    def test_recovery_rejects_missing_archive_graph_after_export(self):
        f=self.recovery_fixture()
        with tarfile.open(fileobj=io.BytesIO(f['archive'])) as tar:blobs={m.name:tar.extractfile(m).read() for m in tar.getmembers()}
        del blobs['blobs/sha256/'+f['native']['Id'][7:]]
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as tar:
            for name,raw in blobs.items():
                m=tarfile.TarInfo(name);m.size=len(raw);tar.addfile(m,io.BytesIO(raw))
        self.recovery_dispatch(f,'EXPORT_GRAPH_MISSING',archive=stream.getvalue())
        self.assertFalse((self.evidence/'recovered/run.json').exists())

    def mutated_archive(self,f,change):
        with tarfile.open(fileobj=io.BytesIO(f['archive'])) as tar:blobs={m.name:tar.extractfile(m).read() for m in tar.getmembers()}
        change(blobs);stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as tar:
            for name,raw in blobs.items():
                member=tarfile.TarInfo(name);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
        return stream.getvalue()

    def test_recovery_rejects_corrupted_archive_index(self):
        f=self.recovery_fixture()
        archive=self.mutated_archive(f,lambda blobs:blobs.update({'blobs/sha256/'+f['native']['Id'][7:]:b'{}'}))
        self.recovery_dispatch(f,'DESCRIPTOR_HASH',archive=archive)
        self.assertFalse((self.evidence/'recovered/run.json').exists())

    def test_recovery_rejects_missing_attestation(self):
        f=self.recovery_fixture()
        def remove(blobs):
            index=json.loads(blobs['blobs/sha256/'+f['native']['Id'][7:]])
            del blobs['blobs/sha256/'+index['manifests'][1]['digest'][7:]]
        self.recovery_dispatch(f,'EXPORT_GRAPH_MISSING',archive=self.mutated_archive(f,remove))

    def test_recovery_rejects_inconsistent_attestation_subject(self):
        f=self.recovery_fixture()
        def change(blobs):
            index=json.loads(blobs['blobs/sha256/'+f['native']['Id'][7:]])
            ad=index['manifests'][1];att=json.loads(blobs['blobs/sha256/'+ad['digest'][7:]])
            layer=att['layers'][0];statement=json.loads(blobs['blobs/sha256/'+layer['digest'][7:]])
            statement['subject'][0]['digest']['sha256']='f'*64
            raw=json.dumps(statement,separators=(',',':')).encode();layer.update(digest='sha256:'+c.sha(raw),size=len(raw));blobs['blobs/sha256/'+c.sha(raw)]=raw
            raw=json.dumps(att,separators=(',',':')).encode();ad.update(digest='sha256:'+c.sha(raw),size=len(raw));blobs['blobs/sha256/'+c.sha(raw)]=raw
            raw=json.dumps(index,separators=(',',':')).encode();identity='sha256:'+c.sha(raw);blobs['blobs/sha256/'+identity[7:]]=raw
            # Authenticate this intentionally invalid graph in the synthetic build fixture, so subject checking is reached.
            f['native'].update(Id=identity,Descriptor={'mediaType':'application/vnd.oci.image.index.v1+json','digest':identity,'size':len(raw)})
            f['metadata'].update(**{'containerimage.digest':identity,'containerimage.descriptor':f['native']['Descriptor']})
            out=f['failed']/'build';(out/'metadata.json').write_text(json.dumps(f['metadata']));(out/'build.iid').write_text(identity)
            f['report']['identities'].update(nativeImageIndexId=identity,buildIID=identity,buildExportDigest=identity)
            (f['origin']/'evidence/FINAL-BUILD-REPORT.json').write_text(json.dumps(f['report']));self.refresh_recovery(f)
        archive=self.mutated_archive(f,change);self.recovery_dispatch(f,'ATTESTATION_STATEMENT',archive=archive)

    def test_recovery_configuration_must_match_original_even_without_metadata_config(self):
        f=self.recovery_fixture();wrong='sha256:'+'e'*64
        f['report']['identities']['configDigestReportedByBuildx']=wrong
        (f['origin']/'evidence/FINAL-BUILD-REPORT.json').write_text(json.dumps(f['report']))
        (f['failed']/'build/build.log').write_text('exporting config '+wrong+'\n');self.refresh_recovery(f)
        calls,save=self.recovery_dispatch(f,'RECOVERY_IDENTITY');self.assertEqual(len(save),1)
        self.assertFalse((self.evidence/'recovered/run.json').exists())

    def test_recovery_rejects_actual_baseline_drift_before_export(self):
        f=self.recovery_fixture();f['fresh']['startedAt']='changed-again-after-review'
        calls,save=self.recovery_dispatch(f,'BASELINE_REVIEW');self.assertEqual(save,[])
        self.assertFalse((self.evidence/'recovered').exists())

    def test_recovery_requires_explicit_checksum_before_contact(self):
        f=self.recovery_fixture();i=f['args'].index('--baseline-review-sha256');f['args'][i+1]='0'*64
        calls,save=self.recovery_dispatch(f,'BASELINE_REVIEW');self.assertEqual(calls,[])

    def test_actual_build_uses_top_level_index_and_verifies_full_graph(self):
        metadata,native,selected,config,archive=self.oci_pair({c.OWNER:self.rec['run'],
            'org.passwordforge.source':self.rec['contextSHA256'],'org.opencontainers.image.version':'0.6.0'})
        out=self.root/'build';out.mkdir();saves=[]
        self.rec.update(production={'containerId':'a'*64,'imageId':'sha256:'+'b'*64,'startedAt':'public-start'},unrelated=[])
        prod={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Running':True,'Health':{'Status':'healthy'},'StartedAt':'public-start'},
              'Config':{'Labels':{'com.docker.compose.project':'passwordforge','com.docker.compose.service':'passwordforge'}},
              'NetworkSettings':{'Networks':{'proxy':{'NetworkID':self.target['proxyNetworkId']}}}}
        def docker(*a,**kw):
            if a[:2]==('image','ls'):return ''
            if a[:2]==('container','ls'):return ''
            if a[:2]==('container','inspect'):return json.dumps([prod])
            if a[:2]==('image','inspect'):return json.dumps([selected if '--platform' in a else native])
            if a[:2]==('buildx','build'):
                Path(a[a.index('--metadata-file')+1]).write_text(json.dumps(metadata));Path(a[a.index('--iidfile')+1]).write_text(native['Id']);return ''
            if a[:2]==('image','save'):
                saves.append(a);Path(a[a.index('--output')+1]).write_bytes(archive);return ''
            raise AssertionError(a)
        with patch.object(c,'docker',side_effect=docker):
            c.build(self.target,self.root,self.rec,out,b'public context',[])
        self.assertEqual(len(saves),1);self.assertEqual(saves[0][-1],native['Id']);self.assertNotIn('--platform',saves[0])
        self.assertEqual(self.rec['identities']['manifestId'],selected['Id']);self.assertEqual(self.rec['configId'],config)

    def test_recovery_rejects_boolean_command_status(self):
        f=self.recovery_fixture();(f['failed']/'build/build.log.status.json').write_text(json.dumps({'exitStatus':False}));self.refresh_recovery(f)
        calls,save=self.recovery_dispatch(f,'SCHEMA_FIELD');self.assertEqual(calls,[])

    def test_recovery_missing_source_argument_rejected_before_contact(self):
        f=self.recovery_fixture();i=f['args'].index('--source');del f['args'][i:i+2]
        calls,save=self.recovery_dispatch(f,'RECOVERY_INPUT');self.assertEqual(calls,[])

    def policy_fixture(self):
        now=dt.datetime.now(dt.timezone.utc);earlier=(now-dt.timedelta(minutes=10)).isoformat();newtime=(now-dt.timedelta(minutes=5)).isoformat()
        pf={'name':'/passwordforge','id':'a'*64,'image':'sha256:'+'b'*64,'running':True,'status':'running','startedAt':earlier,'health':'healthy','restartCount':0}
        homarr=dict(pf,name='/homarr',id='1'*64,image='sha256:'+'2'*64,health=None)
        watch=dict(pf,name='/watchtower',id='5'*64,image='sha256:'+'6'*64)
        before=[pf,homarr,watch];after=copy.deepcopy(before)
        for d in after:d['startedAt']=newtime
        after[1].update(id='3'*64,image='sha256:'+'4'*64)
        replacements=[{'name':'/homarr','before':{'id':homarr['id'],'image':homarr['image']},'now':{'id':after[1]['id'],'image':after[1]['image']}}]
        def network(identity,name):
            return {'id':identity,'name':name,'configuration':{'Driver':'bridge','Scope':'local','Internal':False,'Attachable':False,'Ingress':False,
               'EnableIPv4':True,'EnableIPv6':False,'IPAM':{'Driver':'default','Options':None,'Config':[{'Subnet':'192.0.2.0/24','Gateway':'192.0.2.1'}]},
               'Options':{'com.docker.network.bridge.default_bridge':'true','com.docker.network.bridge.name':'docker0'} if name=='bridge' else {},
               'Labels':{},'ConfigOnly':False,'ConfigFrom':{'Network':''}}}
        netold=[network('a'*64,'bridge'),network(self.target['proxyNetworkId'],'proxy')]
        netnow=copy.deepcopy(netold);netnow[0]['id']='c'*64;netold[0]['configuration']=None
        beforeProtection={d['name']:{'labels':{},'networks':{'proxy':self.target['proxyNetworkId']} if d['name']=='/passwordforge' else {'bridge':'a'*64}} for d in before}
        nowProtection=copy.deepcopy(beforeProtection)
        for name in ('/homarr','/watchtower'):nowProtection[name]['networks']['bridge']='c'*64
        origin=self.root/'policy-origin';(origin/'evidence').mkdir(parents=True)
        old={'containers':before,'composeSHA256':self.target['composeSHA256'],'networkIds':'a'*64+'\n'+self.target['proxyNetworkId']+'\n','volumeNames':''}
        (origin/'evidence/baseline-before.json').write_text(json.dumps(old));oldsha=c.sha((origin/'evidence/baseline-before.json').read_bytes())
        events=[{'time':(now-dt.timedelta(minutes=5,seconds=30)).isoformat(),'message':'Found new ghcr.io/homarr-labs/homarr:latest image ('+'4'*12+')'},
                {'time':(now-dt.timedelta(minutes=5,seconds=1)).isoformat(),'message':'Stopping /homarr ('+'1'*12+') with SIGTERM'},
                {'time':newtime,'message':'Creating /homarr'}]
        evidence={'hostMachineId':self.target['hostMachineId'],'dockerDaemonId':self.target['dockerDaemonId'],'observedAt':now.isoformat(),
                  'originalBaselineSHA256':oldsha,'networksBefore':netold,'networksNow':netnow,'volumesBefore':[],'volumesNow':[],
                  'protectionBefore':beforeProtection,'protectionNow':nowProtection,'watchtowerEvents':events}
        ep=self.root/'resource-evidence.json';ep.write_text(json.dumps(evidence))
        review={'schemaVersion':1,'failureManifestSHA256':'d'*64,'failureReportSHA256':'e'*64,'originalBaselineSHA256':oldsha,
            'targetSHA256':c.sha(self.path.read_bytes()),'toolSHA256':c.sha(Path(c.__file__).read_bytes()),'reviewedAt':(now+dt.timedelta(microseconds=1)).isoformat(),
            'expiresAt':(now+dt.timedelta(minutes=30)).isoformat(),'containers':after,
            'differences':c.baseline_differences(before,after,replacements),'resourceReview':{'evidencePath':str(ep),'evidenceSHA256':c.sha(ep.read_bytes()),
            'containerReplacements':replacements,'bridgeReplacement':{'before':'a'*64,'now':'c'*64,'acknowledged':True,'historicalEquivalence':'not-established'}}}
        rp=self.root/'policy-review.json';rp.write_text(json.dumps(review))
        return {'origin':origin,'old':old,'review':review,'evidence':evidence,'ep':ep,'rp':rp}

    def check_policy(self,f,expected=None):
        f['ep'].write_text(json.dumps(f['evidence']));f['review']['resourceReview']['evidenceSHA256']=c.sha(f['ep'].read_bytes())
        f['rp'].write_text(json.dumps(f['review']));checksum=c.sha(f['rp'].read_bytes())
        def validate():return c.recovery_review(str(f['rp']),checksum,self.target,c.sha(self.path.read_bytes()),f['origin'],'d'*64,'e'*64)
        with patch.object(c,'docker',side_effect=AssertionError('Offline validation must not contact Docker')) as docker:
            if expected:self.rejects(expected,validate);result=None
            else:result=validate()[0]
            docker.assert_not_called()
        return result

    def test_policy_exact_homarr_and_bridge_exceptions(self):
        f=self.policy_fixture();review=self.check_policy(f)
        self.assertEqual(len(review['differences']),3);self.assertEqual(review['resourceReview']['containerReplacements'][0]['name'],'/homarr')

    def test_recovery_bridge_missing_history_explicitly_recorded(self):
        f=self.policy_fixture();review=self.check_policy(f)
        self.assertIsNone(review['_resourceEvidence']['networksBefore'][0]['configuration'])
        self.assertEqual(review['resourceReview']['bridgeReplacement']['historicalEquivalence'],'not-established')
        self.assertIs(review['resourceReview']['bridgeReplacement']['acknowledged'],True)

    def test_recovery_bridge_incorrect_original_identity(self):
        f=self.policy_fixture();f['review']['resourceReview']['bridgeReplacement']['before']='9'*64
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_recovery_bridge_incorrect_current_identity(self):
        f=self.policy_fixture();f['review']['resourceReview']['bridgeReplacement']['now']='9'*64
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_recovery_bridge_acknowledgment_required(self):
        f=self.policy_fixture()
        for value in (False,None,1,'true'):
            f['review']['resourceReview']['bridgeReplacement']['acknowledged']=value
            self.check_policy(f,'RESOURCE_EVIDENCE')
        del f['review']['resourceReview']['bridgeReplacement']['acknowledged']
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_recovery_bridge_equivalence_claim_rejected(self):
        f=self.policy_fixture();f['review']['resourceReview']['bridgeReplacement']['historicalEquivalence']='established'
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_recovery_bridge_unrelated_network_change_rejected(self):
        f=self.policy_fixture();n=copy.deepcopy(f['evidence']['networksNow'][1]);n.update(name='unrelated',id='8'*64)
        f['evidence']['networksBefore'].append(copy.deepcopy(n));f['evidence']['networksNow'].append(n)
        f['old']['networkIds']+='\n'+'8'*64
        (f['origin']/'evidence/baseline-before.json').write_text(json.dumps(f['old']))
        digest=c.sha((f['origin']/'evidence/baseline-before.json').read_bytes())
        f['review']['originalBaselineSHA256']=digest;f['evidence']['originalBaselineSHA256']=digest
        n['id']='9'*64;self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_recovery_bridge_current_default_identity_required(self):
        f=self.policy_fixture();f['evidence']['networksNow'][0]['configuration']['Options']['com.docker.network.bridge.default_bridge']='false'
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_other_stages_do_not_inherit_recovery_bridge_exception(self):
        # Inspect the actual dispatch/call sites; no synthetic stage authorization.
        import ast
        tree=ast.parse(Path(c.__file__).read_bytes());functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        callers=lambda name:{f for f,node in functions.items() if any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id==name for n in ast.walk(node))}
        self.assertEqual(callers('resource_review'),{'recovery_review'})
        self.assertEqual(callers('recovery_review'),{'recover_export'})
        self.assertEqual(callers('live_resource_guard'),{'recover_export'})
        gate=next(n for n in ast.walk(functions['main']) if isinstance(n,ast.If) and ast.unparse(n.test)=="args.stage == 'recover-export'")
        self.assertEqual(len(gate.body),1);self.assertIsInstance(gate.body[0],ast.Return)
        self.assertEqual(gate.body[0].value.func.id,'recover_export')
        f=self.policy_fixture()
        # Default network validator remains strict even with recovery-shaped records.
        self.rejects('RESOURCE_EVIDENCE',lambda:c.network_records(f['evidence']['networksBefore']))

    def test_policy_resource_checksum_substitution_rejected(self):
        f=self.policy_fixture();f['ep'].write_bytes(b'{}')
        with patch.object(c,'docker',side_effect=AssertionError('Offline Docker contact')) as docker:
            self.rejects('RESOURCE_EVIDENCE',lambda:c.recovery_review(str(f['rp']),c.sha(f['rp'].read_bytes()),self.target,
                c.sha(self.path.read_bytes()),f['origin'],'d'*64,'e'*64))
            docker.assert_not_called()

    def test_policy_live_exact_resource_and_watchtower_evidence(self):
        f=self.policy_fixture();review=self.check_policy(f);e=f['evidence']
        networks=[dict(n['configuration'],Id=n['id'],Name=n['name']) for n in e['networksNow']]
        containers=[{'Name':name,'Config':{'Labels':v['labels']},'NetworkSettings':{'Networks':{k:{'NetworkID':identity} for k,identity in v['networks'].items()}}}
                    for name,v in e['protectionNow'].items()]
        logs='\n'.join('time="'+v['time']+'" msg="'+v['message']+'"' for v in e['watchtowerEvents'])
        def transport(*a,**kw):
            if a[:2]==('network','ls'):return '\n'.join(n['id'] for n in e['networksNow'])
            if a[:2]==('network','inspect'):return json.dumps(networks)
            if a[:2]==('volume','ls'):return ''
            if a[:2]==('container','ls'):return '\n'.join(d['id'] for d in review['containers'])
            if a[:2]==('container','inspect'):return json.dumps(containers)
            if a[0]=='logs':
                self.assertEqual(a[-1],review['containers'][2]['id']);self.assertTrue(kw['include_stderr'])
                return logs
            raise AssertionError(a)
        with patch.object(c,'docker',side_effect=transport):c.live_resource_guard(review,f['old'])
        logs=''
        with patch.object(c,'docker',side_effect=transport):self.rejects('RESOURCE_EVIDENCE',lambda:c.live_resource_guard(review,f['old']))

    def test_policy_wrong_previous_container(self):
        f=self.policy_fixture();f['review']['resourceReview']['containerReplacements'][0]['before']['id']='9'*64
        self.check_policy(f,'BASELINE_EXCEPTION')

    def test_policy_wrong_current_container(self):
        f=self.policy_fixture();f['review']['resourceReview']['containerReplacements'][0]['now']['id']='9'*64
        self.check_policy(f,'BASELINE_EXCEPTION')

    def test_policy_wrong_image_digest(self):
        f=self.policy_fixture();f['review']['resourceReview']['containerReplacements'][0]['now']['image']='sha256:'+'9'*64
        self.check_policy(f,'BASELINE_EXCEPTION')

    def test_policy_missing_independent_watchtower_events(self):
        f=self.policy_fixture();f['evidence']['watchtowerEvents']=[];self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_policy_passwordforge_replacement_rejected(self):
        f=self.policy_fixture();f['review']['resourceReview']['containerReplacements'][0]['name']='/passwordforge'
        self.check_policy(f,'BASELINE_EXCEPTION')

    def test_policy_protected_resource_replacement_rejected(self):
        for name in ('/traefik','/portainer','/watchtower'):
            f=self.policy_fixture() if name=='/traefik' else f
            f['review']['resourceReview']['containerReplacements'][0]['name']=name
            self.check_policy(f,'BASELINE_EXCEPTION')

    def test_policy_unreviewed_replacement_rejected(self):
        f=self.policy_fixture();f['review']['resourceReview']['containerReplacements']=[]
        self.check_policy(f,'BASELINE_REVIEW')

    def test_policy_additional_replacement_rejected(self):
        f=self.policy_fixture();f['review']['containers'][2]['id']='8'*64
        self.check_policy(f,'BASELINE_REVIEW')

    def test_policy_unapproved_bridge_replacement_rejected(self):
        f=self.policy_fixture();f['review']['resourceReview']['bridgeReplacement']=None
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_policy_proxy_configuration_change_rejected(self):
        f=self.policy_fixture();f['evidence']['networksNow'][1]['configuration']['IPAM']['Config'][0]['Subnet']='198.51.100.0/24'
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_policy_proxy_replacement_rejected(self):
        f=self.policy_fixture();f['evidence']['networksNow'][1]['id']='7'*64
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_policy_expired_approval_rejected(self):
        f=self.policy_fixture();f['review']['expiresAt']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=1)).isoformat()
        self.check_policy(f,'BASELINE_REVIEW')

    def test_policy_missing_restart_difference_rejected(self):
        f=self.policy_fixture();f['review']['differences']=[]
        self.check_policy(f,'BASELINE_REVIEW')

    def test_policy_passwordforge_attachment_change_rejected(self):
        f=self.policy_fixture();f['evidence']['protectionNow']['/passwordforge']['networks']={'bridge':'c'*64}
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_policy_routing_and_ownership_change_rejected(self):
        f=self.policy_fixture();f['evidence']['protectionNow']['/passwordforge']['labels']={'com.docker.compose.project':'other'}
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_policy_volume_change_rejected(self):
        f=self.policy_fixture();f['evidence']['volumesNow']=[{'name':'new-volume','driver':'local','scope':'local','mountpoint':'/public',
                                                            'optionsSHA256':'a'*64,'labelsSHA256':'b'*64}]
        self.check_policy(f,'RESOURCE_EVIDENCE')

    def test_policy_live_new_resource_change_rejected(self):
        f=self.policy_fixture();review=self.check_policy(f)
        snapshot={'networks':copy.deepcopy(f['evidence']['networksNow']),'volumes':[],'protection':f['evidence']['protectionNow']}
        snapshot['networks'][0]['id']='f'*64
        # Mock only Docker responses; resource_snapshot and all validators remain real.
        def docker(*a,**kw):
            if a[:2]==('network','ls'):return '\n'.join(n['id'] for n in snapshot['networks'])
            if a[:2]==('network','inspect'):return json.dumps([dict(n['configuration'],Id=n['id'],Name=n['name']) for n in snapshot['networks']])
            if a[:2]==('volume','ls'):return ''
            if a[:2]==('container','ls'):return 'a'*64
            if a[:2]==('container','inspect'):return json.dumps([{'Name':name,'Config':{'Labels':p['labels']},'NetworkSettings':{'Networks':{k:{'NetworkID':v} for k,v in p['networks'].items()}}} for name,p in snapshot['protection'].items()])
            raise AssertionError(a)
        with patch.object(c,'docker',side_effect=docker):self.rejects('RESOURCE_EVIDENCE',lambda:c.live_resource_guard(review,f['old']))
        snapshot['networks'][0]['id']=f['evidence']['networksNow'][0]['id']
        snapshot['networks'][0]['configuration']['IPAM']['Config'][0]['Subnet']='198.51.100.0/24'
        with patch.object(c,'docker',side_effect=docker):self.rejects('RESOURCE_EVIDENCE',lambda:c.live_resource_guard(review,f['old']))

    def compose_fixture(self):
        labels={'traefik.enable':'true','traefik.docker.network':'proxy','traefik.http.routers.passwordforge.rule':'Host(`password.example.invalid`)',
                'traefik.http.routers.passwordforge.entrypoints':'websecure','traefik.http.routers.passwordforge.tls':'true',
                'traefik.http.routers.passwordforge.service':'passwordforge','traefik.http.services.passwordforge.loadbalancer.server.port':'8080'}
        return {'name':'passwordforge','services':{'passwordforge':{'image':'sha256:'+'a'*64,'container_name':'passwordforge',
                'platform':'linux/amd64','pull_policy':'never','user':'10001:10001','read_only':True,'cap_drop':['ALL'],
                'security_opt':['no-new-privileges:true'],'pids_limit':128,'mem_limit':'134217728','cpus':1.0,
                'tmpfs':['/tmp:rw,noexec,nosuid,size=16m,mode=1777'],'networks':{'proxy':{}},'labels':labels,'restart':'unless-stopped',
                'healthcheck':{'test':['CMD','wget','-q','-O','/dev/null','http://127.0.0.1:8080/healthz'],'interval':'30s','timeout':'3s','start_period':'10s','retries':3}}},
                'networks':{'proxy':{'name':'proxy','external':True}}}

    def compose56_fixture(self):
        # Sanitized Engine 29 / Compose 5.6 config JSON: private host/image replaced.
        data=self.compose_fixture();service=data['services']['passwordforge']
        service.update(command=None,entrypoint=None,cpus=1,networks={'proxy':None})
        data['networks']['proxy']['ipam']={}
        return data

    def test_compose56_observed_defaults_and_candidate_override(self):
        data=self.compose56_fixture()
        with patch.object(c,'docker',return_value=json.dumps(data)):
            self.assertEqual(c.compose_check(self.target),data)
            self.assertEqual(c.compose_check(self.target,self.root/'override',data['services']['passwordforge']['image']),data)

    def test_compose56_defaults_individually_accepted(self):
        for key in ('command','entrypoint','attachment','ipam'):
            data=self.compose_fixture()
            if key=='attachment':data['services']['passwordforge']['networks']['proxy']=None
            elif key=='ipam':data['networks']['proxy']['ipam']={}
            else:data['services']['passwordforge'][key]=None
            with self.subTest(key=key),patch.object(c,'docker',return_value=json.dumps(data)):
                self.assertEqual(c.compose_check(self.target),data)

    def test_compose56_non_null_execution_defaults_rejected(self):
        for key in ('command','entrypoint'):
            for value in ('',[],False,0,'null','sh',['sh','-c','id']):
                data=self.compose56_fixture();data['services']['passwordforge'][key]=value
                with self.subTest(key=key,value=value),patch.object(c,'docker',return_value=json.dumps(data)):
                    self.rejects('COMPOSE_SCOPE',lambda:c.compose_check(self.target))

    def test_compose56_behavior_changing_ipam_rejected(self):
        for value in (None,False,[],{'driver':'default'},{'config':[]},{'config':[{'subnet':'192.0.2.0/24'}]},
                      {'options':{}},{'driver':'unapproved'}):
            data=self.compose56_fixture();data['networks']['proxy']['ipam']=value
            with self.subTest(ipam=value),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects('COMPOSE_NETWORK',lambda:c.compose_check(self.target))

    def test_compose56_attachment_types_and_overrides_rejected(self):
        for value in (False,0,'',[],{'aliases':['other']},{'ipv4_address':'192.0.2.10'},{'priority':1}):
            data=self.compose56_fixture();data['services']['passwordforge']['networks']['proxy']=value
            code='SCHEMA_FIELD' if type(value) is not dict else 'COMPOSE_NETWORK'
            with self.subTest(attachment=value),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects(code,lambda:c.compose_check(self.target))

    def test_compose56_security_contract_still_enforced(self):
        variants=[('pid','host'),('ipc','host'),('network_mode','host'),('ipc','service:other'),
                  ('privileged',True),('post_start',[{'command':'id','privileged':True}]),('pre_stop',[]),
                  ('devices',[]),('volumes',[]),('cap_add',[]),('unsupported',None)]
        for key,value in variants:
            data=self.compose56_fixture();data['services']['passwordforge'][key]=value
            with self.subTest(key=key),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects('COMPOSE_SCOPE',lambda:c.compose_check(self.target))
        for key,value in [('read_only',False),('user','0:0'),('cap_drop',[]),('security_opt',[]),('ports',[])]:
            data=self.compose56_fixture();data['services']['passwordforge'][key]=value
            code='COMPOSE_SCOPE' if key=='ports' else 'COMPOSE_HARDENING'
            with self.subTest(key=key),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects(code,lambda:c.compose_check(self.target))
        for location in ('service','top'):
            data=self.compose56_fixture()
            if location=='service':data['services']['passwordforge']['networks']['extra']=None
            else:data['networks']['extra']={'external':True,'name':'extra'}
            with self.subTest(location=location),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects('COMPOSE_HARDENING' if location=='service' else 'COMPOSE_NETWORK',lambda:c.compose_check(self.target))

    def test_compose_supports_immutable_production_reference(self):
        data=self.compose_fixture()
        with patch.object(c,'docker',return_value=json.dumps(data)):
            self.assertEqual(c.compose_check(self.target),data)
            self.assertEqual(c.compose_check(self.target,self.root/'override',data['services']['passwordforge']['image']),data)

    def test_compose_rejects_build_dependencies_and_weakened_hardening(self):
        for key,value,code in [('build',{'context':'.'},'COMPOSE_SCOPE'),('depends_on',{'other':{}},'COMPOSE_SCOPE'),
                               ('read_only',False,'COMPOSE_HARDENING'),('pull_policy','always','COMPOSE_HARDENING')]:
            data=self.compose_fixture();data['services']['passwordforge'][key]=value
            with self.subTest(key=key),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects(code,lambda:c.compose_check(self.target))

    def test_compose_rejects_unsupported_execution_and_namespaces(self):
        variants={'pid':'host','ipc':'host','uts':'host','userns_mode':'host','cgroup':'host',
                  'pid-sharing':'service:other','post_start':[{'command':'id','user':'root','privileged':True}],
                  'pre_stop':[{'command':'id'}],'entrypoint':['sh'],'command':['sh','-c','public fixture'],
                  'devices':['/dev/null:/dev/null'],'cap_add':['SYS_ADMIN'],'volumes':['/host:/host'],
                  'network_mode':'host','sysctls':{'kernel.msgmax':'1'},'environment':{'PUBLIC_OVERRIDE':'1'}}
        for key,value in variants.items():
            data=self.compose_fixture();data['services']['passwordforge'][key]=value
            with self.subTest(key=key),patch.object(c,'docker',return_value=json.dumps(data)) as docker:
                self.rejects('COMPOSE_SCOPE',lambda:c.compose_check(self.target));self.assertEqual(docker.call_count,1)
        for value in ('host','container:other','service:other'):
            data=self.compose_fixture();data['services']['passwordforge']['pid']=value
            with self.subTest(pid=value),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects('COMPOSE_SCOPE',lambda:c.compose_check(self.target))

    def test_compose_rejects_privilege_and_extra_security_options(self):
        for key,value,code in [('privileged',True,'COMPOSE_SCOPE'),('privileged','false','COMPOSE_SCOPE'),
                               ('security_opt',['no-new-privileges:true','seccomp=unconfined'],'COMPOSE_HARDENING'),
                               ('cap_drop',['ALL','NET_RAW'],'COMPOSE_HARDENING')]:
            data=self.compose_fixture();data['services']['passwordforge'][key]=value
            with self.subTest(key=key),patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects(code,lambda:c.compose_check(self.target))

    def test_supported_compose_normalization_and_defaults(self):
        data=self.compose_fixture();s=data['services']['passwordforge']
        s.update(privileged=False,tty=False,stdin_open=False,mem_limit=134217728,cpus='1.0',security_opt=['no-new-privileges'],
                 tmpfs=['/tmp:mode=01777,size=16777216,nosuid,noexec,rw'],networks={'proxy':{'priority':0,'gw_priority':0,'aliases':[]}})
        with patch.object(c,'docker',return_value=json.dumps(data)):self.assertEqual(c.compose_check(self.target),data)

    def test_compose_rejects_network_attachment_and_health_overrides(self):
        for attachment in ({'ipv4_address':'192.0.2.10'},{'aliases':['other-service']},{'priority':1}):
            data=self.compose_fixture();data['services']['passwordforge']['networks']['proxy']=attachment
            with patch.object(c,'docker',return_value=json.dumps(data)):
                self.rejects('COMPOSE_NETWORK',lambda:c.compose_check(self.target))
        data=self.compose_fixture();data['services']['passwordforge']['healthcheck']['disable']=True
        with patch.object(c,'docker',return_value=json.dumps(data)):self.rejects('COMPOSE_HEALTH',lambda:c.compose_check(self.target))

    def valid_headers(self):
        return ("HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=utf-8\r\n"
                "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                "font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
                "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n"
                "X-Frame-Options: DENY\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\n\r\n")

    def test_valid_named_headers(self):
        parsed=c.security_headers(self.valid_headers().encode());self.assertEqual(parsed['x-frame-options'],'DENY')
        self.assertEqual(c.security_headers(self.valid_headers().replace('HTTP/1.1 200 OK','HTTP/2 200').encode()),parsed)

    def test_missing_csp_and_unrelated_comment_cannot_pass(self):
        raw=self.valid_headers();line=next(x for x in raw.splitlines(True) if x.startswith('Content-Security-Policy:'))
        self.rejects('HTTP_HEADERS',lambda:c.security_headers(raw.replace(line,'').encode()))
        self.rejects('HTTP_HEADERS',lambda:c.security_headers(raw.replace('Content-Security-Policy:','X-Audit-Comment:').encode()))

    def test_malformed_weakened_and_duplicate_csp(self):
        raw=self.valid_headers()
        for changed in (raw.replace("connect-src 'none'","connect-src *"),raw.replace("script-src 'self'","script-src 'self' 'unsafe-inline'"),
                        raw.replace("connect-src 'none'","connect-src"),raw.replace("connect-src 'none'","connect-src 'none'; connect-src *")):
            self.rejects('HTTP_CSP',lambda:c.security_headers(changed.encode()))
        for value in ("default-src *",next(x.split(':',1)[1] for x in raw.splitlines() if x.startswith('Content-Security-Policy:'))):
            changed=raw.replace('\r\n\r\n','\r\ncOnTeNt-SeCuRiTy-PoLiCy: '+value+'\r\n\r\n')
            self.rejects('HTTP_HEADERS',lambda:c.security_headers(changed.encode()))

    def test_other_security_headers_mandatory_and_exact(self):
        raw=self.valid_headers()
        for name in ('X-Content-Type-Options','Referrer-Policy','Cache-Control','X-Frame-Options','Permissions-Policy'):
            line=next(x for x in raw.splitlines(True) if x.startswith(name+':'))
            for changed in (raw.replace(line,''),raw.replace(line,name+': invalid\r\n'),raw.replace(line,line+line)):
                with self.subTest(name=name):self.rejects('HTTP_HEADERS',lambda:c.security_headers(changed.encode()))

    def test_header_folding_and_multiple_blocks_rejected(self):
        for raw in (self.valid_headers().replace('Referrer-Policy:',' Referrer-Policy:'),
                    self.valid_headers()+self.valid_headers()):
            self.rejects('HTTP_HEADERS',lambda:c.security_headers(raw.encode()))

    def execution_fixture(self):
        expected={'Entrypoint':['nginx'],'Cmd':['-g','daemon off;']}
        d={'Config':dict(expected),'HostConfig':{'PidMode':'','IpcMode':'private','UTSMode':'','UsernsMode':'',
           'CgroupnsMode':'private','Runtime':'runc','Devices':[],'DeviceRequests':None,'DeviceCgroupRules':None,'Binds':None,'VolumesFrom':None}}
        return d,expected

    def test_runtime_rejects_namespaces_and_execution_overrides(self):
        d,expected=self.execution_fixture();c.runtime_execution(d,expected)
        for key,value in [('PidMode','host'),('PidMode','container:other'),('IpcMode','host'),('IpcMode','shareable'),
                          ('UTSMode','host'),('UsernsMode','host'),('CgroupnsMode','host'),('Runtime','unapproved'),
                          ('Devices',[{'PathOnHost':'/dev/null'}]),('Binds',['/host:/host'])]:
            changed=copy.deepcopy(d);changed['HostConfig'][key]=value
            with self.subTest(key=key):self.rejects('RUNTIME_EXECUTION',lambda:c.runtime_execution(changed,expected))
        for key in ('Entrypoint','Cmd'):
            changed=copy.deepcopy(d);changed['Config'][key]=['sh']
            self.rejects('RUNTIME_EXECUTION',lambda:c.runtime_execution(changed,expected))

    def test_unrelated_stop_and_health_transitions_detected(self):
        cid='a'*64;d={'Id':cid,'Name':'/other','Image':'sha256:'+'b'*64,'State':{'StartedAt':'public-start','Running':True,'Status':'running','Health':{'Status':'healthy'}}}
        with patch.object(c,'docker',side_effect=[cid,json.dumps([d])]):before=c.unrelated()
        for changes in ({'Running':False,'Status':'exited'},{'Health':{'Status':'unhealthy'}}):
            altered=copy.deepcopy(d);altered['State'].update(changes)
            with patch.object(c,'docker',side_effect=[cid,json.dumps([altered])]):after=c.unrelated()
            self.assertNotEqual(before,after);self.assertEqual(before[0]['id'],after[0]['id'])

    def record_fixture(self):
        run=self.evidence/'record';run.mkdir();context=b'PUBLIC frozen context';rec=dict(self.rec,commit='a'*40,
            schemaVersion=1,targetSHA256=c.sha(self.path.read_bytes()),contextSHA256=c.sha(context),
            production={'containerId':'a'*64,'imageId':'sha256:'+'b'*64,'startedAt':'public-start'},unrelated=[],stages={})
        for stage in ('preflight','build','scan','smoke','verify'):(run/stage).mkdir()
        out=run/'build';labels={c.OWNER:rec['run'],'org.passwordforge.source':rec['contextSHA256'],'org.opencontainers.image.version':'0.6.0'}
        metadata,inspected,config,_=image_fixture(out/'image.tar',labels=labels,attestation=True)
        rec['imageId']=inspected['Id'];rec['exportReference']=metadata['containerimage.digest'];rec['configId']=config
        rec['identities']=c.verify_identity(out/'image.tar',metadata,inspected,metadata['containerimage.digest'],c.archive_config(out/'image.tar',inspected))
        (out/'context.tar').write_bytes(context);(out/'build.iid').write_text(metadata['containerimage.digest'])
        c.write(out/'metadata.json',metadata);c.write(out/'inspection.json',inspected)
        c.write(out/'identity.json',dict(imageId=rec['imageId'],**rec['identities']))
        db=run/'scan/cache/db';db.mkdir(parents=True)
        now=dt.datetime.now(dt.timezone.utc)
        c.write(db/'metadata.json',{'Version':2,'UpdatedAt':now.isoformat(),'NextUpdate':(now+dt.timedelta(hours=24)).isoformat()})
        result=self.result();result['Metadata']['ImageID']=config
        c.write(run/'scan/vulnerabilities.json',result);rec['counts']=c.scan_gate(result,config)[0]
        c.write(run/'smoke/runtime.json',{'passed':True,'imageId':rec['imageId'],'version':'0.6.0'})
        for stage in ('preflight','build','scan','smoke','verify'):
            rec['stages'][stage]={'passed':True,'files':c.bind_files(run,run/stage)}
        c.write(run/'run.json',rec)
        c.validate_record(run,rec,rec['targetSHA256'],rec['contextSHA256'])
        return run,rec,context

    def record_cli_rejects(self,run,rec,context,code):
        (run/'run.json').write_text(json.dumps(rec))
        before={str(p):p.read_bytes() for p in run.rglob('*') if p.is_file()}
        for action in ('deploy','cleanup'):
            args=[action,'--target',str(self.path),'--evidence',str(run),'--authorize-deploy','--accept-deployment','--image-id','sha256:'+'1'*64]
            with patch.object(c,'source',return_value=(context,[])),patch.object(c,'docker',side_effect=AssertionError('Transport prohibited')) as docker, \
                 patch.object(c,'live',side_effect=AssertionError('Live prohibited')) as live,patch.object(c,'locked',side_effect=AssertionError('Lock prohibited')) as lock, \
                 contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(c.main(args),2);self.assertIn('STOP ['+code+'];',err.getvalue())
                docker.assert_not_called();live.assert_not_called();lock.assert_not_called()
            self.assertEqual(before,{str(p):p.read_bytes() for p in run.rglob('*') if p.is_file()})

    def test_real_record_validator_accepts_complete_synthetic_proof(self):
        run,rec,context=self.record_fixture()
        c.validate_record(run,rec,rec['targetSHA256'],c.sha(context))

    def test_missing_required_artifacts_block_real_dispatch(self):
        # Recreate a public proof per artifact; validator and archive verification are real.
        for relative in ('build/image.tar','build/build.iid','build/metadata.json','scan/vulnerabilities.json','scan/cache/db/metadata.json','smoke/runtime.json'):
            with self.subTest(relative=relative):
                run,rec,context=self.record_fixture();(run/relative).unlink()
                self.record_cli_rejects(run,rec,context,'EVIDENCE_CHANGED')
                import shutil
                shutil.rmtree(run)

    def test_altered_evidence_hash_blocks_real_dispatch(self):
        run,rec,context=self.record_fixture();(run/'build/context.tar').write_bytes(b'PUBLIC altered source')
        self.record_cli_rejects(run,rec,context,'EVIDENCE_CHANGED')

    def test_mixed_build_attempt_even_with_updated_hashes_rejected(self):
        run,rec,context=self.record_fixture();p=run/'build/inspection.json';d=c.read(p);d['Config']['Labels'][c.OWNER]='0'*32;p.write_text(json.dumps(d))
        rec['stages']['build']['files']=c.bind_files(run,run/'build')
        self.record_cli_rejects(run,rec,context,'BUILD_PROOF')

    def test_substituted_scan_even_with_updated_hashes_rejected(self):
        run,rec,context=self.record_fixture();p=run/'scan/vulnerabilities.json';d=c.read(p);d['Metadata']['ImageID']='sha256:'+'0'*64;p.write_text(json.dumps(d))
        rec['stages']['scan']['files']=c.bind_files(run,run/'scan')
        self.record_cli_rejects(run,rec,context,'SCAN_IDENTITY')

    def test_substituted_runtime_even_with_updated_hashes_rejected(self):
        run,rec,context=self.record_fixture();p=run/'smoke/runtime.json';d=c.read(p);d['imageId']='sha256:'+'0'*64;p.write_text(json.dumps(d))
        rec['stages']['smoke']['files']=c.bind_files(run,run/'smoke')
        self.record_cli_rejects(run,rec,context,'RUNTIME_PROOF')

    def test_candidate_identity_mismatch_in_record_blocks_real_dispatch(self):
        run,rec,context=self.record_fixture();rec['imageId']='sha256:'+'0'*64
        self.record_cli_rejects(run,rec,context,'BUILD_PROOF')

    def runtime_fixture(self):
        d,expected=self.execution_fixture()
        d['Image']=self.rec['imageId'];d['State']={'Running':True,'Health':{'Status':'healthy'}};d['Mounts']=[]
        d['Config'].update(User='10001:10001',Labels={})
        d['HostConfig'].update(ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=None,
            SecurityOpt=['no-new-privileges:true'],Memory=134217728,PidsLimit=128,NanoCpus=1000000000,
            Tmpfs={'/tmp':'rw,noexec,nosuid,size=16m,mode=1777'})
        return d,expected

    def test_actual_runtime_validates_real_headers_and_execution(self):
        d,expected=self.runtime_fixture();out=self.root/'http';out.mkdir()
        def curl(args,**kw):
            url=args[-1];head=Path(args[args.index('-D')+1]);body=Path(args[args.index('-o')+1])
            headers=self.valid_headers()
            if url.endswith('/styles.css'):headers=headers.replace('application/javascript','text/css')
            head.write_bytes(headers.encode());body.write_text('ok' if url.endswith('/healthz') else 'class="version">v0.6.0</span>')
            return '404' if url.endswith(('passwordforge-missing','browser-regeneration.mjs')) else '200'
        with patch.object(c,'docker',return_value=json.dumps([d])),patch.object(c,'image',return_value={'Config':expected}),patch.object(c,'command',side_effect=curl):
            c.runtime_check('public-container',out,self.rec,self.target['httpsURL'])
        self.assertEqual(c.read(out/'runtime.json'),{'passed':True,'imageId':self.rec['imageId'],'version':'0.6.0'})

    def test_actual_runtime_rejects_host_namespace_before_http_or_receipt(self):
        d,expected=self.runtime_fixture();d['HostConfig']['PidMode']='host'
        with patch.object(c,'docker',return_value=json.dumps([d])),patch.object(c,'image',return_value={'Config':expected}), \
             patch.object(c,'command',side_effect=AssertionError('HTTP prohibited')) as http,patch.object(c,'write') as writes:
            self.rejects('RUNTIME_EXECUTION',lambda:c.runtime_check('public-container',self.root,self.rec,self.target['httpsURL']))
            http.assert_not_called();writes.assert_not_called()

    def test_binary_crlf_capture_and_header_name_case(self):
        raw=self.valid_headers().encode('ascii')
        expected=c.security_headers(raw)
        changed=raw.replace(b'Content-Security-Policy:',b'cOnTeNt-SeCuRiTy-PoLiCy:\t').replace(b'X-Frame-Options: DENY',b'x-frame-options:  deny\t')
        parsed=c.security_headers(changed);self.assertEqual(parsed['content-security-policy'],expected['content-security-policy'])
        self.assertEqual(parsed['x-frame-options'],'deny')
        for status in (b'HTTP/2 200',b'HTTP/3 200'):
            self.assertEqual(c.security_headers(raw.replace(b'HTTP/1.1 200 OK',status)),expected)

    def test_unicode_and_bare_cr_cannot_fabricate_csp(self):
        raw=self.valid_headers().encode('ascii')
        for separator in ('\u0085'.encode('utf-8'),'\u2028'.encode('utf-8'),b'\x85',b'\r'):
            changed=raw.replace(b'Content-Security-Policy:',b'X-Audit-Comment: public'+separator+b'Content-Security-Policy:')
            with self.subTest(separator=separator):self.rejects('HTTP_HEADERS',lambda:c.security_headers(changed))

    def test_bare_lf_and_incomplete_crlf_framing_rejected(self):
        raw=self.valid_headers().encode('ascii')
        for changed in (raw.replace(b'\r\n',b'\n'),raw.replace(b'Referrer-Policy:',b'X-Comment: public\nReferrer-Policy:'),
                        raw[:-1],raw[:-2],raw+b'public trailing bytes',raw+raw):
            self.rejects('HTTP_HEADERS',lambda:c.security_headers(changed))

    def test_embedded_controls_and_del_rejected(self):
        raw=self.valid_headers().encode('ascii')
        for value in (0,1,8,11,12,27,31,127):
            changed=raw.replace(b'X-Frame-Options: DENY',b'X-Frame-Options: DE'+bytes([value])+b'NY')
            with self.subTest(value=value):self.rejects('HTTP_HEADERS',lambda:c.security_headers(changed))

    def test_obsolete_folding_and_malformed_field_names_rejected(self):
        raw=self.valid_headers().encode('ascii')
        for name in (b' Content-Security-Policy',b'\tContent-Security-Policy',b'Content Security Policy',b'Content-Security-Policy ',b'Content(Security)Policy'):
            changed=raw.replace(b'Content-Security-Policy:',name+b':')
            self.rejects('HTTP_HEADERS',lambda:c.security_headers(changed))
        self.rejects('HTTP_HEADERS',lambda:c.security_headers(raw.replace(b"; connect-src 'none'",b";\r\n connect-src 'none'")))

    def test_text_input_rejected_without_newline_normalization(self):
        self.rejects('HTTP_HEADERS',lambda:c.security_headers(self.valid_headers()))

    def test_runtime_binary_capture_rejects_fabricated_headers_without_success(self):
        d,expected=self.runtime_fixture();raw=self.valid_headers().encode('ascii');original_read=Path.read_text
        def no_header_text(path,*args,**kw):
            if path.suffix=='.headers':raise AssertionError('Header capture must never use text-mode reads')
            return original_read(path,*args,**kw)
        variants=[raw.replace(b'Content-Security-Policy:',b'X-Audit-Comment: public'+sep+b'Content-Security-Policy:')
                  for sep in ('\u0085'.encode('utf-8'),'\u2028'.encode('utf-8'),b'\r',b'\n')]
        variants.extend([raw.replace(b'\r\n',b'\n'),raw.replace(b'Content-Security-Policy:',b'X-Audit-Comment:')])
        for i,bad in enumerate(variants):
            out=self.root/('bad-capture-'+str(i));out.mkdir()
            def curl(args,**kw):
                Path(args[args.index('-D')+1]).write_bytes(bad)
                Path(args[args.index('-o')+1]).write_bytes(b'class="version">v0.6.0</span>')
                return '200'
            with self.subTest(case=i),patch.object(c,'docker',return_value=json.dumps([d])), \
                 patch.object(c,'image',return_value={'Config':expected}),patch.object(c,'command',side_effect=curl), \
                 patch.object(Path,'read_text',no_header_text),patch.object(c,'write') as writes:
                self.rejects('HTTP_HEADERS',lambda:c.runtime_check('public-container',out,self.rec,self.target['httpsURL']))
                writes.assert_not_called();self.assertFalse((out/'runtime.json').exists())


if __name__=='__main__':unittest.main()
