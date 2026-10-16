"""Public fixtures and mocked Docker only. Never contacts any Docker host."""
import ast
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('docker_release',ROOT/'docker-release.py')
release=importlib.util.module_from_spec(spec); spec.loader.exec_module(release)
import evidence_schema as schema
import scan_contract as contract
from checks import database, isolation, hardening
from identity_fixture import fixture

def runtime_approval(directory, version='0.4.0'):
    from test_publication import approved
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'package.json').write_text(json.dumps({'version':version}))
    metadata=approved();metadata['releaseVersion']=version
    path=directory/'private-fixture.json';path.write_text(json.dumps(metadata))
    return path,release.sha(path)

class Fixtures(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.out=Path(self.tmp.name)
        self.target='sha256:'+'a'*64
        now=dt.datetime.now(dt.timezone.utc)
        self.db={'Version':2,'UpdatedAt':(now-dt.timedelta(hours=1)).isoformat(),'NextUpdate':(now+dt.timedelta(hours=2)).isoformat()}
        self.scan={'SchemaVersion':2,'ArtifactType':'container_image','Metadata':{'ImageID':self.target},
                   'Results':[{'Class':'os-pkgs','Target':'Alpine fixture','Packages':[{'Name':'nginx'}],'Vulnerabilities':[]}]}
        self.put('database-metadata.json',self.db); self.put('vulnerabilities.json',self.scan)
    def tearDown(self): self.tmp.cleanup()
    def put(self,name,value):
        p=self.out/name; p.write_text(json.dumps(value)); return p

class ScanTests(Fixtures):
    def test_empty_array_valid(self):
        counts,rows=release.scan_gate(self.out,self.target)
        self.assertEqual(sum(counts.values()),0); self.assertEqual(rows,[])
    def test_invalid_array_not_clean(self):
        for value in (False,True,'false','[]',None,0,{},[False]):
            with self.subTest(value=value),self.assertRaises(Exception):
                bad=copy.deepcopy(self.scan);bad['Results'][0]['Vulnerabilities']=value
                self.put('vulnerabilities.json',bad);release.scan_gate(self.out,self.target)
    def test_missing_array_rejected(self):
        del self.scan['Results'][0]['Vulnerabilities'];self.put('vulnerabilities.json',self.scan)
        with self.assertRaises(Exception): release.scan_gate(self.out,self.target)
    def test_required_fields_exact_types(self):
        for key,value in [('SchemaVersion',True),('SchemaVersion','2'),('Metadata',[]),('Results',False),('ArtifactType',False)]:
            bad=dict(self.scan,**{key:value})
            with self.subTest(key=key,value=value),self.assertRaises(Exception):schema.scan_schema(bad)
    def test_security_booleans_cannot_be_strings_or_numbers(self):
        good={'User':'1000:1000','ReadonlyRootfs':True,'Privileged':False,'Memory':1,'PidsLimit':128,'NanoCpus':1,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'PortBindings':None}
        schema.security_types(good)
        for key,values in [('ReadonlyRootfs',['false','true',0,1,None]),('Privileged',['false',0]),('Memory',[True,'1']),('PidsLimit',[128.0]),('CapDrop',['ALL']),('PortBindings',[False,[]])]:
            for value in values:
                with self.subTest(key=key,value=value),self.assertRaises(Exception):schema.security_types(dict(good,**{key:value}))
    def test_required_result_fields(self):
        for key in ('Class','Target','Packages','Vulnerabilities'):
            bad=copy.deepcopy(self.scan);del bad['Results'][0][key]
            with self.subTest(key=key),self.assertRaises(Exception):schema.scan_schema(bad)
    def test_finding_types(self):
        good={'Severity':'HIGH','PkgName':'fixture','VulnerabilityID':'CVE-TEST','InstalledVersion':'1','FixedVersion':'2'}
        for key in good:
            for value in (False,None,0,[],{}):
                bad=copy.deepcopy(self.scan);bad['Results'][0]['Vulnerabilities']=[dict(good,**{key:value})]
                with self.subTest(key=key,value=value),self.assertRaises(Exception):schema.scan_schema(bad)
    def test_bad_json_duplicate_nan_empty(self):
        for raw in ('{','', '{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(raw=raw),self.assertRaises(Exception):schema.strict_json(raw)
    def test_severity_threshold_and_fixes(self):
        for severity in ('HIGH','CRITICAL','UNKNOWN','MEDIUM','LOW'):
            self.scan['Results'][0]['Vulnerabilities']=[{'Severity':severity,'PkgName':'fixture','VulnerabilityID':'CVE-TEST','InstalledVersion':'1','FixedVersion':'2'}]
            self.put('vulnerabilities.json',self.scan)
            counts,rows=release.scan_results(self.out,self.target)
            self.assertEqual(counts[severity],1);self.assertEqual(rows[0]['FixedVersion'],'2')
            if severity in ('HIGH','CRITICAL','UNKNOWN'):
                with self.assertRaises(Exception):release.scan_gate(self.out,self.target)
            else:release.scan_gate(self.out,self.target)
    def test_identity_mismatch(self):
        with self.assertRaises(Exception):release.scan_gate(self.out,'sha256:'+'b'*64)
    def test_missing_os_inventory(self):
        self.scan['Results'][0]['Packages']=[];self.put('vulnerabilities.json',self.scan)
        with self.assertRaises(Exception):release.scan_gate(self.out,self.target)
    def test_stale_or_wrong_database(self):
        now=dt.datetime.now(dt.timezone.utc)
        for key,value in [('Version',True),('Version','2'),('Version',1),('UpdatedAt',(now-dt.timedelta(hours=49)).isoformat()),('UpdatedAt',(now+dt.timedelta(hours=1)).isoformat()),('NextUpdate',(now-dt.timedelta(hours=1)).isoformat())]:
            with self.subTest(key=key,value=value),self.assertRaises(Exception):database(self.put('bad-db.json',dict(self.db,**{key:value})))
    def test_two_passes_allow_only_corroborated_omission(self):
        raw=copy.deepcopy(self.scan);del raw['Results'][0]['Vulnerabilities']
        contract.combine(self.put('native.json',raw),self.put('explicit.json',self.scan['Results']),self.out/'canonical.json')
        self.assertEqual(json.loads((self.out/'canonical.json').read_text())['Results'][0]['Vulnerabilities'],[])
        for value in (False,'false',None):
            raw['Results'][0]['Vulnerabilities']=value
            with self.subTest(value=value),self.assertRaises(Exception):
                contract.combine(self.put('native.json',raw),self.out/'explicit.json',self.out/'rejected.json')
    def test_two_pass_inventory_difference_rejected(self):
        typed=copy.deepcopy(self.scan['Results']);typed[0]['Packages']=[{'Name':'other'}]
        with self.assertRaises(Exception):contract.combine(self.put('native.json',self.scan),self.put('explicit.json',typed),self.out/'canonical.json')

class WorkflowTests(Fixtures):
    def test_builder_driver_endpoint_and_node_validation(self):
        good='Name: default\nDriver: docker\nNodes:\nName: default\nEndpoint: unix:///var/run/docker.sock\nStatus: running\nPlatforms: linux/amd64\n'
        for value in (good,good.replace('Driver: docker','Driver: docker-container'),good.replace('unix:///var/run/docker.sock','ssh://other'),good.replace('linux/amd64','linux/arm64')):
            with patch.object(release.os,'name','posix'),patch.object(release.os,'getuid',return_value=1000,create=True),patch.object(release,'command',side_effect=['linux/amd64',value]):
                if value==good:release.builder()
                else:
                    with self.assertRaises(Exception):release.builder()
    def test_environment_cannot_redirect_builder_or_platform(self):
        with patch.dict(os.environ,{'DOCKER_HOST':'remote','DOCKER_CONTEXT':'other','DOCKER_DEFAULT_PLATFORM':'linux/arm64','BUILDX_BUILDER':'remote','BUILDKIT_HOST':'remote','COMPOSE_FILE':'production'}):
            env=release.environment()
            for key in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_DEFAULT_PLATFORM','BUILDX_BUILDER','BUILDKIT_HOST','COMPOSE_FILE'):self.assertNotIn(key,env)
    def test_amd64_optional_variant_only(self):
        good={'Id':self.target,'Os':'linux','Architecture':'amd64'}
        release.platform(good);release.platform(dict(good,Variant='v1'))
        for bad in (dict(good,Architecture='arm64'),dict(good,Os=None),dict(good,Architecture=None),dict(good,Architecture=1),dict(good,Variant='v8')):
            with self.assertRaises(Exception):release.platform(bad)
    def test_version_tag_validation(self):
        release.reference('passwordforge:0.4.0')
        for tag in ('passwordforge:latest','other:0.4.0','passwordforge:0.4.0;bad','passwordforge:'):
            with self.assertRaises(Exception):release.reference(tag)
    def test_collision_stops_before_build(self):
        with patch.object(release,'approval') as approval,patch.object(release,'protected'),patch.object(release,'builder'),patch.object(release,'load',return_value={'version':'0.4.0'}),patch.object(release,'command',return_value='passwordforge:0.4.0\n') as command:
            approval.return_value.identity={'version':'0.4.0'}
            with self.assertRaises(Exception):release.build('0.4.0')
            self.assertEqual(command.call_count,1)
    def test_build_invocation_and_identity(self):
        self.build_fixture(index=False)
    def test_build_config_and_manifest_ids_may_differ_but_must_bind(self):
        self.build_fixture(index=True)
    def build_fixture(self,index):
        (self.out/'Dockerfile').write_text((ROOT.parents[1]/'Dockerfile').read_text())
        (self.out/'package.json').write_text('{"version":"0.4.0"}')
        from test_approval_binding import approved_source,mode_observation
        source=self.out/'source';source.mkdir()
        shutil_copy=__import__('shutil').copyfile
        for n in ('Dockerfile','package.json'):shutil_copy(self.out/n,source/n)
        _,approval=approved_source(self.out,source=source)
        d={};calls=[];transport=self.out/'fixture.tar'
        def command(args,log=None,*_,**kwargs):
            calls.append(args)
            if log:
                Path(log).write_text('public mock build');Path(str(log)+'.status.json').write_text('{"exitCode":0,"timedOut":false}')
            if 'build' in args:
                self.assertEqual(args[-1],'-');self.assertEqual(kwargs['input_bytes'],approval.context)
                labels=dict(args[i+1].split('=',1) for i,x in enumerate(args) if x=='--label')
                labels['org.opencontainers.image.version']='0.4.0'
                metadata,actual,config_id,_=fixture(transport,labels,index=index,with_config=not index,attestation=index)
                d.update(actual)
                Path(args[args.index('--iidfile')+1]).write_text(d['Id'])
                Path(args[args.index('--metadata-file')+1]).write_text(json.dumps(metadata))
            if 'save' in args:Path(args[args.index('--output')+1]).write_bytes(transport.read_bytes())
            return ''
        with mode_observation(approval,source),patch.object(release,'APPROVAL',approval),patch.object(release,'protected'),patch.object(release,'SOURCE',source),patch.object(release,'builder'),patch.object(release,'source_hash',return_value='fingerprint'),patch.object(release,'image',return_value=d),patch.object(release,'cached_image',return_value=d),patch.object(release,'command',side_effect=command):
            release.build('0.4.0')
        built=next(args for args in calls if 'build' in args)
        self.assertEqual(built[built.index('--builder')+1],'default')
        self.assertEqual(built[built.index('--platform')+1],'linux/amd64')
        self.assertEqual(built[built.index('--tag')+1],'passwordforge:0.4.0');self.assertIn('--pull=false',built);self.assertNotIn('--pull',built)
        result=json.loads(next((source/'validation-results').glob('*/build.json')).read_text())
        self.assertEqual(result['imageIdKind'],'index' if index else 'config')
        self.assertNotEqual(result['configId'],result['manifestId'])
    def test_runtime_failure_never_publishes_success(self):
        record={'run':'20261010t190558z-ef9ece7212345678'}
        from test_approval_binding import approved_source,mode_observation
        source,bound=approved_source(self.out);approval=(bound.private,bound.checksum)
        record.update(approval=dict(bound.identity))
        d={'Id':self.target,'Config':{'Labels':{'org.opencontainers.image.version':'0.4.0'}}}
        with mode_observation(bound,source),patch.object(release,'APPROVAL',bound),patch.object(release,'protected'),patch.object(release,'SOURCE',source),patch.object(release,'passed_scan',return_value=(d,record)),patch.object(release,'command',side_effect=ValueError('failed runtime cleanup')):
            with self.assertRaises(ValueError):release.runtime('passwordforge:0.4.0',self.out,*approval)
        self.assertTrue((self.out/'runtime-started.json').exists());self.assertFalse((self.out/'runtime.json').exists())
    def test_command_failure_records_status_and_never_overwrites_log(self):
        p=subprocess.CompletedProcess([],7,b'public fixture',b'failure')
        with patch.object(release.subprocess,'run',return_value=p):
            with self.assertRaises(Exception):release.command(['mock'],self.out/'command.log')
            self.assertEqual(json.loads((self.out/'command.log.status.json').read_text()),{'exitCode':7,'timedOut':False})
            with self.assertRaises(FileExistsError):release.command(['mock'],self.out/'command.log')
    def test_timeout_keeps_failure_evidence(self):
        with patch.object(release.subprocess,'run',side_effect=subprocess.TimeoutExpired(['mock'],1,output=b'public fixture')):
            with self.assertRaises(Exception):release.command(['mock'],self.out/'timeout.log')
        self.assertTrue(json.loads((self.out/'timeout.log.status.json').read_text())['timedOut'])
    def test_lock_blocks_concurrency_and_preserves_stale_owner(self):
        with patch.object(release.Path,'home',return_value=self.out):
            with release.locked():
                with self.assertRaises(FileExistsError):
                    with release.locked():pass
            stale=self.out/'.cache/passwordforge-docker.lock';stale.mkdir();(stale/'owner.json').write_text('existing')
            with self.assertRaises(FileExistsError):
                with release.locked():pass
            self.assertEqual((stale/'owner.json').read_text(),'existing')
    def test_exclusive_results_preserve_interrupted_evidence(self):
        release.save(self.out/'scan-started.json',{'original':True})
        with self.assertRaises(FileExistsError):release.save(self.out/'scan-started.json',{})
        self.assertEqual(json.loads((self.out/'scan-started.json').read_text()),{'original':True})
    def test_failed_scan_prevents_runtime_commands(self):
        with patch.object(release,'passed_scan',side_effect=ValueError('failed')),patch.object(release,'command') as command:
            with self.assertRaises(ValueError):release.runtime('passwordforge:0.4.0',self.out)
            command.assert_not_called();self.assertFalse((self.out/'runtime-started.json').exists())
    def test_cleanup_rejects_foreign_resource(self):
        cid='c'*64
        with patch.object(release,'command',side_effect=[cid,json.dumps({'Id':cid,'Labels':{release.LABEL:'foreign'}})]) as command:
            with self.assertRaises(Exception):release.owned_remove(cid,'our-run')
            self.assertEqual(command.call_count,2)
    def test_cleanup_only_captured_owned_container(self):
        cid='c'*64
        with patch.object(release,'protected'),patch.object(release,'command',side_effect=[cid,json.dumps({'Id':cid,'Labels':{release.LABEL:'our-run'}}),'']) as command:
            release.owned_remove(cid,'our-run')
            self.assertEqual(command.call_args.args[0][-4:],['container','rm','-f',cid])
    def test_archive_runtime_config_bound_to_daemon_layers(self):
        layer=b'public layer fixture';diff='sha256:'+hashlib.sha256(layer).hexdigest()
        config={'os':'linux','architecture':'amd64','rootfs':{'diff_ids':[diff]}}
        raw=json.dumps(config).encode();archive=self.out/'image.tar'
        with tarfile.open(archive,'w') as tar:
            for name,data in [('manifest.json',b'[{"Config":"config.json","Layers":["layer.tar"]}]'),('config.json',raw),('layer.tar',layer)]:
                m=tarfile.TarInfo(name);m.size=len(data);tar.addfile(m,io.BytesIO(data))
        self.assertEqual(release.archive_config(archive,{'RootFS':{'Layers':[diff]}}),'sha256:'+hashlib.sha256(raw).hexdigest())
        with self.assertRaises(Exception):release.archive_config(archive,{'RootFS':{'Layers':[]}})
    def test_candidate_tag_change_or_source_change_fails(self):
        run='20261010t190558z-ef9ece7212345678'
        record={'image':'passwordforge:0.4.0','imageId':self.target,'run':run,'sourceSHA256':'original'}
        self.put('build.json',record)
        d={'Id':self.target,'Os':'linux','Architecture':'amd64','Config':{'Labels':{release.LABEL:run}}}
        for inspected,fingerprint in ((dict(d,Id='sha256:'+'b'*64),'original'),(d,'changed')):
            with patch.object(release,'image',return_value=inspected),patch.object(release,'source_hash',return_value=fingerprint),self.assertRaises(Exception):release.candidate(record['image'],self.out)
    def test_no_automatic_deploy_import_prune_or_network_creation(self):
        source=(ROOT/'docker-release.py').read_text()
        for token in ("'load'", "'push'", "'prune'", "'up'", "'down'", "'network','create'", "'volume','rm'"):
            self.assertNotIn(token,source)
        self.assertIn("'--builder','default','--platform','linux/amd64','--pull=false'",source)
        self.assertNotIn('/var/run/docker.sock,dst=',source)
    def test_no_security_asserts_in_new_code(self):
        for name in ('docker-release.py','security.py','checks.py','evidence_schema.py','scan_contract.py','builder_contract.py','build_identity.py'):
            self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(ast.parse((ROOT/name).read_text()))),name)

class ScannerExecutionTests(Fixtures):
    def mock_scan(self,cleanup_failure=False,scanner_failure=False,explicit_failure=False,log_issue=None):
        (self.out/'vulnerabilities.json').unlink()
        (self.out/'database-metadata.json').unlink()
        run='20261010t190558z-ef9ece7212345678'
        record={'run':run,'approval':{},'schemaVersion':1};config=json.dumps({'os':'linux','architecture':'amd64','rootfs':{'diff_ids':[]}}).encode()
        config_id='sha256:'+hashlib.sha256(config).hexdigest()
        record['configId']=config_id
        d={'Id':self.target,'Os':'linux','Architecture':'amd64','RootFS':{'Layers':[]}}
        native=copy.deepcopy(self.scan);native['Metadata']['ImageID']=config_id
        calls=[]; names={}
        def command(args,log=None,*_):
            calls.append(args)
            work=self.out/'scanner'
            if log:
                content='Version: 0.75.0' if Path(log).name=='version.log' else 'public fixture'
                if log_issue and Path(log).name==log_issue[0]+'.log':content+='\n'+log_issue[1]
                Path(log).write_text(content)
            if 'save' in args:
                archive=Path(args[args.index('--output')+1])
                with tarfile.open(archive,'w') as tar:
                    for name,raw in [('manifest.json',b'[{"Config":"config.json","Layers":[]}]'),('config.json',config)]:
                        member=tarfile.TarInfo(name);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
            if 'create' in args:
                cid=hashlib.sha256(args[args.index('--name')+1].encode()).hexdigest()
                names[cid]=args[args.index('--name')+1]
                return cid
            if 'start' in args:
                name=names[args[-1]]
                if name.endswith('-db'):
                    (work/'cache/db').mkdir();(work/'cache/db/trivy.db').write_bytes(b'public database fixture')
                    (work/'cache/db/metadata.json').write_text(json.dumps(self.db))
                if name.endswith('-native'):
                    (work/'output/native.json').write_text('{partial' if scanner_failure else json.dumps(native))
                    if scanner_failure:raise RuntimeError('mock scanner failed')
                if name.endswith('-explicit'):
                    (work/'output/explicit.json').write_text('{partial' if explicit_failure else json.dumps(native['Results']))
                    if explicit_failure:raise RuntimeError('mock explicit failed')
            if 'inspect' in args:return '0' if args[-2]=='{{.State.ExitCode}}' else '{}'
            return ''
        with patch.object(release,'protected'),patch.object(release,'candidate',return_value=(d,record)),patch.object(release,'command',side_effect=command),patch.object(release,'image',return_value=d),patch.object(release,'cached_image',return_value=d),patch.object(release.os,'getuid',return_value=1000,create=True),patch.object(release.os,'getgid',return_value=1000,create=True),patch.object(release,'isolation'),patch.object(release,'owned_remove',side_effect=RuntimeError('mock cleanup failed') if cleanup_failure else None):
            if log_issue:
                with self.assertRaises(release.SecurityError) as caught:release.scan('passwordforge:0.4.0',self.out)
                self.assertEqual(caught.exception.code,'SCANNER_LOG')
            elif cleanup_failure or scanner_failure or explicit_failure:
                with self.assertRaises(Exception):release.scan('passwordforge:0.4.0',self.out)
            else:release.scan('passwordforge:0.4.0',self.out)
        return calls
    def test_actual_scan_commands_bind_same_id_and_no_socket_or_proxy(self):
        calls=self.mock_scan()
        saved=next(c for c in calls if 'save' in c)
        self.assertEqual(saved[-1],self.target)
        self.assertFalse(any('pull' in c for c in calls))
        creates=[c for c in calls if 'create' in c]
        self.assertEqual(len(creates),4)
        for c in creates:
            self.assertEqual(c[c.index('--network')+1],'bridge' if c[c.index('--name')+1].endswith('-db') else 'none')
            self.assertEqual(c[c.index('--pull')+1],'never')
            self.assertIn('--read-only',c);self.assertIn('--cap-drop',c)
            self.assertNotIn('proxy',c);self.assertNotIn('/var/run/docker.sock,dst=', ' '.join(c))
        self.assertTrue((self.out/'scan.json').exists());self.assertFalse((self.out/'scanner').exists())
    def test_json_only_inventory_flag_and_full_coverage(self):
        calls=self.mock_scan()
        passes={c[c.index('--format')+1]:c for c in calls if 'create' in c and '--format' in c}
        native,explicit=passes['json'],passes['template']
        self.assertEqual(native.count('--list-all-pkgs'),1)
        self.assertNotIn('--list-all-pkgs',explicit)
        self.assertEqual(explicit[explicit.index('--template')+1],'@/input/scan-contract.tpl')
        for c in (native,explicit):
            self.assertEqual(c[c.index('--scanners')+1],'vuln')
            self.assertEqual(c[c.index('--pkg-types')+1],'os,library')
            self.assertEqual(c[c.index('--severity')+1],'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')
            self.assertEqual(c[c.index('--input')+1],'/input/image.tar')
            self.assertIn('--offline-scan',c);self.assertIn('--skip-db-update',c)
        canonical=json.loads((self.out/'vulnerabilities.json').read_text())
        self.assertEqual(canonical['Results'][0]['Packages'],self.scan['Results'][0]['Packages'])
    def reject_log(self,step,message):
        self.mock_scan(log_issue=(step,message))
        self.assertFalse((self.out/'scan.json').exists())
        self.assertTrue((self.out/'native.json').exists());self.assertTrue((self.out/'explicit.json').exists())
        self.assertIn(message,(self.out/(step+'.log')).read_text())
        self.assertFalse((self.out/'scanner').exists())
        with patch.object(release,'candidate',return_value=({}, {'configId':self.target})),self.assertRaises(FileNotFoundError):
            release.passed_scan('passwordforge:0.4.0',self.out)
    def test_unexpected_template_warning_blocks_success(self):
        self.reject_log('explicit','WARN unexpected scanner fixture warning')
    def test_known_format_warning_is_not_allowlisted(self):
        self.reject_log('explicit','WARN "--list-all-pkgs" is only valid for the JSON format, for other formats a list of packages is automatically included.')
    def test_native_warning_blocks_success(self):
        self.reject_log('native','WARN unexpected native warning')
    def test_scanner_error_blocks_success(self):
        self.reject_log('explicit','ERROR unexpected scanner error')
    def test_scanner_fatal_blocks_success(self):
        self.reject_log('db','FATAL unexpected database failure')
    def test_cleanup_failure_never_publishes_passed_scan(self):
        self.mock_scan(cleanup_failure=True)
        self.assertFalse((self.out/'scan.json').exists());self.assertTrue((self.out/'scan-findings.json').exists())
    def test_scanner_failure_never_publishes_passed_scan(self):
        self.mock_scan(scanner_failure=True)
        self.assertFalse((self.out/'scan.json').exists());self.assertTrue((self.out/'native.log').exists())
        self.assertEqual((self.out/'native.json').read_text(),'{partial')
    def test_later_scan_failure_preserves_both_available_outputs(self):
        self.mock_scan(explicit_failure=True)
        self.assertEqual(json.loads((self.out/'native.json').read_text())['SchemaVersion'],2)
        self.assertEqual((self.out/'explicit.json').read_text(),'{partial')
        self.assertFalse((self.out/'scan.json').exists())

if __name__=='__main__':unittest.main()
