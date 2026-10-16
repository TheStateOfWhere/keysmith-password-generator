"""Synthetic artifacts only. Tests never invoke Docker, SSH or another process."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
spec=importlib.util.spec_from_file_location('verify_release',Path(__file__).resolve().parents[1]/'verify-release.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
from identity_fixture import fixture, write


class VerifyRelease(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for obj,name in ((subprocess,'run'),(subprocess,'Popen'),(subprocess,'check_output'),(socket,'socket')):
            guard=patch.object(obj,name,side_effect=AssertionError('External execution/network forbidden'))
            guard.start();self.addCleanup(guard.stop)
        self.paths={key:self.root/key for key in ('manifest','context','metadata','iid','inspection','archive')}
        self.source={'package.json':b'{"version":"0.6.0"}', 'Dockerfile':
            ('FROM node:24-alpine@sha256:'+'a'*64+' AS build\nFROM nginx:1-alpine@sha256:'+'b'*64+
             '\nLABEL org.opencontainers.image.version="0.6.0"\n').encode()}
        with tarfile.open(self.paths['context'],'w') as tar:
            for name,raw in self.source.items():
                m=tarfile.TarInfo(name);m.size=len(raw);m.mode=0o644;tar.addfile(m,io.BytesIO(raw))
        self.manifest={'schemaVersion':1,'sourceCommit':'c'*40,'contextSHA256':v.sha(self.paths['context'].read_bytes()),
            'version':'0.6.0','candidateTag':'passwordforge:0.6.0-candidate-public',
            'files':[{'path':name,'bytes':len(raw),'sha256':v.sha(raw),'mode':'0644'} for name,raw in self.source.items()]}
        labels={'org.opencontainers.image.title':'PasswordForge','org.opencontainers.image.version':'0.6.0',
                'org.opencontainers.image.revision':self.manifest['sourceCommit'],'org.passwordforge.source':self.manifest['contextSHA256']}
        metadata,inspected,configid,blobs=fixture(self.paths['archive'],labels=labels,attestation=True)
        root=json.loads(blobs['blobs/sha256/'+metadata['containerimage.digest'][7:]])
        rd=root['manifests'][0];runtime=json.loads(blobs['blobs/sha256/'+rd['digest'][7:]])
        config=json.loads(blobs['blobs/sha256/'+configid[7:]])
        config['config'].update(User='10001:10001',Entrypoint=['nginx'],Cmd=['-g','daemon off;'],ExposedPorts={'80/tcp':{},'8080/tcp':{}},
            Healthcheck={'Test':['CMD-SHELL','wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1'],
                         'Interval':30_000_000_000,'Timeout':3_000_000_000,'StartPeriod':10_000_000_000,'Retries':3})
        self.provenance={'invocation':{'configSource':{'digest':{'sha256':self.manifest['contextSHA256']},'entryPoint':'Dockerfile'},
                                      'environment':{'platform':'linux/amd64'}},
            'materials':[{'uri':'pkg:docker/'+name+'@public','digest':{'sha256':digit*64}} for name,digit in (('node','a'),('nginx','b'))]}
        self.blobs={}
        def blob(raw,media):
            if type(raw) is dict:raw=json.dumps(raw,separators=(',',':')).encode()
            identity='sha256:'+v.sha(raw);self.blobs['blobs/sha256/'+identity[7:]]=raw
            return {'mediaType':media,'digest':identity,'size':len(raw)}
        layer=runtime['layers'][0];self.blobs['blobs/sha256/'+layer['digest'][7:]]=blobs['blobs/sha256/'+layer['digest'][7:]]
        cd=blob(config,'application/vnd.oci.image.config.v1+json');runtime['config']=cd
        rd=dict(blob(runtime,'application/vnd.oci.image.manifest.v1+json'),platform={'os':'linux','architecture':'amd64'})
        ac=blob({},'application/vnd.oci.image.config.v1+json')
        al=blob({'_type':'https://in-toto.io/Statement/v0.1','predicateType':v.PROVENANCE,
                 'subject':[{'name':'public','digest':{'sha256':rd['digest'][7:]}}],'predicate':self.provenance},'application/vnd.in-toto+json')
        am=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':ac,'layers':[al]},'application/vnd.oci.image.manifest.v1+json')
        ad=dict(am,platform={'os':'unknown','architecture':'unknown'},annotations={'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':rd['digest']})
        export=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':[rd,ad]},'application/vnd.oci.image.index.v1+json')
        self.blobs['manifest.json']=json.dumps([{'Config':'blobs/sha256/'+cd['digest'][7:],'Layers':['blobs/sha256/'+layer['digest'][7:]]}]).encode()
        selected=dict(inspected,Id=rd['digest'],Descriptor=rd,Config=config['config'])
        native=dict(selected,Id=export['digest'],Descriptor=export,RepoTags=[self.manifest['candidateTag']])
        self.inspection={'native':native,'selected':selected}
        self.metadata={'containerimage.digest':export['digest'],'containerimage.descriptor':export,
            'containerimage.config.digest':cd['digest'],'image.name':self.manifest['candidateTag'],'buildx.build.provenance':self.provenance}
        self.configid=cd['digest'];self.layername='blobs/sha256/'+layer['digest'][7:];self.rootid=export['digest']
        self.save()

    def save(self):
        for key,value in (('manifest',self.manifest),('metadata',self.metadata),('inspection',self.inspection)):
            self.paths[key].write_bytes(json.dumps(value).encode())
        self.paths['iid'].write_text(self.metadata['containerimage.digest']+'\n')
        write(self.paths['archive'],self.blobs)

    def rebuild(self,config_change=None,runtime_change=None,statement_change=None,attestation_change=None):
        """Rehash a synthetic graph so policy tests do not merely trip stale hashes."""
        original=self.blobs
        read=lambda d:json.loads(original['blobs/sha256/'+d['digest'][7:]])
        root=read({'digest':self.rootid});rd,ad=root['manifests'];runtime=read(rd);config=read(runtime['config'])
        attestation=read(ad);statement=read(attestation['layers'][0])
        keep={runtime['layers'][0]['digest'],attestation['config']['digest']}
        self.blobs={'blobs/sha256/'+d[7:]:original['blobs/sha256/'+d[7:]] for d in keep}
        def blob(value,media):
            raw=json.dumps(value,separators=(',',':')).encode();d={'mediaType':media,'digest':'sha256:'+v.sha(raw),'size':len(raw)}
            self.blobs['blobs/sha256/'+d['digest'][7:]]=raw;return d
        if config_change:config_change(config)
        runtime['config']=blob(config,runtime['config']['mediaType'])
        if runtime_change:runtime_change(runtime)
        rd=dict(blob(runtime,runtime['mediaType']),platform=rd['platform'])
        statement['subject'][0]['digest']['sha256']=rd['digest'][7:]
        if statement_change:statement_change(statement)
        attestation['layers']=[blob(statement,'application/vnd.in-toto+json')]
        if attestation_change:attestation_change(attestation)
        ad=dict(blob(attestation,attestation['mediaType']),platform=ad['platform'],annotations={
            'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':rd['digest']})
        root['manifests']=[rd,ad];export=blob(root,root['mediaType']);self.rootid=export['digest']
        self.metadata.update(**{'containerimage.digest':self.rootid,'containerimage.descriptor':export,'containerimage.config.digest':runtime['config']['digest']})
        self.inspection['selected'].update(Id=rd['digest'],Descriptor=rd,Config=config['config'])
        self.inspection['native'].update(Id=self.rootid,Descriptor=export,Config=config['config'])
        self.blobs['manifest.json']=json.dumps([{'Config':'blobs/sha256/'+runtime['config']['digest'][7:],
            'Layers':['blobs/sha256/'+d['digest'][7:] for d in runtime['layers']]}]).encode()
        self.save()

    def cli(self,expected=None,argv=None):
        args=[]
        for key,path in self.paths.items():args+=['--'+key,str(path)]
        args+=['--manifest-sha256',v.sha(self.paths['manifest'].read_bytes()),'--expected-index-digest',self.rootid]
        before={k:p.read_bytes() for k,p in self.paths.items()}
        with contextlib.redirect_stdout(io.StringIO()) as out:status=v.main(args if argv is None else argv)
        result=json.loads(out.getvalue());self.assertEqual(result['status'],'FAIL' if expected else 'PASS')
        self.assertEqual(status,2 if expected else 0)
        if expected:self.assertEqual(result['code'],expected)
        self.assertEqual(before,{k:p.read_bytes() for k,p in self.paths.items()})
        return result,out.getvalue()

    def test_complete_artifacts_and_deterministic_result(self):
        result,raw=self.cli();self.assertEqual(self.cli()[1],raw)
        self.assertEqual(result['indexDigest'],self.rootid);self.assertEqual(result['configDigest'],self.configid)



    def image_entries(self, entries, first=False):
        # Real tar headers, parsed by the complete CLI; no validator replacement.
        with tarfile.open(self.paths['archive'],'w') as tar:
            def extra():
                for name,kind,size in entries:
                    m=tarfile.TarInfo(name);m.type=kind;m.size=size
                    m.mode=0o755 if kind==tarfile.DIRTYPE else 0o644
                    if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):m.linkname='/outside'
                    tar.addfile(m,io.BytesIO(bytes(size)))
            if first:extra()
            for name,raw in self.blobs.items():
                m=tarfile.TarInfo(name);m.size=len(raw);tar.addfile(m,io.BytesIO(raw))
            if not first:extra()

    def empty_attestation(self, change=None, statement_change=None, runtime_change=None):
        def configure(a):
            a['config']['mediaType']='application/vnd.oci.empty.v1+json'
            if change:change(a['config'])
        self.rebuild(attestation_change=configure,statement_change=statement_change,runtime_change=runtime_change)

    def test_authenticated_empty_attestation_configuration(self):
        self.empty_attestation();self.cli()

    def test_empty_attestation_wrong_digest(self):
        self.empty_attestation(lambda c:c.update(digest='sha256:'+'f'*64));self.cli('ATTESTATION_CONFIG')

    def test_empty_attestation_wrong_size(self):
        for size in (0,3,True,'2'):
            self.empty_attestation(lambda c:c.update(size=size));self.cli('ATTESTATION_CONFIG')

    def test_empty_attestation_nonempty_or_malformed_bytes(self):
        for raw in (b'{"x":1}',b'[]',b' { } ',b'{ ',b'{}\n'):
            self.empty_attestation()
            self.blobs['blobs/sha256/'+v.sha(b'{}')]=raw;self.save()
            self.cli('ATTESTATION_CONFIG')

    def test_empty_attestation_wrong_media_type(self):
        self.empty_attestation(lambda c:c.update(mediaType='application/vnd.oci.empty.v2+json'))
        self.cli('ATTESTATION_POLICY')

    def test_empty_attestation_missing_blob(self):
        self.empty_attestation();del self.blobs['blobs/sha256/'+v.sha(b'{}')];self.save()
        self.cli('ATTESTATION_CONFIG')

    def test_empty_configuration_cannot_replace_runtime(self):
        def runtime(m):m['config']['mediaType']='application/vnd.oci.empty.v1+json'
        self.empty_attestation(runtime_change=runtime);self.cli('MANIFEST_CONFIG')

    def test_empty_attestation_blob_cannot_be_runnable_config(self):
        def runtime(m):
            del self.blobs['blobs/sha256/'+m['config']['digest'][7:]]
            m['config']={'mediaType':'application/vnd.oci.empty.v1+json','digest':'sha256:'+v.sha(b'{}'),'size':2}
        self.empty_attestation(runtime_change=runtime);self.cli('SCHEMA_FIELD')

    def test_empty_attestation_wrong_subject(self):
        def statement(s):s['subject'][0]['digest']['sha256']='f'*64
        self.empty_attestation(statement_change=statement);self.cli('ATTESTATION_STATEMENT')

    def test_empty_attestation_wrong_source(self):
        def statement(s):s['predicate']['invocation']['configSource']['digest']['sha256']='f'*64
        self.empty_attestation(statement_change=statement);self.cli('SOURCE_PROVENANCE')

    def test_empty_attestation_missing_predicate(self):
        self.empty_attestation(statement_change=lambda s:s.pop('predicateType'));self.cli('ATTESTATION_POLICY')

    def test_empty_attestation_unauthenticated_manifest(self):
        self.empty_attestation()
        root=json.loads(self.blobs['blobs/sha256/'+self.rootid[7:]])
        name='blobs/sha256/'+root['manifests'][1]['digest'][7:]
        a=json.loads(self.blobs[name]);a['schemaVersion']=3
        self.blobs[name]=json.dumps(a,separators=(',',':')).encode();self.save()
        self.cli('DESCRIPTOR_HASH')

    def test_empty_attestation_incorrect_index_identification(self):
        self.empty_attestation()
        name='blobs/sha256/'+self.rootid[7:];root=json.loads(self.blobs[name])
        root['manifests'][1]['annotations']['vnd.docker.reference.digest']='sha256:'+'f'*64
        self.blobs[name]=json.dumps(root,separators=(',',':')).encode();self.save()
        self.cli('ATTESTATION_POLICY')

    def test_observed_empty_image_directories_accepted(self):
        for first in (False,True):
            for names in (('blobs','blobs/sha256'),('blobs/','blobs/sha256/')):
                with self.subTest(first=first,names=names):
                    self.image_entries([(n,tarfile.DIRTYPE,0) for n in names],first)
                    self.cli()

    def test_unexpected_and_unsafe_image_directories_rejected(self):
        for name in ('unexpected','blobs/other','blobs/sha256/extra','../blobs','/blobs','blobs/../other',
                     'blobs//sha256','blobs\\sha256','blobs/sha256/'+'f'*64):
            with self.subTest(name=name):
                self.image_entries([(name,tarfile.DIRTYPE,0)])
                self.cli('ARCHIVE_TYPE')

    def test_nonempty_image_directories_rejected(self):
        for name in ('blobs','blobs/sha256'):
            self.image_entries([(name,tarfile.DIRTYPE,1)])
            self.cli('ARCHIVE_TYPE')

    def test_duplicate_directory_aliases_rejected(self):
        for name in ('blobs','blobs/sha256'):
            self.image_entries([(name,tarfile.DIRTYPE,0),(name+'/',tarfile.DIRTYPE,0)])
            self.cli('ARCHIVE_MEMBERS')

    def test_image_directory_file_collisions_rejected(self):
        for first in (False,True):
            for name in ('blobs','blobs/sha256'):
                with self.subTest(first=first,name=name):
                    self.image_entries([(name,tarfile.REGTYPE,0)],first)
                    self.cli('ARCHIVE_PATH')
        self.image_entries([('blobs',tarfile.DIRTYPE,0),('blobs',tarfile.REGTYPE,0)])
        self.cli('ARCHIVE_MEMBERS')

    def test_expected_directory_names_cannot_be_links_or_special_files(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.CHRTYPE,tarfile.BLKTYPE,tarfile.FIFOTYPE):
            for name in ('blobs','blobs/sha256'):
                with self.subTest(kind=kind,name=name):
                    self.image_entries([(name,kind,0)])
                    self.cli('ARCHIVE_TYPE')

    def test_statement_v1_with_slsa02_accepted(self):
        self.rebuild(statement_change=lambda s:s.update(_type='https://in-toto.io/Statement/v1'))
        self.cli()

    def test_unapproved_statement_types_and_predicates_rejected(self):
        for kind in ('https://in-toto.io/Statement/v2','https://in-toto.io/Statement/v0.2','http://in-toto.io/Statement/v1','',None):
            with self.subTest(kind=kind):
                self.rebuild(statement_change=lambda s:s.update(_type=kind))
                self.cli('ATTESTATION_POLICY')
        for predicate in ('https://slsa.dev/provenance/v1','https://slsa.dev/provenance/v0.1','',None):
            with self.subTest(predicate=predicate):
                self.rebuild(statement_change=lambda s:s.update(_type='https://in-toto.io/Statement/v1',predicateType=predicate))
                self.cli('ATTESTATION_POLICY')

    def test_missing_statement_type_rejected(self):
        self.rebuild(statement_change=lambda s:s.pop('_type'))
        self.cli('ATTESTATION_POLICY')

    def test_statement_v1_missing_subject_rejected(self):
        def change(s):s['_type']='https://in-toto.io/Statement/v1';s.pop('subject')
        self.rebuild(statement_change=change);self.cli('SCHEMA_FIELD')

    def test_statement_v1_empty_subject_rejected(self):
        self.rebuild(statement_change=lambda s:s.update(_type='https://in-toto.io/Statement/v1',subject=[]))
        self.cli('ATTESTATION_STATEMENT')

    def test_statement_v1_mismatched_subject_rejected(self):
        def change(s):s['_type']='https://in-toto.io/Statement/v1';s['subject'][0]['digest']['sha256']='f'*64
        self.rebuild(statement_change=change);self.cli('ATTESTATION_STATEMENT')

    def test_statement_v1_missing_source_digest_rejected(self):
        def change(s):
            s['_type']='https://in-toto.io/Statement/v1'
            s['predicate']['invocation']['configSource'].pop('digest')
        self.rebuild(statement_change=change);self.cli('SCHEMA_FIELD')

    def test_statement_v1_incorrect_source_digest_rejected(self):
        def change(s):
            s['_type']='https://in-toto.io/Statement/v1'
            s['predicate']['invocation']['configSource']['digest']['sha256']='f'*64
        self.rebuild(statement_change=change);self.cli('SOURCE_PROVENANCE')

    def test_root_working_directory_accepted(self):
        self.rebuild(config_change=lambda c:c['config'].update(WorkingDir='/'))
        self.cli()

    def test_unexpected_working_directories_rejected(self):
        for directory in ('/tmp','/app','//','.','/../',[],0):
            with self.subTest(directory=directory):
                self.rebuild(config_change=lambda c:c['config'].update(WorkingDir=directory))
                self.cli('RUNTIME_CONFIG')

    def test_observed_docker_format_combination_accepted(self):
        self.rebuild(config_change=lambda c:c['config'].update(WorkingDir='/'),
                     statement_change=lambda s:s.update(_type='https://in-toto.io/Statement/v1'))
        self.image_entries([('blobs/',tarfile.DIRTYPE,0),('blobs/sha256/',tarfile.DIRTYPE,0)],first=True)
        self.cli()

    def reject_before_transport_reader(self, code):
        with patch.object(v,'archive_config',side_effect=AssertionError('Untrusted transport references followed')) as reader:
            self.cli(code)
        reader.assert_not_called()

    def replace_layer_payload(self, raw):
        old=self.layername;identity='sha256:'+v.sha(raw);name='blobs/sha256/'+identity[7:]
        def change_runtime(runtime):
            runtime['layers'][0].update(digest=identity,size=len(raw),mediaType='application/vnd.oci.image.layer.v1.tar')
            self.blobs.pop(old);self.blobs[name]=raw
        self.rebuild(config_change=lambda c:c['rootfs'].update(diff_ids=[identity]),runtime_change=change_runtime)
        self.inspection['selected']['RootFS']['Layers'][:]=[identity]
        self.layername=name;self.save()

    def test_substituted_config_payload_rejected_before_shared_parser(self):
        for encoding,depth in (('utf-16-le',800),('utf-8',800),('utf-8',1)):
            with self.subTest(encoding=encoding,depth=depth):
                payload=('{"os":"linux","architecture":"amd64","rootfs":{"diff_ids":[]},"guard":"quote\\\"","extra":'
                         +'['*depth+'0'+']'*depth+'}').encode(encoding)
                self.replace_layer_payload(payload)
                legacy=json.loads(self.blobs['manifest.json']);legacy[0]['Config']=self.layername
                self.blobs['manifest.json']=json.dumps(legacy).encode();self.save()
                self.reject_before_transport_reader('ARCHIVE_CONFIG_PATH')

    def test_missing_config_reference_rejected_before_reader(self):
        legacy=json.loads(self.blobs['manifest.json']);del legacy[0]['Config']
        self.blobs['manifest.json']=json.dumps(legacy).encode();self.save()
        self.reject_before_transport_reader('SCHEMA_FIELD')

    def test_duplicate_config_key_rejected_before_reader(self):
        legacy=json.loads(self.blobs['manifest.json'])[0]
        self.blobs['manifest.json']=('[{"Config":'+json.dumps(legacy['Config'])+',"Config":'+json.dumps(self.layername)
                                     +',"Layers":'+json.dumps(legacy['Layers'])+'}]').encode();self.save()
        self.reject_before_transport_reader('JSON_DUPLICATE')

    def test_conflicting_runtime_entries_rejected_before_reader(self):
        legacy=json.loads(self.blobs['manifest.json']);legacy.append(dict(legacy[0],Config=self.layername))
        self.blobs['manifest.json']=json.dumps(legacy).encode();self.save()
        self.reject_before_transport_reader('ARCHIVE_RUNTIME')

    def test_missing_runtime_entry_rejected_before_reader(self):
        self.blobs['manifest.json']=b'[]';self.save()
        self.reject_before_transport_reader('ARCHIVE_RUNTIME')

    def test_nonstring_config_reference_rejected_before_reader(self):
        legacy=json.loads(self.blobs['manifest.json']);legacy[0]['Config']=[legacy[0]['Config'],self.layername]
        self.blobs['manifest.json']=json.dumps(legacy).encode();self.save()
        self.reject_before_transport_reader('SCHEMA_FIELD')

    def test_missing_layers_field_rejected_before_reader(self):
        legacy=json.loads(self.blobs['manifest.json']);del legacy[0]['Layers']
        self.blobs['manifest.json']=json.dumps(legacy).encode();self.save()
        self.reject_before_transport_reader('SCHEMA_FIELD')

    def test_missing_duplicate_substituted_and_unsafe_layers_rejected_before_reader(self):
        original=json.loads(self.blobs['manifest.json'])
        for layers in ([],[self.layername,self.layername],['blobs/sha256/'+'f'*64],['../outside'],[None],
                       [original[0]['Config']]):
            with self.subTest(layers=layers):
                legacy=copy.deepcopy(original);legacy[0]['Layers']=layers
                self.blobs['manifest.json']=json.dumps(legacy).encode();self.save()
                self.reject_before_transport_reader('ARCHIVE_LAYER_BINDING')

    def test_reordered_layers_rejected_before_reader(self):
        raw=b'second synthetic layer';identity='sha256:'+v.sha(raw)
        def append_layer(runtime):
            runtime['layers'].append({'digest':identity,'size':len(raw),'mediaType':'application/vnd.oci.image.layer.v1.tar'})
            self.blobs['blobs/sha256/'+identity[7:]]=raw
        self.rebuild(config_change=lambda c:c['rootfs']['diff_ids'].append(identity),runtime_change=append_layer)
        self.inspection['selected']['RootFS']['Layers'].append(identity);self.save()
        self.cli()  # The two-layer authenticated mapping is valid before reordering.
        legacy=json.loads(self.blobs['manifest.json']);legacy[0]['Layers'].reverse()
        self.blobs['manifest.json']=json.dumps(legacy).encode();self.save()
        self.reject_before_transport_reader('ARCHIVE_LAYER_BINDING')

    def test_duplicate_graph_layers_rejected_before_reader(self):
        self.rebuild(config_change=lambda c:c['rootfs']['diff_ids'].append(c['rootfs']['diff_ids'][0]),
                     runtime_change=lambda r:r['layers'].append(copy.deepcopy(r['layers'][0])))
        self.inspection['selected']['RootFS']['Layers'].append(self.inspection['selected']['RootFS']['Layers'][0]);self.save()
        self.reject_before_transport_reader('ARCHIVE_LAYER_BINDING')

    def test_authenticated_config_guard_precedes_shared_readers(self):
        name='blobs/sha256/'+self.configid[7:];original=self.blobs[name]
        for payload,code in ((original.decode().encode('utf-16-le'),'JSON_ENCODING'),
                             (b'['*65+b'0'+b']'*65,'INPUT_LIMIT'),
                             (b' '* (v.JSON_MAX+1),'INPUT_LIMIT')):
            with self.subTest(code=code,size=len(payload)):
                self.blobs[name]=payload;self.save();self.reject_before_transport_reader(code)

    def test_graph_authentication_precedes_transport_reader(self):
        self.blobs['blobs/sha256/'+self.configid[7:]]+=b' ';self.save()
        self.reject_before_transport_reader('DESCRIPTOR_HASH')

    def test_valid_mapping_authenticates_graph_before_transport_reader(self):
        events=[];graph=v.verify_graph;reader=v.archive_config
        def verified(*args):
            result=graph(*args);events.append('graph authenticated');return result
        def transport(*args):
            self.assertEqual(events,['graph authenticated']);events.append('transport read');return reader(*args)
        with patch.object(v,'verify_graph',side_effect=verified),patch.object(v,'archive_config',side_effect=transport):
            self.cli()
        self.assertEqual(events,['graph authenticated','transport read'])

    def test_wrong_source_commit_label(self):
        self.manifest['sourceCommit']='d'*40;self.save();self.cli('IMAGE_LABELS')

    def test_wrong_frozen_source_hash(self):
        self.manifest['contextSHA256']='d'*64;self.save();self.cli('SOURCE_CONTEXT')

    def test_source_file_inventory_mismatch(self):
        self.manifest['files'][0]['sha256']='d'*64;self.save();self.cli('SOURCE_FILE')

    def test_wrong_iid(self):
        self.paths['iid'].write_text(self.configid);self.cli('BUILD_IDENTITY')

    def test_index_substitution(self):
        self.inspection['native']['Id']='sha256:'+'f'*64;self.save();self.cli('BUILD_IDENTITY')

    def test_selected_manifest_mismatch(self):
        self.inspection['selected']['Descriptor']['digest']='sha256:'+'f'*64;self.save();self.cli('PLATFORM_IDENTITY')

    def test_config_digest_mismatch(self):
        self.metadata['containerimage.config.digest']='sha256:'+'f'*64;self.save();self.cli('BUILD_CONFIG')

    def test_layer_hash_mismatch(self):
        self.blobs[self.layername]=b'changed layer bytes';self.save();self.cli('LAYER_MEMBER')

    def test_layer_size_mismatch(self):
        self.blobs[self.layername]+=b'X';self.save();self.cli('LAYER_MEMBER')

    def test_required_attestation_missing(self):
        root=json.loads(self.blobs['blobs/sha256/'+self.rootid[7:]]);root['manifests']=root['manifests'][:1]
        self.blobs['blobs/sha256/'+self.rootid[7:]]=json.dumps(root).encode();self.save();self.cli('ATTESTATION_POLICY')

    def test_unexpected_platform(self):
        self.inspection['selected']['Architecture']='arm64';self.save();self.cli('PLATFORM')

    def test_missing_metadata(self):
        self.paths['metadata'].unlink()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            args=sum((['--'+k,str(p)] for k,p in self.paths.items()),[])+['--manifest-sha256',v.sha(self.paths['manifest'].read_bytes()),'--expected-index-digest',self.rootid]
            self.assertEqual(v.main(args),2)
        self.assertEqual(json.loads(out.getvalue())['code'],'ARTIFACT_FORMAT_OR_IO')

    def test_malformed_metadata(self):
        self.paths['metadata'].write_bytes(b'{bad');self.cli('ARTIFACT_FORMAT_OR_IO')

    def test_duplicate_metadata_fields(self):
        self.paths['metadata'].write_bytes(b'{"a":1,"a":2}');self.cli('JSON_DUPLICATE')

    def test_traversal_archive_member(self):
        self.blobs['../outside']=b'public';self.save();self.cli('ARCHIVE_PATH')

    def test_symlink_archive_member(self):
        with tarfile.open(self.paths['archive'],'a') as tar:
            m=tarfile.TarInfo('link');m.type=tarfile.SYMTYPE;m.linkname='/public';tar.addfile(m)
        self.cli('ARCHIVE_TYPE')

    def test_duplicate_archive_member(self):
        with tarfile.open(self.paths['archive'],'a') as tar:
            m=tarfile.TarInfo('manifest.json');m.size=2;tar.addfile(m,io.BytesIO(b'[]'))
        self.cli('ARCHIVE_MEMBERS')

    def test_oversized_metadata(self):
        self.paths['metadata'].write_bytes(b' '* (v.JSON_MAX+1));self.cli('INPUT_LIMIT')

    def test_deep_json(self):
        self.paths['metadata'].write_bytes(b'['*65+b'0'+b']'*65);self.cli('INPUT_LIMIT')


    def metadata_json(self, depth=2, objects=False, guard='escaped"quote'):
        # The outer metadata object contributes one level to the limit.
        opened,closed = ('{"nested":','}') if objects else ('[',']')
        nested=opened*(depth-1)+'0'+closed*(depth-1)
        return json.dumps(self.metadata,ensure_ascii=False)[:-1]+',"guard":'+json.dumps(guard,ensure_ascii=False)+',"extra":'+nested+'}'

    def test_utf8_valid_metadata_with_non_ascii_strings(self):
        self.paths['metadata'].write_bytes(self.metadata_json(guard='café 漢字 🔒').encode('utf-8'))
        self.cli()

    def test_utf8_exact_depth_limit_arrays_and_objects(self):
        for objects in (False,True):
            with self.subTest(objects=objects):
                self.paths['metadata'].write_bytes(self.metadata_json(64,objects).encode('utf-8'))
                self.cli()

    def test_utf8_one_beyond_depth_limit_arrays_and_objects(self):
        for objects in (False,True):
            with self.subTest(objects=objects):
                self.paths['metadata'].write_bytes(self.metadata_json(65,objects).encode('utf-8'))
                self.cli('INPUT_LIMIT')

    def test_utf16_utf32_original_escaped_quote_bypasses_rejected(self):
        for encoding in ('utf-16-le','utf-16-be','utf-32-le','utf-32-be'):
            for depth in (70,800):
                with self.subTest(encoding=encoding,depth=depth):
                    self.paths['metadata'].write_bytes(self.metadata_json(depth).encode(encoding))
                    self.cli('JSON_ENCODING')

    def test_utf16_utf32_shallow_inputs_rejected(self):
        for encoding in ('utf-16-le','utf-16-be','utf-32-le','utf-32-be'):
            with self.subTest(encoding=encoding):
                self.paths['metadata'].write_bytes(self.metadata_json().encode(encoding))
                self.cli('JSON_ENCODING')

    def test_bom_inputs_rejected_with_stable_code(self):
        for bom,encoding in ((b'\xef\xbb\xbf','utf-8'),(b'\xff\xfe','utf-16-le'),
                             (b'\xfe\xff','utf-16-be'),(b'\xff\xfe\x00\x00','utf-32-le'),
                             (b'\x00\x00\xfe\xff','utf-32-be')):
            with self.subTest(encoding=encoding):
                self.paths['metadata'].write_bytes(bom+self.metadata_json().encode(encoding))
                self.assertEqual(self.cli('JSON_ENCODING')[1],self.cli('JSON_ENCODING')[1])

    def test_malformed_utf8_rejected(self):
        for bad in (b'\xff',b'\xc0\xaf',b'\xed\xa0\x80',b'\xf0\x9f',b'\x80'):
            with self.subTest(bad=bad):
                raw=self.metadata_json().encode('utf-8')[:-1]+b',"bad":"'+bad+b'"}'
                self.paths['metadata'].write_bytes(raw)
                self.cli('JSON_ENCODING')

    def test_escaped_quote_and_backslash_parity_preserve_depth_guard(self):
        for count in range(7):
            for guard in ('\\'*count+'"', '\\'*count):
                with self.subTest(count=count,guard=guard):
                    self.paths['metadata'].write_bytes(self.metadata_json(64,guard=guard).encode('utf-8'))
                    self.cli()
                    self.paths['metadata'].write_bytes(self.metadata_json(70,guard=guard).encode('utf-8'))
                    self.cli('INPUT_LIMIT')

    def test_string_brackets_and_braces_do_not_count_as_nesting(self):
        self.paths['metadata'].write_bytes(self.metadata_json(64,guard='[{"'*100+'}[]'*100).encode('utf-8'))
        self.cli()

    def test_deep_utf8_arrays_and_objects_rejected(self):
        for objects in (False,True):
            self.paths['metadata'].write_bytes(self.metadata_json(800,objects).encode('utf-8'))
            self.cli('INPUT_LIMIT')

    def test_utf8_duplicate_keys_and_nonstandard_numbers_still_rejected(self):
        for suffix,code in ((',"duplicate":1,"duplicate":2}', 'JSON_DUPLICATE'),
                            (',"number":NaN}', 'JSON_CONSTANT'),
                            (',"number":Infinity}', 'JSON_CONSTANT'),
                            (',"number":-Infinity}', 'JSON_CONSTANT')):
            with self.subTest(code=code,suffix=suffix):
                self.paths['metadata'].write_bytes((self.metadata_json()[:-1]+suffix).encode('utf-8'))
                self.cli(code)

    def test_decoded_layer_bound(self):
        with patch.object(v,'DECODED_MAX',1):self.cli('INPUT_LIMIT')

    def test_substituted_source_manifest_checksum(self):
        args=sum((['--'+k,str(p)] for k,p in self.paths.items()),[])+['--manifest-sha256','0'*64,'--expected-index-digest',self.rootid]
        self.cli('MANIFEST_HASH',argv=args)

    def test_independent_expected_index_prevents_coherent_substitution(self):
        self.metadata['containerimage.digest']='sha256:'+'f'*64
        self.metadata['containerimage.descriptor']['digest']=self.metadata['containerimage.digest']
        self.inspection['native']['Id']=self.metadata['containerimage.digest']
        self.inspection['native']['Descriptor']=self.metadata['containerimage.descriptor']
        self.save();self.cli('EXPECTED_INDEX')

    def test_absent_index_trust_anchor_rejected(self):
        args=sum((['--'+k,str(p)] for k,p in self.paths.items()),[])+['--manifest-sha256',v.sha(self.paths['manifest'].read_bytes())]
        self.cli('ARGUMENTS',argv=args)

    def test_absolute_archive_path(self):
        self.blobs['/outside']=b'public';self.save();self.cli('ARCHIVE_PATH')

    def test_oversized_physical_extension_rejected_before_tarfile_parse(self):
        m=tarfile.TarInfo('pax');m.type=tarfile.XHDTYPE;m.size=5000
        self.paths['context'].write_bytes(m.tobuf()+bytes(5120)+bytes(1024))
        self.cli('INPUT_LIMIT')

    def test_trailing_archive_bytes_rejected(self):
        with self.paths['archive'].open('ab') as out:out.write(b'public trailing bytes')
        self.cli('ARCHIVE_FRAMING')

    def test_missing_attestation_blob(self):
        root=json.loads(self.blobs['blobs/sha256/'+self.rootid[7:]])
        del self.blobs['blobs/sha256/'+root['manifests'][1]['digest'][7:]]
        self.save();self.cli('ARTIFACT_FORMAT_OR_IO')

    def test_corrupted_root_blob(self):
        self.blobs['blobs/sha256/'+self.rootid[7:]]+=b' '
        self.save();self.cli('DESCRIPTOR_HASH')

    def test_native_and_selected_config_id_roles_are_distinct(self):
        self.inspection['selected']['Id']=self.configid;self.save()
        result,_=self.cli();self.assertEqual(result['configDigest'],self.configid)

    def test_wrong_runtime_capture(self):
        self.inspection['native']['Config']=copy.deepcopy(self.inspection['native']['Config'])
        self.inspection['native']['Config']['User']='0';self.save();self.cli('PLATFORM')

    def test_runtime_override_in_both_captures(self):
        self.inspection['native']['Config']['User']='0';self.save();self.cli('RUNTIME_CAPTURE')

    def test_missing_provenance_metadata(self):
        del self.metadata['buildx.build.provenance'];self.save();self.cli('SCHEMA_FIELD')

    def test_provenance_source_substitution(self):
        self.metadata['buildx.build.provenance']['invocation']['configSource']['digest']['sha256']='f'*64
        self.save();self.cli('SOURCE_PROVENANCE')

    def test_cli_missing_arguments_machine_readable(self):
        self.cli('ARGUMENTS',argv=[])

    def test_no_external_commands_or_network(self):
        self.cli()  # Every test has process/network entry points replaced with failing sentinels.

    def test_network_input_path_rejected_before_filesystem_access(self):
        from security import SecurityError
        with patch.object(Path,'absolute',side_effect=AssertionError('Network path must not be examined')):
            with self.assertRaises(SecurityError) as caught:v.snapshot('//server/share/file',self.root/'unused',128)
        self.assertEqual(caught.exception.code,'INPUT_PATH')

    def test_source_permission_mismatch(self):
        self.manifest['files'][0]['mode']='0755';self.save();self.cli('SOURCE_FILE')

    def test_source_manifest_traversal(self):
        self.manifest['files'][0]['path']='../outside';self.save();self.cli('ARCHIVE_PATH')

    def test_oversized_logical_archive_member(self):
        m=tarfile.TarInfo('blobs/sha256/'+'f'*64);m.size=v.ARCHIVE_MAX+1
        self.paths['archive'].write_bytes(m.tobuf()+bytes(1024));self.cli('INPUT_LIMIT')

    def test_authenticated_runtime_root_user_rejected(self):
        self.rebuild(config_change=lambda c:c['config'].update(User='0'))
        self.cli('RUNTIME_CONFIG')

    def test_authenticated_layer_descriptor_size_mismatch(self):
        self.rebuild(runtime_change=lambda r:r['layers'][0].update(size=r['layers'][0]['size']+1))
        self.cli('LAYER_MEMBER')

    def test_authenticated_attestation_subject_mismatch(self):
        self.rebuild(statement_change=lambda s:s['subject'][0]['digest'].update(sha256='f'*64))
        self.cli('ATTESTATION_STATEMENT')

    def test_authenticated_wrong_attestation_predicate(self):
        self.rebuild(statement_change=lambda s:s.update(predicateType='https://example.invalid/unsupported'))
        self.cli('ATTESTATION_POLICY')

    def test_sparse_tar_extension_rejected_before_parser(self):
        m=tarfile.TarInfo('sparse');m.type=tarfile.GNUTYPE_SPARSE;m.size=0
        self.paths['archive'].write_bytes(m.tobuf()+bytes(1024));self.cli('ARCHIVE_TYPE')


if __name__ == '__main__':unittest.main()
