"""Nonsecret OCI/Docker-save bytes for identity regression tests."""
import hashlib
import io
import json
import tarfile

def fixture(path, labels=None, index=True, with_config=True, attestation=False, platform=None):
    blobs={}
    def blob(value,media):
        raw=json.dumps(value,separators=(',',':')).encode() if type(value) is dict else value
        identity='sha256:'+hashlib.sha256(raw).hexdigest();blobs['blobs/sha256/'+identity[7:]]=raw
        return {'mediaType':media,'digest':identity,'size':len(raw)}
    conf_media='application/vnd.oci.image.config.v1+json';man_media='application/vnd.oci.image.manifest.v1+json'
    layer=blob(b'public nonsecret layer','application/vnd.oci.image.layer.v1.tar')
    config=blob({'os':'linux','architecture':'amd64','rootfs':{'type':'layers','diff_ids':[layer['digest']]},'config':{'Labels':labels or {}}},conf_media)
    runtime=blob({'schemaVersion':2,'mediaType':man_media,'config':config,'layers':[layer]},man_media)
    desc=dict(runtime,platform=platform or {'os':'linux','architecture':'amd64'})
    descriptors=[desc]
    if attestation:
        ac=blob({},conf_media);al=blob({'predicateType':'https://slsa.dev/provenance/v0.2','subject':[{'name':'public-fixture','digest':{'sha256':runtime['digest'][7:]}}]},'application/vnd.in-toto+json')
        am=blob({'schemaVersion':2,'mediaType':man_media,'config':ac,'layers':[al]},man_media)
        descriptors.append(dict(am,platform={'os':'unknown','architecture':'unknown'},annotations={
            'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':runtime['digest']}))
    export=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':descriptors},'application/vnd.oci.image.index.v1+json') if index else runtime
    blobs['manifest.json']=json.dumps([{'Config':'blobs/sha256/'+config['digest'][7:],'Layers':['blobs/sha256/'+layer['digest'][7:]]}]).encode()
    metadata={'containerimage.digest':export['digest'],'containerimage.descriptor':export,'buildx.build.provenance':{}}
    if with_config:metadata['containerimage.config.digest']=config['digest']
    inspected={'Id':export['digest'] if index else config['digest'],'Os':'linux','Architecture':'amd64',
               'RootFS':{'Layers':[layer['digest']]},'Config':{'Labels':labels or {}}}
    write(path,blobs)
    return metadata,inspected,config['digest'],blobs

def write(path,blobs):
    with tarfile.open(path,'w') as tar:
        for name,raw in blobs.items():
            m=tarfile.TarInfo(name);m.size=len(raw);tar.addfile(m,io.BytesIO(raw))
