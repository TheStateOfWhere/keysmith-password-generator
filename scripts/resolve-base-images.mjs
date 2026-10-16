import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
const results = [];
const accepted = ['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json','application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'].join(', ');
for(const [repository,tag] of [['node','24-alpine'],['nginx','stable-alpine']]) {
  const authResponse=await fetch(`https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/${repository}:pull`);
  if(!authResponse.ok) throw new Error(`Anonymous registry authentication failed: HTTP ${authResponse.status}`);
  const {token}=await authResponse.json();
  async function manifest(reference) {
    const response=await fetch(`https://registry-1.docker.io/v2/library/${repository}/manifests/${reference}`,{headers:{Authorization:`Bearer ${token}`,Accept:accepted}});
    if(!response.ok) throw new Error(`Manifest resolution failed for ${repository}:${tag}: HTTP ${response.status}`);
    const bytes=Buffer.from(await response.arrayBuffer());
    const computed='sha256:'+createHash('sha256').update(bytes).digest('hex');
    const reported=response.headers.get('docker-content-digest');
    if(reported && reported!==computed) throw new Error('Registry digest verification failed');
    return {digest:computed,json:JSON.parse(bytes),mediaType:response.headers.get('content-type')};
  }
  const index=await manifest(tag);
  const platforms=[];
  for(const architecture of ['amd64','arm64']) {
    const selected=index.json.manifests?.find(item=>item.platform?.os==='linux' && item.platform?.architecture===architecture);
    if(!selected) continue;
    const child=await manifest(selected.digest);
    if(child.digest!==selected.digest) throw new Error('Platform digest verification failed');
    const configResponse=await fetch(`https://registry-1.docker.io/v2/library/${repository}/blobs/${child.json.config.digest}`,{headers:{Authorization:`Bearer ${token}`}});
    if(!configResponse.ok) throw new Error('Image configuration lookup failed');
    const configBytes=Buffer.from(await configResponse.arrayBuffer());
    if('sha256:'+createHash('sha256').update(configBytes).digest('hex')!==child.json.config.digest) throw new Error('Configuration digest verification failed');
    const config=JSON.parse(configBytes);
    const env=config.config?.Env || [];
    platforms.push({os:'linux',architecture,variant:selected.platform.variant||null,manifestDigest:child.digest,configDigest:child.json.config.digest,applicationVersion:env.find(value=>value.startsWith(repository==='node'?'NODE_VERSION=':'NGINX_VERSION='))?.split('=')[1]||null});
  }
  const exactTag=platforms[0].applicationVersion+'-alpine';
  const exactIndex=await manifest(exactTag);
  const releaseTag=exactIndex.digest===index.digest ? exactTag : tag;
  results.push({exactVersionTag:exactTag,exactVersionTagDigest:exactIndex.digest,repository:`docker.io/library/${repository}`,sourceTag:tag,indexDigest:index.digest,pinnedReference:`${repository}:${releaseTag}@${index.digest}`,platforms});
}
const record={resolvedAtUTC:new Date().toISOString(),registry:'https://registry-1.docker.io',verification:'SHA-256 computed from fetched index, platform manifest and configuration bytes; registry digest headers checked.',images:results};
await writeFile('BASE-IMAGES.json',JSON.stringify(record,null,2)+'\n');
console.log(JSON.stringify(record,null,2));