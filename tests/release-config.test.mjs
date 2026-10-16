import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { screenshotDirectory } from './browser-artifacts.mjs';
const read = name => readFile(new URL('../'+name,import.meta.url),'utf8');

test('production Compose is image-only and retains generic routing and hardening', async () => {
  const prod = await read('compose.yaml'), dev = await read('compose.dev.yaml');
  assert.doesNotMatch(prod,/^\s+(build|ports):/m);
  assert.match(prod,/pull_policy: never/);
  assert.match(prod,/image: passwordforge:\$\{PASSWORDFORGE_TAG:-1\.0\.0\}/);
  assert.match(prod,/Host\(`password\.example\.invalid`\)/);
  assert.match(prod,/traefik\.docker\.network: proxy/);
  assert.match(prod,/entrypoints: websecure/);
  assert.match(prod,/tls: \"true\"/);
  assert.match(prod,/server\.port: \"8080\"/);
  assert.match(dev,/build:\n\s+context: \./);
  assert.match(dev,/127\.0\.0\.1:18080:8080/);
  assert.match(dev,/network_mode: bridge/);
  assert.doesNotMatch(dev,/traefik|proxy|container_name/);
  assert.match(prod,/^    cpus: 1\.0$/m);
  for (const config of [prod,dev]) assert.match(config,/^    platform: linux\/amd64$/m);
  for (const config of [prod,dev]) for (const field of ['user: "10001:10001"','read_only: true','no-new-privileges:true','pids_limit: 128','mem_limit: 128m','/tmp:rw,noexec,nosuid,size=16m,mode=1777','start_period: 10s','retries: 3']) assert.ok(config.includes(field),field);
});

test('browser screenshots stay in separate ignored per-run directories', async () => {
  const first = await screenshotDirectory('fixture'), second = await screenshotDirectory('fixture');
  assert.notEqual(first('one.png'),second('one.png'));
  assert.match(first('one.png'),/artifacts[\\/]browser[\\/]/);
  assert.throws(()=>first('../escape.png')); assert.throws(()=>first('UPPER.png'));
  assert.match(await read('.gitignore'),/artifacts\//);
  const build = await read('scripts/build.mjs');
  assert.doesNotMatch(build,/browser-artifacts|tests\//);
});

test('Docker build stage includes configuration-test inputs and excludes them from runtime', async () => {
  const dockerfile = await read('Dockerfile');
  const [build, runtime] = dockerfile.split(/\nFROM nginx:/);
  assert.match(build, /COPY compose\.yaml compose\.dev\.yaml \.gitignore Dockerfile \.\//);
  assert.match(build, /RUN npm ci --no-audit --no-fund/);
  assert.match(build, /RUN npm test/);
  assert.doesNotMatch(runtime, /COPY (?:compose|tests|scripts)/);
  assert.match(runtime, /USER 10001:10001/);
});


test('current release metadata agrees without changing historical dictionary provenance',async()=>{
 const pkg=JSON.parse(await read('package.json')),lock=JSON.parse(await read('package-lock.json'));
 assert.equal(pkg.version,'1.0.0');assert.equal(lock.version,pkg.version);assert.equal(lock.packages[''].version,pkg.version);
 assert.match(await read('Dockerfile'),/org.opencontainers.image.version="1.0.0"/);
 assert.match(await read('public/index.html'),/class="version">v1.0.0/);
 assert.match(await read('compose.dev.yaml'),/PASSWORDFORGE_DEV_TAG:-dev-1.0.0/);
 assert.equal(JSON.parse(await read('data/readability-overrides.json')).version,'0.4.0');
});
