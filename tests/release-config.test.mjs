import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { screenshotDirectory } from './browser-artifacts.mjs';
const read = name => readFile(new URL('../'+name, import.meta.url), 'utf8');

test('standalone is loopback-only; HTTPS alternatives do not publish the backend', async () => {
  const local = await read('compose.yaml');
  assert.match(local, /127\.0\.0\.1:\$\{KEYSMITH_PORT:-18080\}:8080/);
  for (const name of ['compose.yaml','compose.traefik.yaml','compose.caddy.yaml']) {
    const config = await read(name);
    const app = config.split(/\n  (?:traefik|caddy):/)[0];
    assert.match(app, /build:\n\s+context: \./);
    for (const value of ['platform: linux/amd64','pull_policy: never','user: "10001:10001"','read_only: true','cap_drop: [ALL]','no-new-privileges:true','pids_limit: 128','mem_limit: 128m','/tmp:rw,noexec,nosuid,size=16m,mode=1777','http://127.0.0.1:8080/healthz']) assert.ok(app.includes(value), name+': '+value);
    assert.doesNotMatch(config, /container_name:|privileged:\s*true|docker\.sock|network_mode:\s*host/);
    if (name !== 'compose.yaml') {
      assert.doesNotMatch(app, /^\s+ports:/m);
      assert.match(config, /:443:8443\/tcp/);
      assert.match(config, /user: "65532:65532"/);
      assert.match(config, /driver: bridge/);
      assert.doesNotMatch(config, /internal:\s*true/);
      assert.match(config, /create_host_path: false/);
    }
  }
});

test('Docker build retains regression inputs and bundles application and data licenses', async () => {
  const [build,runtime] = (await read('Dockerfile')).split(/\nFROM nginx:/);
  assert.match(build,/RUN npm ci --no-audit --no-fund/);
  assert.match(build,/RUN npm test/);
  assert.match(build,/COPY compose\.yaml compose\.traefik\.yaml compose\.caddy\.yaml \.gitignore \.dockerignore Dockerfile LICENSE \.\//);
  assert.match(build,/COPY examples \.\/examples/);
  assert.doesNotMatch(runtime,/COPY (?:compose|tests|scripts|examples)/);
  assert.match(runtime,/USER 10001:10001/);
  assert.equal(await read('dist/licenses/LICENSE.txt'),await read('LICENSE'));
  assert.equal(await read('dist/licenses/ESDB-Copyright.txt'),await read('data/ESDB-Copyright.txt'));
  assert.equal(await read('dist/licenses/CC-BY-4.0.txt'),await read('data/CC-BY-4.0.txt'));
});

test('proxy routes use existing certificates without Docker discovery', async () => {
  const staticConfig=await read('examples/traefik/traefik.yaml');
  const dynamic=await read('examples/traefik/dynamic/keysmith.yaml');
  const caddy=await read('examples/caddy/Caddyfile');
  assert.doesNotMatch(staticConfig,/docker:|dashboard:|insecure:/);
  assert.match(dynamic,/http:\/\/keysmith:8080/);
  assert.match(dynamic,/\/certs\/fullchain\.pem/);
  assert.match(dynamic,/\/certs\/privkey\.pem/);
  assert.match(dynamic,/minVersion: VersionTLS12/);
  assert.match(dynamic,/sniStrict: true/);
  assert.match(caddy,/admin off/);
  assert.match(caddy,/auto_https disable_redirects/);
  assert.match(caddy,/https_port 8443/);
  assert.match(caddy,/reverse_proxy keysmith:8080/);
  assert.doesNotMatch(caddy,/tls internal/);
});

test('browser screenshots stay in separate ignored per-run directories', async () => {
  const first=await screenshotDirectory('fixture'),second=await screenshotDirectory('fixture');
  assert.notEqual(first('one.png'),second('one.png'));
  assert.throws(()=>first('../escape.png'));
  assert.match(await read('.gitignore'),/artifacts\//);
  assert.doesNotMatch(await read('scripts/build.mjs'),/browser-artifacts|tests\//);
});

test('release metadata agrees and historical dictionary provenance stays unchanged', async () => {
  const pkg=JSON.parse(await read('package.json')),lock=JSON.parse(await read('package-lock.json'));
  assert.equal(pkg.name,'zevyrn');
  assert.equal(lock.name,pkg.name);
  assert.equal(lock.packages[''].name,pkg.name);
  assert.equal(pkg.version,'1.0.0');
  assert.equal(lock.version,pkg.version);
  assert.equal(lock.packages[''].version,pkg.version);
  assert.match(await read('Dockerfile'),/org.opencontainers.image.title="Zevyrn"/);
  assert.match(await read('Dockerfile'),/org.opencontainers.image.version="1.0.0"/);
  assert.match(await read('public/index.html'),/class="version">v1.0.0/);
  assert.equal(JSON.parse(await read('data/readability-overrides.json')).version,'0.4.0');
});
