# Docker installation

Build from source as shown in [README.md](README.md). No public KeySmith registry
image is currently provided. The standalone default needs no environment file.
For remote browser access, choose one HTTPS alternative below.

## Existing-certificate prerequisites

1. Create an A record for your hostname pointing to the Docker host. Add AAAA only
   if you intend to support and configure IPv6 access.
2. Obtain a server certificate with that DNS SAN and a matching private key.
   `fullchain.pem` contains the PEM leaf followed by intermediate certificates;
   do not append the trusted root. `privkey.pem` contains the matching PEM key.
3. Keep both files in a protected directory **outside the clone**, for example
   `/etc/keysmith/tls`. Both example proxies run as UID/GID `65532`. Arrange for
   that identity to read the directory and files: a typical Linux setup uses
   owner `root`, group `65532`, directories `0750` and key `0640`. Also permit
   traversal of parent directories. Do not make the key world-readable.
4. Confirm browsers trust the issuing CA. Certificate issuance and renewal are
   your responsibility; these examples use existing certificates, not ACME.
5. Make the intended host address and TCP 443 reachable by your users. Backend
   8080, Docker API and proxy administration ports are not published. The app
   has no login system; choose access appropriate to your installation.

```sh
cp .env.example .env
# Edit .env: KEYSMITH_DOMAIN, KEYSMITH_BIND_IP and KEYSMITH_TLS_DIR.
```

Use a fresh `.env` file, not an existing file belonging to another application.
It contains configuration, not private-key contents. The default bind address in
the example is loopback; for remote clients select an address on your Docker host.
The TLS directory must already exist and contain the two files above. Do not use
an unrelated application's certificate or network without its owner's permission.

## Traefik

```sh
docker compose -p keysmith-traefik -f compose.traefik.yaml config
docker compose -p keysmith-traefik -f compose.traefik.yaml build keysmith
docker compose -p keysmith-traefik -f compose.traefik.yaml pull --policy always traefik
docker compose -p keysmith-traefik -f compose.traefik.yaml up -d --no-build --pull never --wait --wait-timeout 120
docker compose -p keysmith-traefik -f compose.traefik.yaml ps
curl --fail https://YOUR_HOSTNAME/healthz
```

Replace `YOUR_HOSTNAME` with `KEYSMITH_DOMAIN`; expect `ok`. Traefik uses the file
provider in `examples/traefik`, with a hostname supplied through its environment.
It reads certificates from a read-only bind mount, listens internally on 8443 and
receives host TCP 443. Routing is `keysmith:8080` on this project's private bridge.
No certificate resolver, labels for discovery or Docker socket is required.

## Caddy

Use this alternative instead of the Traefik or standalone file:

```sh
docker compose -p keysmith-caddy -f compose.caddy.yaml config
docker compose -p keysmith-caddy -f compose.caddy.yaml build keysmith
docker compose -p keysmith-caddy -f compose.caddy.yaml pull --policy always caddy
docker compose -p keysmith-caddy -f compose.caddy.yaml up -d --no-build --pull never --wait --wait-timeout 120
docker compose -p keysmith-caddy -f compose.caddy.yaml ps
curl --fail https://YOUR_HOSTNAME/healthz
```

`examples/caddy/Caddyfile` uses the same hostname and certificate files. It disables
the administration API and automatic HTTP redirects, so only TCP 443 is published.
Its backend is `keysmith:8080`, not localhost. Writable Caddy scratch directories
are bounded tmpfs mounts; no persistent certificate database is needed for these
manually supplied certificates. Do not replace this with `tls internal` unless
you deliberately want to manage a different CA and client trust.

## Health, troubleshooting and maintenance

Application `/healthz` returns HTTP 200 and `ok`. Compose waits for the app's
health check before starting its proxy. The HTTPS request above verifies the
public route and normal certificate validation; Compose status alone does not.
Check Generate, Copy, settings and themes in your browser after setup.

Use the same project/file options for status and bounded logs:

```sh
docker compose -p keysmith-traefik -f compose.traefik.yaml logs --tail 100 keysmith traefik
```

For Caddy substitute its project, file and service. Check file permissions for
certificate-loading errors, hostname/DNS and CA trust for TLS failures, and app
health/network membership for 502 responses. Do not disable read-only mode or
run the app as root to conceal an error. No real generated passwords belong in
logs, screenshots or support issues.

For updates, review upstream changes, update your source checkout to the intended
release, rebuild, and repeat the same `up` command and health/browser checks.
Changes to pinned dependencies require review, not automatic substitution.
New builds are separate images; prior vulnerability results do not qualify them.
No automatic updater, custom release framework or retained rollback image is
required by these examples.

For certificate renewal, obtain replacement files from your issuer, verify the
hostname/chain/key match, replace them securely in the external TLS directory,
and restart only the proxy with your same project/file options. Verify the served
certificate afterward. Do not change the app image for certificate renewal.

To remove an installation, run `docker compose down` with its exact project/file
options. Do not add broad prune, volume-removal or unrelated-project commands.
The external TLS files are not managed or deleted by Compose.

References: [Docker installation](https://docs.docker.com/engine/install/ubuntu/),
[Traefik file configuration](https://doc.traefik.io/traefik/reference/dynamic-configuration/file/),
[Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).
