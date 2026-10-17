# Docker installation

These instructions target **Zevyrn v1.1.0** from the
[canonical GitHub repository](https://github.com/TheStateOfWhere/zevyrn-password-generator).
See the [rename notes](docs/REPOSITORY-RENAME.md) for the completed repository
rename and retained configuration identifiers.

Build from source as shown in [README.md](README.md). No public Zevyrn registry
image is currently provided. The standalone default needs no environment file.
For remote browser access, choose one HTTPS alternative below.

## Choose a hostname and client trust

Replace the sample `keys.example.com` with a name you control, such as
`keys.your-domain.com`. Set `KEYSMITH_DOMAIN` in `.env` to the bare hostname,
without a scheme, path or port, and use that same name in DNS and the certificate's
DNS SAN. `KEYSMITH_BIND_IP` is an address assigned to the Docker host, not the
client's address. These examples publish HTTPS on TCP 443 at that address.

- **Public DNS name:** create the record with your domain's DNS provider. A name
  under a public domain can also be used with internal or split DNS. Publishing
  the DNS record does not itself expose the application; routing and access
  restrictions are separate administrator decisions.
- **Internal DNS name:** create the record in the DNS service used by your
  internal clients. VPN clients must use a resolver that can resolve that name
  and have a route to the Docker host. Do not expect public resolvers to know a
  private DNS zone.

A publicly trusted certificate is suitable for a name it covers, including a
public-domain name used internally. A private-only name generally needs your
organization's private CA. Obtain certificates through your existing issuer;
these examples do not enroll certificates or create a CA. For a private CA,
distribute its public root certificate through your normal client trust process
to every browser/device that will access Zevyrn. Supplying the server's
certificate files to a container does not establish client trust.

For a command-line check using an explicitly trusted private root:

```sh
curl --fail --cacert /path/to/your-root-ca.pem https://YOUR_HOSTNAME/healthz
```

Replace both placeholders. The URL name must match the certificate SAN; do not
substitute an IP address unless the certificate also contains that IP SAN.
Never disable certificate verification to make an installation test pass.

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
The dedicated network is a normal bridge: an internal-only Docker network cannot
provide the published HTTPS listener used here. Backend 8080 remains unpublished.

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

The pinned official Caddy binary has a `NET_BIND_SERVICE` file capability. Its
service drops all capabilities and adds back only `NET_BIND_SERVICE` so Linux
can execute that binary. Removing this exception can cause
`exec /usr/bin/caddy: operation not permitted`, even though Caddy listens on
unprivileged container port 8443. Zevyrn receives no added capabilities; both
services remain non-root with read-only filesystems and `no-new-privileges`.

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

## Updates

Review the upstream release notes before updating. Start in your existing clone
and preserve your external TLS files and `.env` settings. If `git status` shows
local tracked-file changes, review them before switching versions; do not discard
them automatically. Use a real published release tag or a reviewed full commit:

```sh
git status --short
git fetch origin --tags
RELEASE_REF='vX.Y.Z' # Replace with the intended published tag or full commit.
git show --no-patch "$RELEASE_REF"
git checkout --detach "$RELEASE_REF"
```

Use only the commands for your existing installation, with its original project,
file and environment settings. A separate build step is required; `up --no-build`
does not rebuild the application.

Standalone:

```sh
docker compose config
docker compose build keysmith
docker compose up -d --no-build --pull never --wait --wait-timeout 120
```

Traefik:

```sh
docker compose -p keysmith-traefik -f compose.traefik.yaml config
docker compose -p keysmith-traefik -f compose.traefik.yaml build keysmith
docker compose -p keysmith-traefik -f compose.traefik.yaml pull --policy always traefik
docker compose -p keysmith-traefik -f compose.traefik.yaml up -d --no-build --pull never --wait --wait-timeout 120
```

Caddy:

```sh
docker compose -p keysmith-caddy -f compose.caddy.yaml config
docker compose -p keysmith-caddy -f compose.caddy.yaml build keysmith
docker compose -p keysmith-caddy -f compose.caddy.yaml pull --policy always caddy
docker compose -p keysmith-caddy -f compose.caddy.yaml up -d --no-build --pull never --wait --wait-timeout 120
```

Repeat the health request and browser checks above after updating. For standalone,
check `http://127.0.0.1:18080/healthz` (or your configured loopback port). For HTTPS,
use your hostname and normal CA trust, or the explicit private-root check above.
Changes to pinned dependencies require review, not automatic substitution.
New builds are separate images; prior vulnerability results do not qualify them.
The existing `keysmith.theme` preference key is retained for compatibility.
Legacy Automatic/Light map to Zevyrn, Dark to Midnight, Emerald to Aurora, and
Amethyst to Dusk. New installations default to Zevyrn; Slate is a new choice.
Only a theme identifier is saved. Password generation is unchanged.
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
