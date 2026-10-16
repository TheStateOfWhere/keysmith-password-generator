# Install KeySmith from source

Publication preparation draft: the owner-selected future destination is
https://github.com/TheStateOfWhere/keysmith-password-generator.
The application is MIT-licensed. Public availability and GitHub Private
Vulnerability Reporting enablement/delivery verification remain pending.
Use these instructions after separately authorized publication of the reviewed
source and examples. No public image or release tag is assumed. The technical
image/service name remains `passwordforge`.

## Requirements and source

Use a maintained Docker Engine (28 or newer), Compose v2 CLI with `--wait` and
Buildx, Git, curl, and a Linux/amd64 container environment. Docker Desktop must run
Linux containers; native Windows containers are unsupported. Other architectures
have not been qualified. Node/npm are provided by the multi-stage build. Allow
enough capacity for a Node build plus your existing workloads; check disk/RAM
before building. Registry, locked npm dependency and pinned Alpine package access
are required on a fresh machine. Pins deliberately fail if unavailable.

Commands below use a POSIX shell (Linux, macOS or WSL with Docker integration).
Set `PUBLISHED_COMMIT` to the full commit explicitly identified by the owner after
publication. Do not use an internal archive, an uncommitted checkout, or assume
that the default branch is the release:

```sh
: "${PUBLISHED_COMMIT:?Set the reviewed public release commit first}"
git clone https://github.com/TheStateOfWhere/keysmith-password-generator.git
cd keysmith-password-generator
git checkout --detach "$PUBLISHED_COMMIT"
test "$(git rev-parse HEAD)" = "$PUBLISHED_COMMIT"
test -z "$(git status --porcelain)"
docker version
docker compose version
docker buildx version
df -h .
```

Read the release notes and [MIT application license](LICENSE) before use or
redistribution. Keep all `data/` notices; never replace pins or disable tests to
make a build succeed. The Dockerfile runs the application/security tests and
serves only locally bundled assets. A new local build is not the operator's
previously qualified image and does not inherit its scan result or image identity.
For release/exposed deployments apply the source, artifact, fresh Trivy and smoke
gates in [DEPLOYMENT.md](DEPLOYMENT.md) before exposure. HIGH/CRITICAL/UNKNOWN
findings block use; MEDIUM findings need an explicit reviewed disposition. Scanner
errors and stale/incomplete scans are not clean results.

## Licensing when redistributing

The MIT application notice is in LICENSE; third-party data keeps its original
licenses in data/. Preserve all notices and the EFF modification attribution.
A source clone includes the MIT notice. If redistributing a static bundle or
container image, include LICENSE with that distribution as well as the bundled
third-party notices. The currently qualified image predates this new LICENSE
file and must not be described as containing it. No container/static build change
is made here; self-contained license packaging for future binary distribution
needs separate review. This task does not authorize binary image publication.

## Standalone: loopback only

Use the complete standalone file by itself. Do not combine it with `compose.yaml`.
Choose an unused port (18080 below); a pre-check does not reserve it. Keep the same
project name, file and environment for every command for this installation.

```sh
export KEYSMITH_PORT=18080
export KEYSMITH_IMAGE=passwordforge:1.0.0-local
# Inspect interpolation and hardening before creating anything.
docker compose -p keysmith-local -f compose.standalone.example.yaml config
# Builds only PasswordForge; pulls still obey digest-pinned FROM lines.
docker compose -p keysmith-local -f compose.standalone.example.yaml build --pull passwordforge
docker image inspect "$KEYSMITH_IMAGE" --format '{{.Id}} {{.Config.User}} {{index .Config.Labels "org.opencontainers.image.version"}}'
docker compose -p keysmith-local -f compose.standalone.example.yaml up -d --no-deps --no-build --pull never --wait --wait-timeout 120 passwordforge
docker compose -p keysmith-local -f compose.standalone.example.yaml ps
CID=$(docker compose -p keysmith-local -f compose.standalone.example.yaml ps -q passwordforge)
docker inspect "$CID" --format '{{.State.Health.Status}} {{.RestartCount}}'
curl --fail --show-error --max-time 10 "http://127.0.0.1:$KEYSMITH_PORT/healthz"
```

Expect image user `10001:10001`, version `1.0.0`, healthy status and `ok`.
Open `http://localhost:18080/` on that workstation (substitute your port). Localhost
allows the browser clipboard API; ordinary HTTP on a remote IP does not. Firefox,
Chrome and Safari are not evidence-backed supported browsers; automated desktop
qualification used Microsoft Edge on Windows. No NVDA or physical-mobile
certification is claimed. Try Readable, Strong Random, inline Custom Policy,
Focus and a five-password Sheet; test Generate, Regenerate, Hide/Show, Copy, Clear
and themes. Entropy must meet the 64-bit minimum and invalid policy must block
generation. Never put generated passwords in logs, screenshots or support issues.

The example has no fixed container name, application volumes or Docker socket.
It uses a project-specific network and publishes only loopback, with non-root,
read-only root, ALL capabilities dropped, no-new-privileges, 128 MiB memory,
1 CPU, 128 PIDs and a 16 MiB /tmp tmpfs. Restart is `unless-stopped`. Docker 28+
closes a historical localhost-publication exposure on earlier engines; host
administrators/firewall policy still control access. Do not replace the bind with
`0.0.0.0` simply to allow remote clients: use HTTPS through a reviewed proxy.

To change the port, set `KEYSMITH_PORT` to another unused value and rerun the same
service-only `up` command with `--force-recreate`. Expect brief downtime. Do not
edit unrelated projects or open a production firewall for this example.

## Reverse proxy / load balancer

Provide your own DNS name, reachable HTTPS listener, trusted certificate/renewal
and access policy. TLS terminates at the proxy; KeySmith's HTTP backend is port
8080, with GET `/healthz` expecting 200 and body `ok`. Serve at the domain root,
not an untested URL subpath. Restrict the backend to the proxy and administrators;
it has no authentication or TLS itself. Use private access controls if exposing a
password generator is inappropriate for your audience.

### Existing Traefik Docker provider

The example configures only KeySmith, not Traefik or certificate acquisition.
The proxy must already have a reviewed Docker provider (`exposedByDefault=false`),
a TLS entry point and the named working certificate resolver. Manage provider
Docker API access as a privileged host capability; never mount it into KeySmith
or expose an unauthenticated API. No certificates or DNS API tokens belong in
labels, Git, or the application container.

Use a dedicated backend network shared only by this app and its intended proxy.
For a fresh, operator-owned network, inspect for a collision first and create it
once only after confirming absence. If the name exists, establish ownership and
intended proxy membership before reusing it; do not delete or automatically adopt
an unrelated network. Configure the existing proxy's own Compose to attach to that
external network through a separately reviewed proxy change; do not blindly
attach to an unrelated production network or recreate other services.

```sh
export KEYSMITH_PROXY_NETWORK=keysmith-proxy  # choose your own dedicated network
export KEYSMITH_DOMAIN=keys.example.com
export KEYSMITH_CERT_RESOLVER=letsencrypt
export KEYSMITH_HTTPS_ENTRYPOINT=websecure
export KEYSMITH_IMAGE=passwordforge:1.0.0-local
# On a fresh host only, after establishing ownership and absence:
docker network inspect "$KEYSMITH_PROXY_NETWORK"
# If absent, explicitly create the new dedicated network; do not delete a collision.
docker network create "$KEYSMITH_PROXY_NETWORK"
# Attach your own proxy through its reviewed configuration before continuing.
docker compose -p keysmith-proxy-app -f compose.traefik.example.yaml config
docker compose -p keysmith-proxy-app -f compose.traefik.example.yaml build --pull passwordforge
# Complete artifact/scan/isolated-smoke gates in DEPLOYMENT.md before exposure.
docker compose -p keysmith-proxy-app -f compose.traefik.example.yaml up -d --no-deps --no-build --pull never --wait --wait-timeout 120 passwordforge
curl --fail --show-error --max-time 10 "https://$KEYSMITH_DOMAIN/healthz"
```

Replace the example DNS name/resolver/entry point with your own values. Ensure the
router/service name `keysmith` is unused in that Traefik instance; if not, rename
only this example's router/service labels consistently. The required network variable must
match your actual shared network name; an unset domain, resolver or network is
a configuration error. This file deliberately publishes no backend
host ports. Never use it as an overlay on the standalone or legacy templates.
Do not connect a remote load balancer directly to an unrestricted Docker backend.

### NGINX or HAProxy

For a proxy installed on the *same host*, use the standalone loopback listener as
the upstream. For a containerized proxy, `127.0.0.1` means that proxy container:
instead use a dedicated shared backend network and `passwordforge:8080`, with no
host port. Adapt the proxy example's network-only service (remove Traefik labels)
in your own reviewed configuration. For a different host, use a firewall-restricted
private upstream and protected transport (TLS, a secured tunnel or a private
trusted segment according to your threat model); never publish an unrestricted
HTTP backend for convenience.

NGINX example for a host-installed proxy, inside your own TLS configuration:

```nginx
server {
    listen 443 ssl;
    server_name keys.example.com;
    ssl_certificate /etc/nginx/tls/keys-fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/keys-key.pem;
    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "";
    }
}
```

HAProxy equivalent fragment for a host-installed proxy; integrate into an existing
reviewed `global`/`defaults` configuration with suitable timeouts:

```haproxy
frontend keysmith_https
    bind :443 ssl crt /etc/haproxy/tls/keys.pem
    mode http
    acl keysmith_host hdr(host) -i keys.example.com keys.example.com:443
    http-request deny deny_status 404 unless keysmith_host
    http-request del-header Forwarded
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-For %[src]
    default_backend keysmith_backend
backend keysmith_backend
    mode http
    option httpchk
    http-check send meth GET uri /healthz ver HTTP/1.1 hdr Host keys.example.com
    http-check expect status 200
    server keysmith 127.0.0.1:18080 check
```

Keep private key/certificate files outside this repository, permission-restricted.
Set redirects and HSTS at the TLS proxy only after testing certificate renewal and
HTTPS reachability. Preserve upstream CSP, Cache-Control and other security
headers exactly once; don't replace/append conflicting CSP or weaken it with
`unsafe-inline`. Do not add CORS, framing or WebSocket allowances. KeySmith is
static and does not consume forwarded headers for authorization. At the public
edge overwrite client-supplied forwarding headers; trust a further upstream only
from explicitly allowed proxy addresses, never globally. Health checks should use
`/healthz`, not a credential-bearing endpoint. Disable unnecessary request-body,
query, tracing and diagnostic logging; never transmit generated passwords.

## Updates, removal and troubleshooting

For an update, obtain the new reviewed public commit and notes, verify pins and
run the build/tests, artifact checks, fresh vulnerability scan and isolated smoke
test again. Use a new local image tag (`KEYSMITH_IMAGE`), then recreate only this
service with the same project/file/environment and `--no-deps --no-build
--pull never --force-recreate --wait --wait-timeout 120 passwordforge`. Recheck
health, headers, browser behavior and unrelated services. Do not assume that an
old clean scan qualifies a new build. No automatic production updater or rollback
image is required. If qualification fails, stop; retain evidence and the running
installation while investigating.

To remove a standalone installation you own:

```sh
docker compose -p keysmith-local -f compose.standalone.example.yaml down
```

Use `keysmith-proxy-app` and `compose.traefik.example.yaml` for that installation
instead. Check `compose ps` and project ownership first. These examples own no
volumes. Never add `--volumes`, `--rmi`, `--remove-orphans`, force removal or prune.
The external proxy network and proxy are retained; don't remove a network in use
by the proxy or other apps. Images are retained until you verify that **no running
or stopped container** or other installation needs them, then explicitly remove
only the exact owned unused image ID/reference without force. Do not remove TLS
material, source or evidence as part of application container removal.

- Port collision: select another unused `KEYSMITH_PORT`; don't stop another app.
- Missing image: run the explicit build for this file/project/tag, not `pull latest`.
- Build/pin/network failure: retain logs; check connectivity and published pins.
  Never float digests or disable tests. Build tools need more memory than runtime.
- Unhealthy: inspect `compose ps` and bounded logs for this service; verify /tmp
  and hardening against the example. Don't disable read-only or run as root.
- Proxy 502: verify its intended network membership and upstream port 8080.
- TLS/router failure: verify your DNS, entry point, resolver and certificate trust;
  never accept `curl -k` as a pass.
- Clipboard unavailable: use HTTPS/localhost and explicit user activation. Don't
  persist passwords in reports to demonstrate a clipboard problem.

Reference behavior: [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/),
[Traefik Docker labels](https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/docker/),
[NGINX proxy headers](https://nginx.org/en/docs/http/ngx_http_proxy_module.html),
and [HAProxy health checks](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/).
