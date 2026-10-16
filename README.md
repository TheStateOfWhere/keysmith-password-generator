# KeySmith

Self-hosted password generation in your browser. KeySmith provides Readable,
Strong Random and Custom Policy profiles, single-password and batch views,
copying controls, Large Text and five themes.

Passwords are generated on your device using Web Crypto. There is no backend
password storage, telemetry or external dictionary service. Only the selected
theme is saved. Clear does not erase OS clipboard history or securely wipe memory.

## Install from source

There is currently no official published KeySmith container image. Build from
this repository; a locally built image is named `keysmith:1.0.0-local`.

Requirements: Linux/amd64 containers, Git, maintained Docker Engine 28 or newer,
Docker Compose plugin with `--wait`, and Buildx. Docker Desktop must use Linux
containers. Node/npm are included in the build; they are not host prerequisites.
The first build needs access to container registries, npm and Alpine repositories.

On Ubuntu, follow [Docker's official apt repository setup](https://docs.docker.com/engine/install/ubuntu/#install-using-the-apt-repository),
including the Compose and Buildx plugins. Do not reinstall Docker if it is already
working. Commands below use a POSIX shell; prefix Docker commands with `sudo` if
your account does not have Docker access.

```sh
git clone https://github.com/TheStateOfWhere/keysmith-password-generator.git
cd keysmith-password-generator
docker version
docker compose version
docker buildx version
docker compose build
docker compose up -d --no-build --pull never --wait --wait-timeout 120
curl --fail http://127.0.0.1:18080/healthz
```

Expect `ok`. Open **http://localhost:18080** on the Docker host. If Docker runs on
a remote server, localhost refers to that server; use the HTTPS instructions below
for remote browser access. This loopback-only setup does not publish the app to
other machines. Change its port with `KEYSMITH_PORT=18081 docker compose ...` and
use the same setting for subsequent commands.

The Dockerfile runs the application tests during the build. Builds intentionally
fail when pinned inputs are unavailable; do not bypass tests or remove the pins.

## HTTPS: choose Traefik or Caddy

See [INSTALLATION.md](INSTALLATION.md) for complete commands using an existing
certificate. Both examples create their own project network, publish only TCP 443,
and route to `keysmith:8080`. No Docker socket or external proxy network is needed.
Use one complete Compose file at a time; do not combine the alternatives.

| Option | Compose file | Browser address |
| --- | --- | --- |
| Local only | `compose.yaml` | `http://localhost:18080` |
| Traefik + existing certificate | `compose.traefik.yaml` | `https://<your-domain>` |
| Caddy + existing certificate | `compose.caddy.yaml` | `https://<your-domain>` |

Provide a DNS record pointing to your Docker host, a certificate whose DNS SAN
matches that name, and client trust in the issuing CA. Private hostnames need a
trusted private-CA certificate. The examples do not issue certificates or create
a CA. Keep private keys outside this repository. Port 80 is not required by these
existing-certificate examples. HTTPS or localhost is required for browser copying.

## Troubleshooting

```sh
docker compose ps
docker compose logs --tail 100 keysmith
curl --fail http://127.0.0.1:18080/healthz
```

For HTTPS, use the same `-p` and `-f` options as your installation when checking
status or logs. A 502 usually means the app is unhealthy or the proxy cannot reach
`keysmith:8080`. A certificate warning means the hostname, chain, expiry or client
trust needs attention; do not treat `curl -k` as a successful HTTPS test.
If a port is occupied, choose another port or host address; do not stop another
application. A missing local image requires the explicit build step above.
See [INSTALLATION.md](INSTALLATION.md) for updates and removal.

## Development and licensing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local tests and [SECURITY.md](SECURITY.md)
for reporting and security boundaries. Other CPU architectures and physical mobile,
screen-reader and full cross-browser behavior have not been qualified. Existing
automated browser coverage uses Microsoft Edge on Windows.

Application: [MIT](LICENSE). Dictionary data retains its separate licenses and
[attribution](data/NOTICE.md). Application and third-party notices are included in
the built `/licenses/` assets. Historical project names in `data/NOTICE.md` are
retained verbatim to preserve pinned dictionary attribution and provenance; the
current product name is KeySmith.
