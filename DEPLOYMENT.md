# Operator qualification and Docker deployment

KeySmith 1.0.0 has a qualified private candidate; production remains the validated
0.7.0 image. Candidate deployment still needs explicit approval. An independent
rebuild requires its own source/artifact/scan/runtime qualification. Technical
image and service names remain `passwordforge`; this document authorizes no host
operations. For independent source installation see [INSTALLATION.md](INSTALLATION.md)
and the complete standalone/Traefik examples. Application MIT licensing is
approved. Public publication still requires explicit owner approval; the public
launch plan must enable/verify GitHub Private Vulnerability Reporting when
eligible, as described in SECURITY.md. Public-install acceptance requires the
pending fresh-install test.

Use standard Docker Buildx/Compose and `scripts/release/verify-release.py`.
Legacy orchestrators (`compose-release.py`, `docker-release.py`) and recovery
instructions are historical, not the active workflow. No historical network/volume
comparisons or custom failed-export recovery are required. Keep live identities,
configuration and evidence private; repository Compose files are generic examples.

## 1. Source and host checks

Use a reviewed source checkpoint. Run application tests, TypeScript, dictionary
validation and applicable browser suites. Freeze the exact source in an uncompressed
tar with a verifier-compatible manifest: source commit, version, candidate tag,
context SHA-256 and file paths/sizes/modes/hashes. Record its trusted checksum
separately; exclude unreviewed changes.

Verify strict SSH host identity, machine, explicit Docker endpoint/daemon,
architecture, existing service health, capacity and absence of conflicting writers.
Capture an immediate unrelated-service baseline. Use unique candidate names without
changing production tags, routing or other services.

## 2. Build and authenticate

Use pinned Dockerfile/lockfile inputs, the local default Buildx builder and
linux/amd64. Submit the frozen tar; capture metadata, IID and logs. Request retained
provenance with `--attest type=provenance,mode=max,version=v0.2` and provide the
reviewed source commit/context labels. No push or automatic stage advancement.

Authenticate the OCI index/Buildx IID separately from the selected amd64 manifest
and runnable configuration. Capture native and platform-selected inspection.
Check candidate-tag continuity immediately before/after export. Docker save must
use an authenticated locally resolvable top-level reference; do not assume a
platform manifest is exportable or use platform filtering.

Run verify-release.py with all explicit inputs: manifest/trusted checksum, source
tar, Buildx metadata/IID, both inspection captures, exported archive and expected
index digest. Require PASS for source, full OCI graph, runtime configuration and
SLSA v0.2 provenance. Establish the trusted index from reviewed build captures;
never rewrite artifacts to agree. This verifies captures, not builder honesty or
a live tag. Build/export failure stops for review, not custom recovery.

## 3. Scan the same image

Use Trivy 0.75.0 at the exact digest in SCANNER-PROVENANCE.json; verify version and
platform identity. Scan the authenticated archive with a non-root/read-only,
resource-bounded scanner, private mounts and no Docker socket. Provide adequate
isolated scratch: the validated run used a bounded 1 GiB scanner /tmp tmpfs,
not the application's 16 MiB allowance.

Acquire DB updates with separately approved network access. Validate schema,
UpdatedAt/NextUpdate and freshness: not future/expired and at most 48 hours old.
Only after successful preparation may scans use skip-update/offline flags.
Run native JSON with package inventory and the committed template pass on the
same DB/archive, with network none. Use existing checks/scan_contract validators;
require nonempty inventory, approved configuration digest and consistent reports.
Preserve DB metadata/hashes, logs and findings.

HIGH/CRITICAL/UNKNOWN block release; MEDIUM needs written disposition. Warnings,
errors, stale/missing data and inconsistent reports block acceptance. Never
suppress findings or treat an incomplete scan as PASS.

## 4. Isolated smoke test

Authenticate the existing candidate tag immediately before creating one unique
owned container with pull disabled. Verify its image chain and configuration
before starting. Docker/containerd may report the OCI index in container .Image;
accept it only through the authenticated manifest/configuration relationship.

Use default bridge only, Traefik/Watchtower exclusion, no production volumes,
loopback-only ephemeral access, UID/GID 10001:10001, read-only root, ALL cap drop,
no-new-privileges, 128 MiB/1 CPU/128 PIDs and the approved 16 MiB /tmp tmpfs.
Bound health/HTTP checks; verify branding/version, assets/hashes/MIME, full security
headers/CSP, expected 404s and browser functionality. Use public screenshot fixtures;
never record generated passwords, secrets, traces or raw Docker event attributes.
Remove only the authenticated owned test container after collecting evidence.

## 5. Service-only deployment

Obtain explicit approval. Recheck host/image identities, capacity, concurrency
and unrelated services. Verify the repository@digest reference resolves locally;
do not pull or retag around a mismatch. Change only the private Compose image
reference. Compare normalized configurations; preserve routing/network, volumes,
hardening, limits, health checks, restart and Watchtower exclusion behavior.

Set APPROVED_COMPOSE to the reviewed private path, then recreate only the service:

```bash
docker --host unix:///var/run/docker.sock compose \
  --project-name passwordforge --file "$APPROVED_COMPOSE" \
  up --detach --no-deps --no-build --pull never \
  --force-recreate --wait --wait-timeout 120 passwordforge
```

Brief downtime is acceptable. Require approved image identity, healthy state,
hardening, public HTTPS/TLS, security headers, assets, all profiles, Focus/Sheet,
inline policy, copying and themes. Health alone is insufficient. Compare unrelated
containers and network/volume inventories; unexpected drift blocks acceptance.

## Failure, cleanup and maintenance

Stop on failed gates; preserve evidence and report state. No automatic retry,
rollback, speculative image replacement or broad pruning. No separate rollback
image is required; a corrected build with downtime needs explicit approval.

After acceptance and separate cleanup approval, remove only exact unused
PasswordForge resources. Check all containers (including stopped), Compose
dependencies and required references; never force removal. Preserve canonical
evidence and unrelated services/images/networks/volumes. Retain uncertain items
and report why.

Review pins and relevant dependency/base/scanner advisories before each release
and periodically during internal operation. Acquire reviewed updates and repeat
affected gates; no unattended updater or new release framework is required.
README.md records acceptance dispositions; SECURITY.md defines maintenance scope.
