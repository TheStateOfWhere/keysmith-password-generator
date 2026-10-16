# PasswordForge generic Docker operator runbook

## Replacement workflow — local implementation, host execution HOLD

`compose-release.py` is the proposed single-host replacement. Its local mocked
tests are not Docker acceptance. Independent review and separately approved real
Docker validation are required before use. Legacy instructions remain below;
do not mix their evidence with replacement runs.

One trusted operator, trusted committed checkout and no concurrent filesystem or
Docker writers are required. Host administrators are outside the threat model.
Hashes detect substitution/drift; they are not signatures or external approvals.
The compact `run.json` binds source context, private target, build, scan and runtime.
No separate fixture/source/production authority documents or VMs are required.

Prerequisites: non-root Ubuntu 24.04 amd64, Engine, Compose, default Docker-driver
Buildx, Python 3, Bash and curl. Local application/browser tests, TypeScript,
dependency audit and release tests must pass before a reviewed clean commit.
Host Node/npm are unnecessary. Keep the existing pinned bases and Trivy cached;
missing images stop, never pull automatically. Acquisition and build/database
network access require separate approval. --pull=false is not an offline guarantee.

Create private target configuration from TARGET.example.json outside source;
replace every placeholder with trusted-console/operator-reviewed values. Target
mode must be private and operator-owned; evidence root must already exist with
mode 0700. Source, private Compose and evidence paths must have no links/junctions.
The target identifies host machine, daemon, endpoint, dedicated Compose project,
service, Compose checksum, external proxy network and HTTPS origin. No credentials.
There is no provisioning or remote transport in the helper.

These are reference commands, not authorization. Run only one block after its
separate approval. Never paste all blocks as a deployment pipeline.

```bash
SOURCE=/path/to/reviewed/passwordforge
TARGET=/private/target.json
RUN=/private/evidence/pf-release-UNIQUE_RUN
COMMIT=REVIEWED_FULL_COMMIT
VERSION=REVIEWED_VERSION
CANDIDATE=passwordforge:REVIEWED_VERSION-candidate-UNIQUE_RUN
cd -- "$SOURCE"
python3 -B scripts/release/compose-release.py preflight --target "$TARGET" \
  --evidence "$RUN" --commit "$COMMIT" --version "$VERSION" --candidate "$CANDIDATE"
```

STOP. Review host, daemon, builder, source, cached images, capacity and production.
Preflight uses read-only Docker inspection but creates private evidence and an
operator lock. It is not a filesystem-read-only command. All locally knowable
invalid prerequisites are rejected before contact or output creation.

```bash
python3 -B scripts/release/compose-release.py build --target "$TARGET" --evidence "$RUN"
```

STOP. Build submits captured, verified committed tar bytes on stdin. Review build
logs and authenticated index/manifest/config identity roles. Source drift fails
publication of success. The same immutable image is required in all later stages.

```bash
python3 -B scripts/release/compose-release.py scan --target "$TARGET" --evidence "$RUN"
```

STOP. Pinned Trivy 0.75.0 downloads its database with bridge access; both actual
passes use network none, the same archive/database, and OS/library coverage.
Native JSON uses --list-all-pkgs; the template pass does not. Schema, warnings,
errors, freshness (48 hours and NextUpdate), inventory and image mismatches fail.
HIGH/CRITICAL/UNKNOWN block. No socket mount. Raw findings/logs remain after failure.
MEDIUM requires a private JSON with exactly imageId, resultSHA256 (scan result
bytes), and dispositions mapping every `PkgName|VulnerabilityID|InstalledVersion`
MEDIUM key to a nonempty reviewed rationale. Pass its path as --medium-review to
smoke, verify and deploy. It is not permission to suppress HIGH findings.

```bash
python3 -B scripts/release/compose-release.py smoke --target "$TARGET" --evidence "$RUN"
python3 -B scripts/release/compose-release.py verify --target "$TARGET" --evidence "$RUN"
```

STOP. Smoke uses a unique, labelled, hardened bridge container and a Docker-assigned
127.0.0.1 port. Inspect health, static assets, version, MIME and security headers.
Temporary cleanup uses captured full IDs and ownership checks. Every owned scanner
cleanup is attempted; failures block success. No network/volume/image pruning.
HTTP smoke is not browser acceptance: manually review all profiles/themes, copying,
native selection, persistence and privacy with public fixtures before deployment.

The private Compose must contain only PasswordForge, image-only/pull-never, with
the documented hardening, exact routing, no dependencies/ports/host mounts and an
existing external proxy. Custom routing/settings require review rather than bypass.

```bash
# Execute ONLY after separate production deployment authorization.
python3 -B scripts/release/compose-release.py deploy --authorize-deploy \
  --target "$TARGET" --evidence "$RUN"
```

STOP. A private evidence override selects the verified immutable image; the original
Compose remains untouched. Compose config, fresh source/image/baseline checks and
service-only up --no-build --pull never --no-deps must succeed sequentially. The
helper verifies health/HTTPS/assets after replacement. No automatic next stage.
Browser acceptance and unrelated-workload review remain required. Downtime and
recovery by corrected rebuild are accepted operating choices; no rollback image
archive is required. Never claim a failed deployment passed; preserve its evidence.

```bash
# Execute ONLY after acceptance and separate exact-image cleanup authorization.
python3 -B scripts/release/compose-release.py cleanup --accept-deployment \
  --image-id sha256:APPROVED_UNUSED_FULL_ID --target "$TARGET" --evidence "$RUN"
```

Only one explicitly selected old image per run, including its verified PasswordForge
aliases, is eligible. Active, referenced, shared or registry-tagged images stop.
Never use force image deletion or broad pruning. Keep evidence independently.

An interrupted stage directory blocks replay. Preserve partial logs/resources;
review captured ownership before separately approved recovery. Never clear stale
locks blindly. All stages require the same target checksum and verified source.
Filesystem TOCTOU and other administrators remain trusted-operator limitations.
Source packages require a new clean reviewed commit containing this implementation;
the previous approved archive cannot silently authorize the enlarged inventory.

## Controlled recovery of a failed canonical export

Execution remains HOLD until independent review and separate operator approval.
`recover-export` never builds, pulls, retags, scans, starts containers or deploys.
It exports the existing authenticated top-level OCI index without platform filtering,
then uses the unchanged full graph/layer/config/attestation verifier. Ordinary build
and scan exports also use the authenticated top-level index, with tag continuity
checks before and after export. A selected manifest digest is not an export reference.

The original failure root, report, evidence manifest and run remain immutable.
Recovery is supported only when the build status is integer 0, export status integer
1 and its error identifies the recorded selected manifest as `No such image`.
Require the original complete hash inventory, Buildx metadata/IID/provenance,
frozen context and original clean committed source checkout. Missing evidence,
changed source, another failure cause, absent descriptors or tag drift stop recovery.
No missing historical inspection or success record is invented.

The corrected recovery tool is separate from the original build source. `--source`
points to the original checkout at its original commit. Successful recovery retains
that commit, source fingerprint and build ownership/run label. A distinct recovery
operation ID and corrected tool SHA-256 are recorded. Later stages continue checking
the original source and hash-authenticated origin evidence.

Before execution, obtain a fresh read-only baseline and explicit operator review.
Prepare a private JSON outside source with exactly: `schemaVersion` (integer 1),
`failureManifestSHA256`, `failureReportSHA256`, `originalBaselineSHA256`,
`targetSHA256`, `toolSHA256`, `reviewedAt`, `expiresAt`, `containers`, `differences`.
The original baseline hash covers `evidence/baseline-before.json`; target and tool
hashes cover the exact new private target bytes and corrected compose-release.py.
Use timezone-aware ISO timestamps, at most one hour apart. Future/expired review
fails before Docker contact. The separately supplied review checksum is the
operator's authorization binding, not a signature or proof of external trust.

`containers` is the complete reviewed inventory, sorted by name, with exact fields
`name` (Docker /name), `id`, `image`, `running`, `status`, `startedAt`, `health`,
`restartCount`. `differences` lists each changed container as
`{"name":"/name","changes":{"startedAt":{"before":"old","now":"new"}}}`,
including restartCount changes in the same form. No difference may be omitted.
By default only reviewed start-time/restart-count differences are supported.
Other identity, image, running, status or health changes require investigation.
The exact exception below supports only the independently evidenced Homarr update. A reboot
alone establishes neither corruption nor permission to replace the old baseline.
Host, daemon, Compose checksum and proxy identity must still match the old target.
Live inventory must match the reviewed baseline before output creation and after
export. No change to production Compose or unrelated services is authorized.

An optional `resourceReview` permits one exact `/homarr` replacement and one exact
replacement of the default `bridge`. It has exactly `evidencePath` (absolute,
symlink-free), `evidenceSHA256`, `containerReplacements` and `bridgeReplacement`.
`containerReplacements` is empty or contains one record:
`{"name":"/homarr","before":{"id":"FULL_OLD_ID","image":"sha256:FULL_OLD_IMAGE"},"now":{"id":"FULL_NEW_ID","image":"sha256:FULL_NEW_IMAGE"}}`.
Both identities must change; the reviewed container must remain running with its
unchanged recorded healthy/no-healthcheck state. Include every ID/image/start-time/
restart-count difference in `differences`. PasswordForge, Traefik, Portainer,
Watchtower and all other container replacements are unsupported.
`bridgeReplacement` is null or exactly
`{"before":"FULL_OLD_ID","now":"FULL_NEW_ID","acknowledged":true,"historicalEquivalence":"not-established"}`.
This is an explicit acknowledgment of observed identity change, not an assertion
that historical configuration was equivalent. It applies only to recover-export.
No wildcard, unused exception or unrestricted replacement baseline is accepted.

The separate, independently recorded resource JSON has exactly `hostMachineId`,
`dockerDaemonId`, `observedAt`, `originalBaselineSHA256`, `networksBefore`,
`networksNow`, `volumesBefore`, `volumesNow`, `protectionBefore`, `protectionNow`,
`watchtowerEvents`. Bind its hash into the operator-reviewed baseline; observation
must precede review by no more than one hour. A checksum binds bytes, not their
external authenticity. Obtain trusted pre-change evidence for protected resources; never copy current
configuration into a supposed historical snapshot. Original failure evidence stays
read-only. Only the exactly acknowledged historical default-bridge record may use
`configuration: null`; this records unavailable history without inferring equivalence.

Network records contain `id`, `name`, `configuration`. Configuration includes every
Docker inspect field `Driver`, `Scope`, `Internal`, `Attachable`, `Ingress`,
`EnableIPv4`, `EnableIPv6`, `IPAM`, `Options`, `Labels`, `ConfigOnly`, `ConfigFrom`.
All network names and protected configurations must match exactly. Only the exactly
acknowledged default-bridge ID may differ; its historical configuration must be null.
Current bridge configuration is fully recorded and must identify Docker's default
local IPv4 bridge with its default-bridge option true. No historical equivalence is
claimed or required for this image-export-only operation. The original/current IDs
must match the original inventory and fresh evidence. Protect the proxy identity
and configuration and all PasswordForge attachments without exceptions.
The fresh complete network configuration is compared before and after export;
additional drift, another network replacement or an unused acknowledgment stops
recovery. This exception does not apply to build, scan, smoke, verify, deploy or
cleanup stages. A reboot is not evidence of historical equivalence.

Volume records contain `name`, `driver`, `scope`, `mountpoint`, `optionsSHA256`,
`labelsSHA256`; hash Options/Labels using SHA-256 of UTF-8 `json.dumps(value,
sort_keys=True)`, preserving null. Inventory and records must match exactly.
Protection maps cover every container by /name, each with `labels` (Compose project/
service and Traefik labels) and `networks` (name to ID). Routing/ownership cannot
change. Only non-PasswordForge bridge attachments may follow the approved bridge ID.

For Homarr, `watchtowerEvents` contains exactly three ordered `{time,message}`
records: `Found new ghcr.io/homarr-labs/homarr:TAG image (NEW_IMAGE_FIRST12)`,
`Stopping /homarr (OLD_CONTAINER_FIRST12) with SIGTERM`, `Creating /homarr`.
Use timezone-aware original log timestamps; creation must match the current start
within two minutes. Events must be independently captured and remain readable in
Watchtower's last 24 hours of logs during recovery. No exception means no events.
Checksummed resource evidence is validated offline; live resource/configuration,
container and log checks repeat before/after export. New drift stops recovery.
Without resourceReview, any network-ID or volume-name drift also stops recovery.

This review does not authorize export. STOP for independent code review and a fresh
explicit operator decision before preparing live approval or executing recovery.

After explicit recovery approval, run only this block, with reviewed absolute paths
and exact checksums. RECOVERY_RUN must not exist and must be outside source and the
old failed run, beneath the new target's operator-owned mode-0700 evidence root.

```bash
python3 -B scripts/release/compose-release.py recover-export \
  --target "$TARGET" --evidence "$RECOVERY_RUN" \
  --failed-run "$ORIGINAL_FAILED_RUN" \
  --failure-manifest-sha256 "$ORIGINAL_EVIDENCE_MANIFEST_SHA256" \
  --failure-report-sha256 "$ORIGINAL_FAILURE_REPORT_SHA256" \
  --source "$ORIGINAL_SOURCE" \
  --baseline-review "$REVIEWED_BASELINE_JSON" \
  --baseline-review-sha256 "$REVIEWED_BASELINE_SHA256"
```

STOP. Review the new run.json, original evidence hashes, baseline comparison,
recovery identity and authenticated index/manifest/config roles. An occupied or
interrupted recovery directory cannot be replayed. Failure preserves partial new
evidence and never changes the original failure files or candidate. Do not clear
locks, remove resources, retry, scan or deploy automatically. Full containerd archive
compatibility still requires the separately authorized real recovery operation.

## Legacy workflow — retained during migration

Every host operation needs separate approval. Run one operation, review evidence,
then STOP. This file is an example procedure, not deployment authorization.
No GitHub/registry publishing, automatic release, Docker pruning or automatic
image acquisition is provided. Preserve private deployment configuration/evidence.

## 1. Read-only preflight — STOP on failure

Required: non-root Ubuntu 24.04 operator, local Docker Engine 29.x, Compose,
Buildx default/docker builder, linux/amd64, Bash, Python 3 and standard tools.
Host Node/npm are not required. One operator and no concurrent Docker writers are
required; per-user locking cannot protect against other administrators.

Privately record approved baseline metadata as JSON outside source, with exactly
these string fields (actual approved values, no credentials):

- releaseVersion, sourceCommit (the new committed source, not a historical commit)
- sourceArchiveSHA256 and sourceManifestSHA256 (exact approved archive and manifest bytes)
- productionContainerId (full 64 hex), productionImageId (sha256 plus 64 hex)
- productionImageTag (passwordforge:X.Y.Z), productionStartedAt (exact Docker UTC)
- productionComposePath (absolute), productionComposeSHA256 (64 hex)
- composeProject, composeService and productionContainerName
- proxyNetwork, proxyNetworkId (full 64 hex), routerHost, httpsEntryPoint

Service/container must be passwordforge; candidate and production tags must differ.
Obtain the archive and private-metadata SHA-256 from independently approved records.
No field has a default. Do not edit expectations merely to obtain a passing result.
The private file must not be checked into Git or included in packages.

```bash
# Assign real reviewed paths/identities privately; these placeholders are nonproduction.
SOURCE=/path/to/reviewed-source/passwordforge
ARCHIVE=/path/to/approved-source.tar.gz
ARCHIVE_SHA256=REPLACE_WITH_APPROVED_64_HEX
PRIVATE_METADATA=/path/to/private/approved-baseline.json
PRIVATE_METADATA_SHA256=REPLACE_WITH_APPROVED_64_HEX
cd -- "$SOURCE"
export PYTHONDONTWRITEBYTECODE=1
bash scripts/release/host-preflight.sh "$ARCHIVE" "$ARCHIVE_SHA256" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256"
```

Preflight verifies both archive and actual staged source/checksums/version/commit, exact protected container/image/
start time/Compose checksum/network identity, healthy status and private routing;
checks local builder/architecture, cached pinned images, candidate conflicts and
capacity. It performs no extraction or Docker mutation. TLS needs separate trusted
HTTPS observation; never use curl -k. Review disk/RAM capacity explicitly.
Acquire any missing pinned images only through a separately approved operator
operation, never by modifying the script or bypassing its cache checks.

Application tests/TypeScript/build, npm audit and browser suites run locally.
Normal/optimized Python release tests and Bash syntax checks also run before handoff.
Release inventory must be exact; package only clean committed source. Preserve an
approved version distinct from the current production version before candidate build.

## 2. Build — STOP for independent image review

```bash
python3 -B scripts/release/docker-release.py --approval "$ARCHIVE" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256" build REVIEWED_VERSION
```

The helper first checks the entire staged source against the approved manifest:
exact paths, regular files, bytes, sizes and POSIX modes; no unexpected source or
links. Only root .git/node_modules/dist/artifacts/validation-results and Python
bytecode directories are outside this inventory; none enter the build context.
Keep private metadata outside source. New metadata fields are mandatory; previous
approval documents must be independently reapproved, never silently migrated.

Docker receives a deterministic in-memory tar on stdin, captured from the approved
archive. It cannot reopen mutable staged source files. Fresh source/approval and
protected production checks immediately precede the build and follow it. A source
change fails the attempt even though submitted build bytes remain approved. The
snapshot, manifest and complete exported image graph/layers remain private evidence.
Do not edit them or replay interrupted attempts. This is not protection against a
host administrator replacing the trusted helper or daemon.

The helper verifies cached digest-pinned FROM images and refuses an occupied version
tag. It uses local default builder, linux/amd64 and --pull=false. It never executes
docker pull. BuildKit can still resolve registry metadata; npm/Alpine package steps
need separately approved network access. This is not an offline-build guarantee.
If a cached image disappears through another administrator, STOP; the single-operator
boundary is mandatory. Do not run this workflow concurrently with other image writers.

Record the printed evidence path, candidate tag, daemon/index/manifest/config roles,
source fingerprint, metadata and build logs. Export verification hashes the actual
runtime graph and layer bytes. Identities are not interchangeable. Attestation
content checks are not signature verification. Failures preserve private evidence;
never delete or replace candidate tags automatically. Build-proof schemaVersion 1
requires approval identity, source fingerprint, unique attempt, tag, immutable
image/config/manifest/export IDs and roles, metadata and SHA-256 of every required
artifact: approval.json, SOURCE-MANIFEST.json, build-context.tar, build-started.json,
example-compose.yaml, build.log, build.log.status.json, build.iid, build-metadata.json,
build-identity.tar.
image.id and build-identity.json must agree with build.json. Missing exportId,
unsupported schema, corrupted or mixed proof stops before scanning/runtime.
The export graph/layer verification is repeated against the current image identity.
Legacy verify-existing is blocked: it cannot establish a missing approved context;
use a separately approved fresh build, with an unoccupied tag, never overwrite it.

```bash
EVIDENCE=/exact/private/validation-results/path
IMAGE=passwordforge:REVIEWED_VERSION
```

## 3. Scan — STOP for findings review

```bash
python3 -B scripts/release/docker-release.py --approval "$ARCHIVE" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256" scan "$IMAGE" "$EVIDENCE"
```

Scanner reference is pinned in docker-release.py and SCANNER-PROVENANCE.json.
It must already be cached; no automatic pull is allowed. No Docker socket mount.
Database acquisition alone uses bridge with approved network access; both actual
analysis passes use network none and the same archive/database. Native JSON uses
--list-all-pkgs; the explicit typed-template pass does not. Preserve full inventory.
Wrong exact types, malformed results, warnings/errors, stale/expired database and
HIGH/CRITICAL/UNKNOWN block continuation. MEDIUM needs written operator disposition.
Keep scanner logs, status, DB metadata, config identity and scan reports privately.

## 4. Runtime — STOP before deployment

```bash
python3 -B scripts/release/docker-release.py --approval "$ARCHIVE" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256" runtime "$IMAGE" "$EVIDENCE" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256"
python3 -B scripts/release/docker-release.py --approval "$ARCHIVE" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256" check "$IMAGE" "$EVIDENCE"
```

Same immutable image, unique owned container, existing bridge only, loopback18080,
non-root/read-only/cap drop/no-new-privileges/limits/tmpfs; no production proxy or
Traefik routing. Check health, all eight JS assets, HTML/CSS/licenses, MIME, CSP and
headers, package fixes and fixture exclusion. Browser smoke uses public fixtures.
Cleanup uses captured full container IDs and verified labels, not reusable names.
Success evidence requires successful cleanup. No image/network/volume deletion.
Runtime requires the approved release version to match package, tag and image
metadata. Before container creation it checks the full production container/image,
start time, project/service and healthy running state against the explicit private
baseline. Missing/failed inspection or inconsistent versions stop.
Every operation revalidates the same approved source/archive/private metadata.
Scan and runtime receipts bind the approval and the canonical complete build proof.
Final check returns only the verified immutable image ID. Deployment/rollback
approval-binding corrections remain a separate checkpoint; do not use section 5 yet.

## 5. Deploy — separate approval REQUIRED

BLOCKED pending the next deployment-binding checkpoint. The historical illustrative
block below deliberately remains unchanged and fails the new explicit-approval CLI
gate. It is not an executable recommendation for this source checkpoint.

This illustrative block operates on an approved private Compose file, never on
this repository's example. Before use, verify fresh protected identities and
routing from private metadata, backup exact prior Compose bytes/release information,
preserve the old immutable image and confirm rollback approval boundaries. Stop
on any drift. Review the private configuration: image-only, pull_policy never,
linux/amd64, expected project/service/routing and all documented runtime hardening.
MEDIUM dispositions and trusted TLS checks must be complete. Readiness is not
established by an exit status alone. Obtain explicit deployment authorization.

```bash
(
set -Eeuo pipefail
umask 077
APPROVED_COMPOSE=$(python3 -B "$SOURCE/scripts/release/private_metadata.py" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256" productionComposePath) || exit $?
EXPECTED_COMPOSE_SHA256=$(python3 -B "$SOURCE/scripts/release/private_metadata.py" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256" productionComposeSHA256) || exit $?
PROJECT=$(python3 -B "$SOURCE/scripts/release/private_metadata.py" "$PRIVATE_METADATA" "$PRIVATE_METADATA_SHA256" composeProject) || exit $?
test "$(sha256sum -- "$APPROVED_COMPOSE" | cut -d ' ' -f1)" = "$EXPECTED_COMPOSE_SHA256" || exit 2
IMAGE_ID=$(python3 -B scripts/release/docker-release.py check "$IMAGE" "$EVIDENCE") || exit $?
[[ $IMAGE_ID =~ ^sha256:[0-9a-f]{64}$ ]] || exit 2
( set -o noclobber; printf 'services:
  passwordforge:
    image: %s
' "$IMAGE_ID" > "$EVIDENCE/deploy-image.yaml" ) || exit $?
docker --host unix:///var/run/docker.sock compose --env-file /dev/null -p "$PROJECT" -f "$APPROVED_COMPOSE" -f "$EVIDENCE/deploy-image.yaml" config --quiet || exit $?
docker --host unix:///var/run/docker.sock compose --env-file /dev/null -p "$PROJECT" -f "$APPROVED_COMPOSE" -f "$EVIDENCE/deploy-image.yaml" up -d --no-build --pull never passwordforge || exit $?
)
```

Paste only after approval as a complete fail-closed block. Failed metadata, checksum,
identity, exclusive override or Compose checks prevent up, including in an outer
conditional. It does not overwrite the private Compose file. Only PasswordForge is
recreated; approved private Compose may contain no additional service dependencies.
Wait for healthy, confirm the exact running image and verify trusted public HTTPS,
headers, assets, all profiles/themes, persistence/copy/privacy, responsive layouts
and unchanged unrelated workloads. No generated passwords belong in evidence.

## 6. Rollback and interruptions

Rollback is a separately authorized operation. Restore/use the exact privately
saved prior Compose bytes and retained immutable image; verify checksum/tag-ID/
project/service/routing before the same no-build/no-pull service-only replacement.
Repeat health, trusted HTTPS and asset/security checks. Preserve failure evidence.
No automatic rollback, old-image deletion, global pruning or infrastructure repair.

SIGINT/SIGTERM fail the operation. Power loss may leave an operator lock at
~/.cache/passwordforge-docker.lock, evidence or owned containers. Inspect exact
ownership and live process state before separately approved recovery. Never clear
locks blindly or replay started markers. Cleanup attempts each captured owned ID;
unknown ownership/failure remains a blocker. Direct runtime.sh replay is prohibited
by a one-use locked-parent capability. No workflow can exclude other administrators;
ensure a single operator and no external build/retag/deploy activity.

## Source packaging (local, not a host operation)

After validation, reviewed changes and a clean commit, run package-source.py with
a fresh output directory outside source. It packages committed bytes from the exact
inventory with fixed tar/gzip metadata and matching embedded/external manifests.
Compare two independently generated archives. Never include private metadata,
deployment evidence, credentials, caches or previous archives. Source determinism
is not proof of byte-identical container builds or vulnerability freedom.
