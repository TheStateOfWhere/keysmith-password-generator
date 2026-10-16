# Fresh-install acceptance (not yet executed)

Purpose: verify the *published* source and public instructions on a clean Docker
host. Status is PENDING until the owner authorizes publication and the actual
unauthenticated GitHub installation test. Local syntax/static checks are not a
fresh-install pass. No internal artifact/image, private network, retained evidence
or development worktree may be supplied to this test.

## Inputs and safety

Use two clean disposable Linux/amd64 test environments, or separate uniquely
named Compose projects with independently reviewed cleanup. Do not run this on a
production host. Record OS, Engine/Compose/Buildx/browser versions and available
resources. Require maintained Docker 28+ and a browser capable of Web Crypto;
Microsoft Edge is the existing evidence-backed desktop baseline. Provide a real
test DNS name and trusted TLS certificate for the reverse-proxy scenario. A clean
proxy fixture must be operator-owned, digest-pinned, configured using the public
proxy documentation, and have a dedicated network; no live internal proxy or
credentials may be reused. Record its image digest and TLS/provider configuration
without credentials. Choose the maintained proxy version before authorizing the
test; this document does not invent a tested proxy pin.

MIT licensing has been approved, with the holder KeySmith Contributors; check
that the published LICENSE and third-party notices are present and unchanged.
PVR enablement/delivery must be verified separately under SECURITY.md.

Record the full public release commit supplied by the owner. On a clean machine
without a GitHub login or stored credentials:

```sh
: "${PUBLISHED_COMMIT:?Set the reviewed public release commit first}"
GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone https://github.com/TheStateOfWhere/keysmith-password-generator.git keysmith-fresh
cd keysmith-fresh
git checkout --detach "$PUBLISHED_COMMIT"
test "$(git rev-parse HEAD)" = "$PUBLISHED_COMMIT"
test -z "$(git status --porcelain)"
```

FAIL if access needs authentication, the commit is absent, source files are
missing, or the documentation requires private records. Check every published
`RELEASE-INVENTORY.json` path/mode against `git ls-files --stage`; reject unexpected
tracked files, unsafe paths or missing examples/notices. Do not silently substitute
a local repository or use a locally cached production image. Set fresh unique
`KEYSMITH_IMAGE` tags and verify they do not already exist before building.

Keep evidence in a new operator-owned directory outside the clone/build context;
never overwrite earlier evidence. Record commands, exit codes, public versions,
image/container IDs and boolean outcomes. No generated passwords, screenshots of
random output, browser traces, secrets, raw Docker events, full environment or
unrelated healthcheck output. Keep complete inspection data private; publish only
selected nonsecret settings and redacted errors.

## Scenario A: standalone

Follow INSTALLATION.md exactly with `compose.standalone.example.yaml`, project
`keysmith-local`, a new local image tag and an unused loopback port. Record:

1. `compose config` succeeds; published host IP is exactly 127.0.0.1. Build completes
   with pinned inputs and all bundled application/security tests passing. Capture
   build log and source commit. Fail if pins/tests must be bypassed.
2. Inspect the resulting image index, selected amd64 manifest and configuration
   separately; record immutable identities and version 1.0.0. Record runtime user
   and execution configuration. Never assume a platform manifest is exportable.
   A normal Compose build is not claimed to generate the stateless verifier's
   complete retained-provenance contract: if artifact qualification is required,
   follow the public Buildx procedure in DEPLOYMENT.md and require verifier PASS.
3. Run the fresh full-image Trivy policy from DEPLOYMENT.md for this exact image,
   record scanner digest/version, DB schema/timestamps, package count, errors and
   all severities. No Docker socket mount or privileged scanner. HIGH, CRITICAL,
   UNKNOWN block; MEDIUM needs written disposition; stale/incomplete/error scans
   block. Do not reuse the operator's private scan or waive a new finding.
4. `up --wait` succeeds; /healthz returns 200/ok. Inspect the created container:
   non-root10001:10001, readonly, ALL cap drop, no-new-privileges,128MiB/1CPU/128PIDs,
   approved/tmp tmpfs, no application volume/device/socket, no host namespaces.
5. Verify localhost access works and a separate machine cannot access the backend
   port. Container network is project-scoped, with no production/proxy attachment
   or Traefik registration. Check both IPv4 and IPv6 exposure where available.
6. Using the application checklist below, validate browser behavior and headers.
7. Test restart behavior on **only this disposable container**: perform a bounded
   service restart, require healthy within120s and unchanged image identity.
   On a disposable VM, an explicitly approved Docker/host restart may additionally
   validate unless-stopped startup; otherwise record boot recovery as PENDING.
8. Remove only this project using the documented `down`; confirm no owned container
   or project-created network remains. Check unrelated container IDs/states,
   network/volume inventories. Do not prune or remove arbitrary cached layers.
   Retain test source/image/evidence until separate image-removal approval and
   an all-container dependency check.

## Scenario B: reverse proxy

Use a separate fresh clone from the same actual public GitHub URL/commit and a new
image tag. Set your own domain and resolver as in INSTALLATION.md. Prepare the
new disposable proxy fixture and attach it to a dedicated external backend network.
Do not reuse an internal network. Confirm the network and Traefik router/service
names do not collide. Execute the documented `compose.traefik.example.yaml` path.

Repeat build, scan, hardening and application checks from Scenario A. Additionally:

- Require valid HTTPS/TLS hostname/chain without insecure flags, correct domain
  routing and 200/ok through the proxy. Check renewal/configuration prerequisites.
- Verify the application publishes **no host port**, the proxy uses backend8080,
  and only the intended proxy/app attach to the dedicated backend network.
- Verify wrong-host requests do not route to KeySmith; direct public backend
  access is unavailable. Check the trusted edge overwrites spoofed forwarding
  headers and public security headers are preserved exactly once.
- Confirm the proxy's healthcheck targets /healthz and an app-only bounded restart
  recovers without restarting/recreating the proxy or unrelated services.
- Run documented `down` for only the app project; verify the shared external
  network, proxy, certificates and unrelated workloads remain intact. A separate
  explicitly scoped fixture teardown may later remove only the owned disposable
  proxy/network after dependency checks. Never include it in application cleanup.

NGINX and HAProxy fragments are guidance, not claimed tested deployments. If those
paths are advertised as qualified support, authorize separate tests with their
own pinned fixture and TLS configuration; until then report them as unvalidated.

## Application and HTTP checklist (both scenarios)

- Title KeySmith, visible v1.0.0; assets served locally with appropriate MIME.
- /healthz200/ok; unknown paths and test-source URLs404. Compare served asset hashes
  with image files. Health alone is insufficient.
- Capture headers in binary without newline normalization. Use the published pure
  `security_headers` validator in scripts/release/compose-release.py or an
  independently equivalent strict check. Require the full nginx.conf CSP, no-store,
  nosniff, no-referrer, DENY and camera/microphone/geolocation disabled. Reject
  missing/duplicate/conflicting security headers and injected text in other fields.
- Focus1 and Sheet5/20; Readable capitalization/literal separators; Strong Random;
  inline Custom Policy including128characters and invalid-policy rejection.
- Entropy >=64 and configured/global exclusions enforced; no policy bypass.
- Whole/component/Copy All preserve exact bytes; clipboard rejection has safe
  feedback; Hide removes plaintext from rendered DOM/accessibility output;
  explicit hidden copying behaves as documented. Scoped regeneration leaves
  other results unchanged; Clear/profile changes invalidate prior results.
- Five themes and native dropdowns; keyboard/settings modal/Escape/focus restoration;
  Large Text applies to all results. Check1280/768/390/320 widths with no overflow.
- Block/log only request metadata (never passwords): no unexpected external runtime
  request; only theme preference persists. No generated value in URL/storage/logs.
  Use public deterministic fixtures for any screenshot; keep random output in memory.

## Decision record

For each gate record PASS (executed successfully), FAIL (reproduced defect) or
PENDING (not executed), with evidence references and exact public source/image
identities. Never replace a pending fresh-install test with internal qualification.
NVDA/physical-mobile tests remain nonblocking for the internal operator's scope;
that disposition is not a general public accessibility guarantee.

Release/public-install acceptance is GO only after reviewed MIT/third-party
notice checks, PVR enablement/delivery verification, publication approval and both
required installation scenarios pass without private inputs.
Any missing source, exposure, health, security, scan or correctness gate is HOLD.
No publication/deployment or destructive cleanup is authorized by this checklist.
