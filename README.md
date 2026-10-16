# KeySmith 1.0.0 release preparation

Source is prepared for KeySmith's first stable, MIT-licensed 1.0.0 release.
A 1.0.0 candidate has passed isolated Docker artifact, vulnerability and runtime
qualification. Production remains the deployed, validated 0.7.0 image; deployment
of the candidate still requires separate authorization.
The supported release path is standard Docker Buildx, the stateless artifact
verifier, pinned Trivy, an isolated smoke test and PasswordForge-only Docker Compose
recreation. See DEPLOYMENT.md. Legacy orchestrators and recovery-only instructions
are retained for historical reference, not as the active deployment workflow.

Self-hosted, static browser password generation with three profiles and five themes.
Application/package/template metadata is 1.0.0. Qualification of one private
candidate does not qualify an independent rebuild or authorize public distribution.
The KeySmith application is licensed under [MIT](LICENSE), Copyright (c) 2026
KeySmith Contributors. Third-party dictionary/data material is not relicensed:
retain its separate ESDB/EFF licenses, attribution and modification notices in
`data/` and the generated `/licenses/` assets. Redistributed application copies
must also include the MIT notice; see INSTALLATION.md. The npm `private` flag
prevents accidental npm publication and does not restrict the MIT license.

## Existing functionality acceptance and desktop support

The evidence below qualifies the unchanged 0.7.0 functionality. It does not replace
artifact, vulnerability and runtime qualification of each independently built image.

The retained automated desktop evidence is Microsoft Edge on Windows. This is the
evidence-backed desktop support baseline; no automated Firefox, Chrome or Safari
qualification is claimed. The operator has confirmed completed desktop UI and RDP
password-transcription acceptance, including the approved themes and dropdowns.
These are operator-attested results, not newly executed tests in this stabilization.

The operator explicitly accepts unexecuted NVDA and physical-mobile testing as
nonblocking for this internal application. Those dispositions are not test passes
or accessibility/device certification. Automated keyboard, accessibility-tree,
responsive and contrast checks remain supporting evidence. No unresolved manual
defect was identified in the available accepted desktop/RDP records.

This summary supersedes the earlier pending dispositions for the current internal
scope; historical reports remain unchanged. Acceptance evidence remains privately
retained by the operator, not a dependency of an independent installation. The
accepted production record covers 17 public HTTP/security checks, 107 live Edge
checks and six dropdown/theme cases. Wider browser, assistive-technology or mobile support needs
its own evidence; it is not a prerequisite imposed on this internal release.

## Independent installation (publication preparation)

See [INSTALLATION.md](INSTALLATION.md) for standalone Compose and generic HTTPS
proxy examples, and [FRESH-INSTALL-ACCEPTANCE.md](FRESH-INSTALL-ACCEPTANCE.md) for
the pending clean-environment test. These use the intended public GitHub source,
not private images or evidence. MIT licensing is approved. The public-launch
plan must include administrator
enablement and delivery verification of GitHub Private Vulnerability Reporting
once the repository is eligible, as described in SECURITY.md.
That reporting service and the public installation tests are not yet verified.
The new examples are separate complete files; never overlay them onto compose.yaml.

## Local development

Node.js 22+ and npm are required on the development workstation:

```sh
npm ci
npm test
npx --no-install tsc --noEmit
npm run dev
python3 -B -m unittest discover -s scripts/release/tests -q
python3 -O -B -m unittest discover -s scripts/release/tests -q
```

The preview binds only to localhost:4173. npm test builds static assets and checks
pinned dictionary integrity before testing. Node/npm are not host prerequisites
for the multistage Docker build. There are no third-party runtime dependencies,
external fonts, dictionary APIs, analytics or telemetry.

## Profiles

- **Readable (default):** three distinct dictionary words in
  Titlecase.UPPERCASE.Titlecase.suffix format. Defaults are word lengths 4–12 and
  suffix length 6: complete passwords are 21–45 characters. Excludes l L i I o O
  0 1 everywhere. Suffix digits are 23456789 and symbols are -_@#%*+; at least one
  digit and symbol are required, with identical adjacent symbols rejected.
- **Strong Random:** 20 characters by default, all four categories enabled and
  required at least once; conservative symbols and ambiguous exclusions enabled.
- **Custom Policy:** printable ASCII, length up to 128, allowed categories,
  minimum category counts, literal symbols and global exclusions. Space may be
  explicitly permitted. No Unicode or regex policies. Raw symbol/exclusion fields
  allow 256 characters; oversized input is rejected, never truncated.

All profiles require an exact password-space count of at least 2^64 before
consuming randomness and validate full output. Random profiles use exact BigInt
counting and unbiased cryptographic rank sampling. Estimated entropy assumes
uniform generation; it is not an offline-attack guarantee. Configured-rule
compliance does not establish compliance with an unspecified customer policy.

Readable has 17,195 eligible words; default suffix count is 9,453,696 and default
entropy is approximately 65.38 bits. Fixed case and separators contribute no
entropy. data/entropy-report.json covers all 45 word-length intervals and their
minimum suffix requirements. Dictionary frequency/familiarity is not guaranteed.

## Display, themes and privacy

The application is branded KeySmith; technical package and deployment identifiers remain PasswordForge. The interface uses a centered Focus view for a single password
and a full-width Password Sheet for multiple passwords, introduced by “Strong
passwords. Made simple.” Readable words and their literal periods wrap together
without adding whitespace. Batches show all numbered results with per-result actions, Copy All, Clear batch, and Generate above and below the list. Profiles can be switched from the workspace or settings dialog. Show passwords controls output visibility, and Large Text enlarges every result. Component copying stays behind “Copy a word or suffix”; whole-password Copy remains visible.

Readable and Strong Random settings open in a native modal dialog. Custom Policy controls and their validation appear inline in the workspace, using the same form state and generation rules. Tab and Shift+Tab cycle inside the dialog; Escape, Close and Done restore focus to Settings. Invalid settings remain signposted outside the dialog. Generate controls use normal document flow, with no sticky overlays. All five themes retain their existing persistence behavior.

Native substring selection, explicit copying, Copy All, individual regeneration,
hiding and large-text mode are supported. Readable also has four component-copy
controls. Settings changes invalidate existing output. Duplicate complete batch
passwords are possible; uniqueness is not enforced.

Automatic follows OS light/dark preference; Light, Dark, Emerald and Amethyst
apply immediately. Only a validated theme identifier is saved in origin-scoped
localStorage under passwordforge.theme. Denied storage leaves session themes usable.
Themes do not change passwords, policies, randomness, visibility or clipboard state.

Passwords, policies, clipboard contents and random state are never persisted by
the application. Generation is browser-only, without password-bearing requests,
URLs or logs. Clear/reload removes application results; this is not secure memory
zeroization and cannot erase OS clipboard history. Hiding masks display, not memory.
Clipboard API support requires HTTPS or localhost. Browser extensions and a
compromised browser/device remain outside this protection.

Loaded assets work without generation-time network access. Offline reload needs
reachable local assets; there is no service worker. Build dependency installation,
Alpine package installation and vulnerability-database acquisition may need network
access after separate operator approval.

## Docker and operation

Dockerfile is digest-pinned and multistage. Production compose.yaml is a generic
Traefik example for password.example.invalid, never a live deployment file. It has
no build section or published ports, pull_policy never, linux/amd64, UID/GID
10001:10001, read-only root, ALL capabilities dropped, no-new-privileges, bounded
/tmp and memory/CPU/PID limits. compose.dev.yaml is standalone and loopback-only.
See DEPLOYMENT.md for the active workflow; older runbooks describe historical tooling.
Do not point generic example commands at production without private review.

The operator verifies the target host, Docker endpoint/daemon, source and immutable
image identities before authorized operations. Actual routing/configuration and
evidence stay private. Pinned base/scanner images must be available; acquisition,
build/database network access, deployment and cleanup require their own approval.
Buildx may resolve registries and npm/Alpine steps may need network access; this is
not an offline container-build claim. No custom recovery or multi-authority release
framework is required. Preserve unrelated services; never use broad Docker pruning.

## Attribution and validation

Retain every file under data/. See data/NOTICE.md, ESDB-Copyright.txt and CC-BY-4.0.txt.
Sources, exclusions, annotations and ten approved EFF replacements are pinned and
verified locally. data/readability-review.json reviews capitalization and entropy.
Changes require explicit review; do not update hashes merely to make tests pass.
The readability test compares an independently computed report with the committed
review fixture without rewriting it. Fixture regeneration is a separate, explicitly
reviewed maintenance action, never an effect of ordinary test execution.

Optional Edge suites use an external Playwright installation via
PASSWORDFORGE_PLAYWRIGHT_MODULE and the Edge executable via
PASSWORDFORGE_BROWSER_PATH. Run the eight executable tests/browser-*.mjs suites individually
(selection, regeneration, profiles, ui-corrections, focus-copy, themes, direction-b and keysmith; direction-b validates the combined design and keysmith covers the branding/inline-policy refinements). browser-dialog.mjs and browser-artifacts.mjs are shared helpers.
Screenshots contain public fixtures and remain in ignored artifacts/ directories.
Manual desktop/RDP acceptance and the nonblocking NVDA/mobile dispositions are
recorded above. Headless checks do not prove native speech or physical-device
behavior. Source/static determinism does not prove container reproducibility.

See SECURITY.md and CONTRIBUTING.md. Private provenance, historic source, release
identities, scan evidence, deployment backups and old handoffs stay outside GitHub.
