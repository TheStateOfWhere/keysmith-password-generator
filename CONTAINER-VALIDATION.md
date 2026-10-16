# Isolated container validation

Follow scripts/release/OPERATOR-RUNBOOK.md only after separate authorization.
Use the local default Docker builder with linux/amd64, digest-pinned cached images,
strict ownership/identity binding and unique isolated resources. No Docker operation
is authorized by publication preparation. No automatic pull, publishing or pruning.
Build network access to registries/npm/Alpine must be reviewed separately.

Two-pass pinned Trivy scanning must bind to the exact exported runtime config.
Warnings, failures, malformed JSON, expired database, HIGH/CRITICAL/UNKNOWN findings
block continuation. MEDIUM findings require explicit written review. Runtime tests
require the same immutable image, non-root/read-only/capabilities/limits/tmpfs,
loopback-only delivery, all eight JS assets including theme.js, MIME/CSP/headers,
health, fixture exclusion and successful owned cleanup. No production proxy joining.

Local tests mock Docker. Host validation remains unverified for this publication
candidate. Image/config/index/manifest digests are not interchangeable. Exact base
package availability and container reproducibility are not assumed. Review official
image updates manually, verify actual digest bytes, and repeat all gates.
