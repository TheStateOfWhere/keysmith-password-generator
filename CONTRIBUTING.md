# Development checklist

Keep changes small and reviewed. Do not include deployment credentials, host
identities, real passwords or private evidence. The application is MIT-licensed
(LICENSE); dictionary/data licenses, attribution and modification notices must be
retained separately and are not relicensed.

Run npm ci, npm test, npx --no-install tsc --noEmit, normal/optimized release-tool
unittests, Bash syntax checks and the relevant external Edge suites. Do not log
password values on failures. Use controlled public fixtures for screenshots.

Preserve exact entropy/counting/sampling, global exclusions and Readable behavior.
Dictionary changes require provenance and independent entropy review. No frameworks,
backend storage or telemetry are planned. There is no automatic release workflow.

Source uses LF; data/ is byte-preserved. Do not normalize pinned data or alter
checksums without approval. Add new repository files to RELEASE-INVENTORY.json;
packaging requires a clean committed tree with exact inventory. Artifacts stay
outside source packages. A future release must revalidate Docker and browser gates.

Use main with short-lived descriptive branches. Annotated vX.Y.Z tags follow a
qualified release; creating or pushing tags is a separate publication action.
