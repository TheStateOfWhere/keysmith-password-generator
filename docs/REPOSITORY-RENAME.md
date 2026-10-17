# Repository rename coordination

Zevyrn v1.1.0 metadata and active README, installation and security links are
prepared locally for the canonical repository:
`https://github.com/TheStateOfWhere/zevyrn-password-generator`

The existing public repository is still
`TheStateOfWhere/keysmith-password-generator`. The target name currently returns
404. New canonical links must be activated by the authorized repository rename
before publishing these prepared documentation changes. The clone command keeps
`zevyrn-password-generator` as its explicit local folder.

Recheck target-name availability and the remote baseline before execution.
Rename the existing repository, preserving its ID, owner, default branch and
history. Update active owned Git remotes, verify the new URL and old redirects,
and do not reuse the old name. Confirm installed GitHub Apps, external consumers
and deploy-key retention with the owner; do not change access without approval.
No README badges, Pages site or Actions workflows currently require migration.
Relative documentation and screenshot paths remain unchanged.

Keep existing `keysmith` Compose services, project/image identifiers, proxy route
filenames, `KEYSMITH_*` variables and external TLS paths for compatibility. The
retained `keysmith:1.0.0-local` image tag is a local compatibility name; application
and OCI version metadata is 1.1.0. No Compose file change is needed for this update.
A repository rename does not require changing application hostnames or deployment
resources. Historical licenses, dictionary provenance and release notes remain
historical. Preserve the existing KeySmith v1.0.0 tag/release exactly.

Local version preparation does not create a v1.1.0 tag or release. Commit, push,
repository rename, tagging, release publication and deployment require separate
authorization. No public operation is performed during preparation.
