# Security guidance

KeySmith 1.0.0 is prepared for its first stable MIT-licensed release. One candidate
has passed artifact, vulnerability and isolated runtime gates; the deployed image
remains 0.7.0. This does not qualify an independent rebuild or authorize public
publication/deployment. See INSTALLATION.md and FRESH-INSTALL-ACCEPTANCE.md.

## Confidential reporting: intended GitHub PVR process

GitHub Private Vulnerability Reporting (PVR) is the selected reporting channel.
**Enablement, notification delivery and maintainer receipt have not been verified.**
This document alone does not enable PVR or establish that a report is monitored.
No response-time or public support-lifetime guarantee is made.

Once enabled, open the repository's [Security advisories page](https://github.com/TheStateOfWhere/keysmith-password-generator/security/advisories)
and select **Report a vulnerability**. Supply affected version, impact and minimal
nonsecret reproduction details through that private form. Do not include real
passwords, private keys, credentials, production configuration or unrelated data.
Do not post unpatched vulnerability details in public issues or discussions.
If the button is unavailable, ask the maintainer to enable a confidential channel
without disclosing the vulnerability in that public request. No unverified email
address is advertised as an alternative.

### Administrator actions (not performed here)

After the separately approved repository setup permits PVR:

1. With repository admin/security permissions, open Settings, then the security
   settings (currently **Security and quality > Advanced Security**), and enable
   **Private vulnerability reporting**. Confirm availability for the repository;
   GitHub documents repository-level PVR for public repositories. Do not change
   visibility merely to test this without separate approval.
2. Designate a responsible maintainer. For that account, enable repository
   notifications: Watch > All Activity or Custom > Security alerts. In personal
   notification settings, enable Email under Subscriptions > Watching and verify
   the receiving mailbox. Keep personal addresses/settings out of repository files.
3. Verify delivery using a consenting separate reporter account without repository
   admin/security permissions. Admins can create draft advisories directly, which
   does not test the external reporting path. Submit a benign private report titled
   `PVR delivery test - no vulnerability`, with a unique nonsecret marker and no
   exploit, password or production data. Do not create a public issue.
4. Have the maintainer confirm notification delivery, locate the private report in
   Advisories/Triage, and reply privately. Have the reporter confirm that reply and
   that the report is not visible to a signed-out visitor. Close it as a delivery
   test with a private explanation. Do not publish an advisory, request a CVE or
   create a temporary fork for this test.
5. Record date and PASS/FAIL for form availability, notification, receipt and reply
   in private operational evidence. Only then update the reporting-status statement
   after review. Failed/unperformed delivery remains a public-launch readiness gate.
   Repository creation/visibility approval precedes enablement if GitHub requires
   a public repository; this does not authorize that transition now.

Official instructions: [enable PVR and notifications](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository),
[submit a private report](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately),
and [review reports](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/manage-vulnerability-reports).

## Security boundaries

Generation uses browser Web Crypto with unbiased sampling, exact >=64-bit gates
and complete validation. No backend generator, telemetry or password persistence
exists. Only passwordforge.theme stores an approved preference identifier.
CSP, no-store and other headers are required deployment controls. TLS, redirects,
HSTS and access controls belong to the operator and require independent evidence.

Clipboard history, extensions, malicious same-origin code, compromised clients and
memory inspection are outside the application's protection. Clear/hide do not
provide cryptographic erasure. Entropy assumes uniform sampling; choosing favorites
can bias results. Password handling and MFA at the destination system matter.

## Supported maintenance boundary

Source version 1.0.0 preserves the approved 0.7.0 application behavior. Existing
desktop support and operator acceptance,
including the nonblocking NVDA/physical-mobile dispositions, are recorded in
README.md. Automated Edge evidence is not a claim of full cross-browser or
assistive-technology certification.

The internal operator owns maintenance; there is no promised public support
lifetime or unattended security update service. Review locked build dependencies,
pinned base/scanner images, exact Alpine packages and relevant advisories before
each release and periodically during internal operation. Acquire/rebuild only
reviewed updates; do not silently float pins or enable automatic production updates.
Use fresh full-image scans: HIGH/CRITICAL/UNKNOWN block release; MEDIUM requires
written disposition.
A previous zero-finding scan does not prove future or undetectable vulnerability
freedom. Never suppress scanner failures/warnings to obtain a clean result.

No deployment credentials belong in the repository or CI. Production changes,
image acquisition, scans/runtime resources, rollback and cleanup require explicit
operator authorization. Preserve private approval/evidence and existing resources.

DEPLOYMENT.md is the active Buildx/stateless-verifier/Trivy/Compose procedure.
Legacy orchestrators and recovery-only tooling are historical, not required for
ordinary releases. Preserve image identity and unrelated services at every stage.
