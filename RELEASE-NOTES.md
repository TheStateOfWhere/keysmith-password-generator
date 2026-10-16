# KeySmith 1.0.0 release preparation

First stable release preparation for the existing approved application. No
feature-development or interface redesign is included.

- Preserve Readable, Strong Random and Custom Policy; Focus and Password Sheet;
  modal settings, inline policy, all five themes, Large Text and exact copying.
- Preserve cryptographic randomness, the exact 64-bit minimum, dictionary data,
  character exclusions, browser security headers and container hardening.
- Keep dependency and base/scanner image pins unchanged. Technical package,
  image and Compose identifiers remain PasswordForge/passwordforge.
- Carry forward operator-confirmed desktop/RDP acceptance and the explicitly
  nonblocking NVDA/physical-mobile dispositions; no new manual tests are claimed.
- Ordinary readability tests compare the approved fixture without rewriting it.
- License the application under MIT, Copyright (c) 2026 KeySmith Contributors.
  Retain the separately licensed ESDB/EFF data and all third-party notices.
- Prepare GitHub Private Vulnerability Reporting instructions and standalone/
  proxy installation examples for the proposed keysmith-password-generator repo.
  PVR enablement/delivery and clean public-source installation tests remain pending.

Version metadata is 1.0.0. One immutable 1.0.0 candidate has passed source/artifact,
vulnerability and isolated runtime/browser qualification. Production remains the
validated 0.7.0 deployment. Documentation/license changes do not rebuild, rescan,
re-attribute or deploy that candidate. Public publication and production deployment
still need separate authorization.

The sections below are historical release-preparation records. The 0.7.0 candidate
was subsequently qualified and deployed; its original preparation text is retained.
Earlier proprietary/private licensing statements describe the policy at that time
and are superseded for the KeySmith application by the current MIT LICENSE.
Third-party licenses remain unchanged.

---

# KeySmith 0.7.0 release candidate

KeySmith introduces the Focus view for one password, a Password Sheet for batches,
modal secondary settings and inline Custom Policy configuration. Branding uses a
local key icon; Light, Dark, Emerald, Amethyst and Automatic remain available.
Large Text, exact selection/copying and explicit copying while hidden are retained.

Generation algorithms, dictionary data, the 64-bit minimum entropy policy,
cryptographic randomness, forbidden-character rules, dependency/base/scanner pins,
CSP and runtime hardening are unchanged. Technical repository, package, Docker and
deployment identifiers remain PasswordForge/passwordforge.

This candidate is not authorized for deployment or publication. A clean Docker
build, authenticated image identity, vulnerability policy and hardened container
smoke test must pass before deployment can be considered.

---

# PasswordForge 0.6.0 publication candidate

The application retains three profiles and five persistent color themes from the
reviewed 0.6.0 source. Generator, policy mathematics, dictionary bytes, UI behavior,
dependency versions, base/scanner pins and Nginx controls are preserved.

Publication preparation uses new sanitized history. Production metadata and old
reports remain private. Generic examples use reserved nonproduction DNS values.
Release ownership labels use org.passwordforge.*; this candidate must not be used
to reconcile older labelled images. Future images need separately approved builds.
Preflight requires explicit approved private identities and trusted checksums.
Scanner/runtime image acquisition is disabled; cached digest references are required.
No host validation, deployment or v1.0 qualification is implied by local tests.
Application licensing remains proprietary/private. Third-party notices are retained.
