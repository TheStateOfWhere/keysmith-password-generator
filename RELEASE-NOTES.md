# Zevyrn 1.2.0 — 2026-10-17

Additive Zevyrn-native standalone, Traefik and Caddy installation examples use
the `zevyrn` service, `zevyrn:1.2.0-local` image and `ZEVYRN_*` settings. Legacy
KeySmith installation files remain unchanged and supported. New settings accept
legacy variable fallbacks; a nonempty Zevyrn setting wins. Separate Traefik
configuration directories prevent duplicate route loading.

Installation documentation separates new installations from existing updates.
Password generation, security protections, themes and deployment hostnames are
unchanged. Docker images are not published; build from source.

# Zevyrn 1.1.0 — historical

Zevyrn replaced KeySmith branding with the Gradient Eye logo and five accessible
themes, preserving password-generation behavior. README screenshots are genuine
v1.1.0 captures. The published v1.1.0 tag and release remain unchanged.

# KeySmith 1.0.0

Browser-only password generation with Readable, Strong Random and Custom Policy
profiles; Focus and Password Sheet views; copying controls, Large Text and five
themes. The source includes regression tests, a hardened static Nginx runtime,
and standalone, Traefik and Caddy Compose examples.

Build from source using README.md. No official public KeySmith container image
is provided by this source package. Linux/amd64 is the supported container target.
The application is MIT-licensed; dictionary attribution and separate licenses are
retained under data/ and bundled into /licenses/.
