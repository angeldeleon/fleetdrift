# Changelog

Notable changes to fleetdrift, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-03

First release.

Reads osquery software inventory from Fleet or an osquery results log, compares
it against a stored baseline, and reports risky software and changes to a
security team. Curated risk catalog, allow/denylist policy, code-signature
checks, OSV vulnerability matching for Linux packages, and fleet-level drift
detection. Slack, webhook and email notification. Markdown, JSON and HTML
output. Pseudonymised by default.

See the [README](README.md) for what each check covers and where the known
limitations are, and [PRIVACY.md](PRIVACY.md) for exactly what is collected.

[0.1.0]: https://github.com/angeldeleon/fleetdrift/releases/tag/v0.1.0
