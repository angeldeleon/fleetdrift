# Changelog

Notable changes to fleetdrift, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Software whose name is only punctuation, symbols or emoji is no longer
  invisible.** `normalize_software_name` reduced `+++` or a single emoji to the
  empty string, and every caller skips a name that normalises to nothing — so
  such a package matched no rule, produced no drift finding, was not listed as
  unclassified, and skipped the signature check, which does not depend on the
  name at all. The attacker picks the name, so this was one rename away. Names
  that survive nothing but the separator strip now keep their sanitised text as
  a key, which is still case- and width-folded and still stable across versions.
- **A bare URL in a software name can no longer become a link in the report.**
  The Markdown escaper covered link *syntax*, and `https://evil.example/patch`
  uses none of it: GitHub-flavoured Markdown and most ticket systems autolink it
  on sight, putting a live phishing link in a finding line. URL-shaped runs are
  now rendered inside a code span, where no CommonMark implementation
  autolinks. Escaping could not fix this one — the autolinker matches the shape
  of the text rather than a metacharacter.
- **A named pipe at the salt or state path no longer hangs the run.** Both files
  are opened with `O_NOFOLLOW`, but opening a FIFO for reading blocks inside
  `os.open` until a writer appears — before the regular-file check that would
  have rejected it. Anyone able to write the state directory could stop every
  scheduled scan indefinitely, with no timeout and no log line. Both opens now
  add `O_NONBLOCK`, cleared once the descriptor is known to be a regular file.
- **The generic webhook honours `notify.max_findings_per_message`.** Slack and
  email always did; the webhook serialised every finding at or above the
  threshold, so a large estate with `enforce_allowlist` on posted tens of
  megabytes in a single request and the scan that found the most became the one
  whose alert the receiver dropped. The payload now carries `findings_total` and
  `findings_truncated` so a receiver can tell it is looking at a subset.
- **`~~~` in the summary can no longer restructure the report.** The backtick
  spelling of a code fence was escaped and the tilde spelling was not, and a
  fence that is never closed runs to the end of the document — enough for model
  output to render every finding below it as preformatted text.
- **A summary line starting with a number no longer shows a stray backslash.**
  Escaping the digit suppressed the ordered list, but CommonMark honours a
  backslash only before ASCII punctuation, so readers saw `\3 machines gained
  AnyDesk`. The list marker is escaped instead.

### Changed

- **An approved decision must name its reviewer.** `reviewed_by` is now required
  when `status: approved`, and the decision file is rejected with a clear error
  otherwise. An approved entry is the only kind that changes a finding, and the
  audit trail this file exists to be is worth nothing if it does not say who
  made the call. Existing files with approved entries need a name adding before
  the next run.

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
