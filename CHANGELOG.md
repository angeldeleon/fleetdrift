# Changelog

Notable changes to fleetdrift, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A cross-tool consistency pass, measuring this repository against the controls
its siblings implement rather than against its own documentation. Most of what
follows was never claimed here, which is exactly why nothing caught it.

### Fixed

- **Every file this tool opens now refuses a symlink and a named pipe.** The
  state database and the salt were opened this way; the report, the osquery
  results log, an extra catalog and the decision file were not. The results log
  in particular lives in a drop directory shared with whatever ships it, and
  `is_file()` followed by `open()` checked one name and read another — so a link
  planted there aimed the reader at any file the scanning account could open,
  and a FIFO there hung every scheduled scan with no timeout and nothing in the
  log. All of them now open through a descriptor with `O_NOFOLLOW` and
  `O_NONBLOCK`, take the file type and size from `fstat` on that descriptor, and
  restore blocking mode only once the descriptor is known to be a regular file.
- **Reports are written `0600`, through a descriptor that will not follow a
  link.** A report lists which machines run what, and under
  `privacy.mode: identified` it names them; it was being written at the process
  umask, to whatever the path resolved to.
- **The state database's parent chain is validated, not just its final
  component.** `O_NOFOLLOW` applies to the last component only and
  `mkdir(exist_ok=True)` accepts a pre-existing symlink-to-directory, so a
  planted `.fleetdrift -> /tmp/attacker` redirected the whole inventory with
  every guard on the file itself still passing. The default state path is
  relative, which puts it inside the checked-out repository on CI.
- **A host that reported nothing is no longer read as a host that uninstalled
  everything.** The diff guarded the empty *baseline* and not the empty
  *current* snapshot, so a re-enrolled machine that had not yet reported
  inventory would have produced a removal finding for every flagged package on
  it — a security report announcing remediation that did not happen. Both
  collectors already drop such a host; the diff no longer depends on them
  continuing to.
- **Finding evidence is redacted and bounded where the finding is serialised**,
  rather than at each of the four sinks that render it. An osquery row is
  whatever the table returned and an operator's catalog entry can name any
  field, so a value under a key like `license_key` reached the JSON report and
  the webhook; it now keeps its name and loses its value in every format,
  including the next one somebody adds.
- **The JSON report caps its findings and its collection notes**, the way it
  already capped the unclassified-software list, with the totals kept whole
  above the cap so a consumer can tell it is reading a subset.
- **The decision file's temporary sibling is chmodded through its descriptor**
  rather than by name.

### Added

- CI invariants asserting that every `os.open` in the tree carries
  `O_NOFOLLOW`, that every read carries `O_NONBLOCK`, that no module reaches
  around the guarded reader with `read_text`/`write_text`, that an empty
  collection produces no uninstall findings, and that nothing credential-shaped
  survives into any of the three report formats.

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
