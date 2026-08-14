# Security Policy

## Reporting a vulnerability

Report privately through GitHub's [private vulnerability reporting](https://github.com/angeldeleon/fleetdrift/security/advisories/new) rather than opening a public issue.

Include affected version, reproduction steps, and impact. I aim to acknowledge within 72 hours and to ship a fix or mitigation plan within 30 days for confirmed issues. Credit in the advisory unless you would rather not be named.

## Threat model

fleetdrift runs on a management host with credentials for a fleet manager, network reach into internal systems, and a complete software inventory of every managed endpoint. It also ingests strings chosen by whatever is installed on those endpoints — which, in the scenario it exists to detect, includes an attacker. That shapes what it defends against.

| Threat | Mitigation |
|---|---|
| **Arbitrary endpoint read via injected query** — osquery can read any file, so a config-supplied query would be a fleet-wide exfiltration primitive | The query pack is fixed in `sources/queries.py`. No config key accepts a query, table, or SQL fragment; results-log records outside the pack are ignored rather than parsed. `fleetdrift pack --explain` prints exactly what is read |
| **Writing to endpoints** | No source has a write path. A read-only Fleet observer token is sufficient, and the tool is designed so that anything more is a signal something is wrong |
| **SSRF to cloud metadata or internal services** | Every outbound URL is validated and its host resolved before connecting; loopback, RFC1918, link-local (`169.254.169.254`), CGNAT, reserved, multicast and IPv4-mapped/6to4/NAT64 spellings are refused |
| **SSRF via redirect** | Redirects are followed manually, capped at 3 hops, re-validated at each. `allow_internal` — which exists solely for a named on-prem Fleet server — does **not** survive a cross-origin hop, so a compromised or on-path Fleet cannot redirect the scanner into the rest of the network |
| **Credential forwarding via redirect** | Credential-bearing headers and the request body are dropped on any cross-origin hop; 301/302/303 downgrade to GET |
| **Alert and report injection** — a crafted software name forging a finding line, a phishing link, or a tracking pixel in the report an analyst opens | Endpoint strings are sanitised at ingestion (control characters collapsed, invisible and bidi-override characters dropped, unpaired surrogates replaced, length capped) and escaped again at every renderer, for that renderer's syntax. Markdown link, image and code-span metacharacters are escaped, and a bare URL — which needs none of them, and which most renderers autolink on sight — is quarantined inside a code span, where autolinking does not happen; HTML output is fully entity-escaped; email headers are validated and control characters stripped. Slack is handled structurally rather than by escaping — mrkdwn has no backslash escape, so finding prose is emitted as `plain_text` with `emoji: false`, where no markup is interpreted at all |
| **Name spoofing** — a binary whose displayed name is not the name it matches on | Bidi overrides and zero-width characters are stripped, so a name cannot render as one thing and be stored as another. Matching is NFKC-normalised and Unicode-aware, so a fullwidth or non-Latin spelling neither evades a rule nor disappears from the report |
| **Prompt injection via software names** | The model runs after all findings are final and cannot change them. It only proposes decisions, which are written `pending` and inert until a human approves. Replies are parsed against a strict schema and any name not in the request is discarded |
| **Code execution via config** | `yaml.safe_load` only, size-capped, unknown keys rejected |
| **Secret leakage** | Secrets come from the environment, never config. A `*_env` field containing a URL or path is rejected. A logging filter redacts credential-shaped strings including in tracebacks; URLs in error messages are truncated to scheme and host. Finding evidence is redacted where the finding is serialised rather than at each renderer, so a field named like a credential keeps its name and loses its value in every output format, including the next one somebody adds |
| **Re-identification of employees** | Pseudonymous by default; install paths omitted; error strings count hosts rather than naming them. See [PRIVACY.md](PRIVACY.md) |
| **Salt, state, report or input theft via symlink** | Every file this tool opens — the salt, the SQLite state database, the report it writes, the osquery results log, an extra catalog and the decision file — is opened with `O_NOFOLLOW` on every open, not only on creation, since a link pointing at an *existing* file is the case that matters. `O_NONBLOCK` is set alongside it on every read: opening a FIFO blocks inside `open()`, before the regular-file check can refuse it, so a named pipe left at any of those paths would otherwise hang every run indefinitely rather than failing. The file type and size come from `fstat` on the descriptor that is actually read, not from a `stat()` of a name that may since have become something else, and permissions are set and repaired with `fchmod` on that descriptor, never `chmod` on the path — so the tool cannot be made to tighten somebody else's file and lock its owner out of it |
| **Redirection of the state database through its parent directory** | `O_NOFOLLOW` covers the final path component only, and `mkdir(exist_ok=True)` accepts a pre-existing symlink-to-directory. The default state path is relative, so on CI it lands inside the checked-out repository; the whole parent chain is therefore walked and refused if any component is a link, before and after the directory is created |
| **Reports readable by anyone on the runner** | Written `0600`, like the state database and for the same reason: a report lists which machines run what, and under `privacy.mode: identified` it names them |
| **Resource exhaustion from a hostile or broken fleet manager** | Per-host item cap, aggregate item cap, page cap, streamed HTTP with an incremental size cap, config and log size caps, and a cap on every serialised collection — findings and collection notes in the JSON report, findings in the Slack, email and webhook payloads, and the keys, items, depth and value length inside an evidence blob. Totals stay whole above each cap, so a consumer can always tell it is reading a subset |
| **False findings from partial data** | A truncated results log fails loudly rather than reading the oldest records; hosts with missing or empty inventory are skipped, never recorded as empty, and a host that reported nothing in the *current* collection produces no uninstall findings either, because "it reported nothing" and "everything was removed" are different facts and announcing remediation that did not happen is worse than saying nothing; two configs sharing a state file get separate baselines; a baseline sharing no hosts with the current collection is reported instead of silently producing no drift; a host listing that reaches the `max_hosts` cap says so, because landing exactly on the cap is indistinguishable from a fleet that size. Every renderer, including HTML, carries these notes — an incomplete scan must not look like a clean one in any output format |
| **State corruption** | SQLite created at `0600` *before* the driver opens it; decision file written atomically |

### Explicitly out of scope

- **The integrity of the inventory itself.** fleetdrift trusts what osquery reports. Malware with kernel-level persistence can hide from osquery, and nothing here changes that. This is a drift detector, not an EDR.
- **Time-of-check/time-of-use on the HTTP client.** DNS can change between validation and connection. The guard raises the bar substantially against accidental and opportunistic SSRF without claiming to be airtight; pinning the resolved address at connect time would close it and is not implemented.
- **Remediation.** The tool detects and reports. It has no capability to uninstall software, and adding one would require privilege on endpoints and turn it into an attack path.

## Supply chain

- Two runtime dependencies: `PyYAML` and `httpx`. Every dependency is attack surface someone else maintains.
- CI runs `pip-audit` on every push and weekly.
- Workflow `permissions` default to `contents: read`; jobs opt in to more.
- Dependabot is enabled for pip and GitHub Actions.
- Actions are pinned to **full commit SHAs**, with the version tag kept in a trailing comment so Dependabot can still propose updates. A tag is mutable and can be repointed at malicious code by anyone who compromises the action's repository; a SHA cannot.

## Running it safely

- Use a **read-only** Fleet API token. The tool never needs more.
- Give the host the narrowest network egress you can.
- Store the Fleet token, webhook URLs and SMTP credentials as environment variables or secrets — never in the config file. The config only names them.
- Treat `fleetdrift.db` as sensitive: it is a complete software map of every managed endpoint, and a useful one for an attacker.
- Leave `verify_tls: true`. Disabling it exposes your Fleet API token to anyone on-path, and the tool logs a warning every run if you do.
- Keep `ai.enabled: false` unless you have accepted sending software names to a third-party API.
