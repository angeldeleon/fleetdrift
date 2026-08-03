# Privacy

fleetdrift processes software inventory from employee endpoints. That is workplace monitoring data. In the EU and UK it is personal data under GDPR the moment it can be tied to a named individual, and in several jurisdictions — Germany's works councils most prominently — deploying it is a consultation obligation before it is a technical decision.

This document states exactly what the tool collects, what it stores, and for how long, so you can answer those questions without reading the source. If your deployment needs a data protection impact assessment, this is the input for it.

## What is collected

Only what the reviewed query pack asks for. Run `fleetdrift pack --explain` to see the exact SQL.

| Field | Why |
|---|---|
| Software name | The whole point |
| Version | Vulnerability and end-of-life matching |
| Publisher / bundle identifier | Distinguishing a real vendor from a lookalike |
| Install path | Detecting software running from unusual locations |
| Code-signing authority and status | Detecting unsigned or tampered binaries |
| Hostname and host identifier | Correlating findings to a machine |
| OS and version | Selecting the right vulnerability ecosystem |

## What is deliberately not collected

There is no query in the pack that touches any of these, and no way to add one through configuration:

- Browser history, bookmarks, or downloads
- File contents, or any listing of a user's files
- Shell history, running processes, or command lines
- Network connections, DNS lookups, or traffic
- Keystrokes, screenshots, clipboard, or any live activity
- Location, hardware serial numbers, or user account details beyond the hostname

The query pack lives in `src/fleetdrift/sources/queries.py`. It is fixed in the source tree, reviewed in-tree, and reads only software-inventory tables. This is enforced structurally, not by policy: `config.py` has no key that accepts a query, and results-log records whose query name is not in the pack are ignored rather than parsed.

If a pull request adds a query, it must state what new data it collects and why the finding it enables justifies that collection. That trade is the point of the review.

## Pseudonymisation

**Default mode: `pseudonymous`.** Host identifiers are replaced with stable labels like `host-0e8bb20bbb19` in every report, alert, and webhook payload.

The mechanism is HMAC-SHA256 under a locally generated 32-byte salt:

- **Deterministic**, so drift detection and "the same three machines keep showing this" both work.
- **Not reversible** by anyone holding a report but not the salt — which matters, because reports get pasted into tickets and chat.
- **Not enumerable**, unlike a plain hash. A 100,000-host estate has a small enough hostname space to brute-force a bare SHA-256 in seconds.

The salt is stored beside the database at mode `0600`. Deleting it makes every previously issued pseudonym permanently unresolvable and resets the baseline — which is the correct behaviour for a "forget this fleet" request.

Install paths, which usually contain an employee's account name, are omitted from findings in pseudonymous mode. Collection error messages count affected hosts rather than naming them, because those strings reach reports and webhooks too.

**`privacy.mode: identified`** puts real hostnames and install paths in output. It is a deliberate choice with a warning logged every run. Make it knowingly.

Re-identification, when an investigation genuinely warrants it, is done by looking the machine up in your fleet manager — not by reversing the pseudonym.

## What is stored, and for how long

| Artefact | Contains | Retention |
|---|---|---|
| `fleetdrift.db` (SQLite, `0600`) | Host ids, hostnames, software names and versions per snapshot | Last 14 snapshots; older pruned automatically on every run |
| `salt` (`0600`) | The pseudonymisation key | Until deleted |
| `decisions.yml` (`0600`) | Software names and their classifications | Indefinite — it is the audit trail |
| Reports | Whatever you configure | Yours to manage |

The database holds real hostnames even in pseudonymous mode. That is intentional: the mapping has to live somewhere for drift to work across runs, and the right place is a `0600` file on a host you control, not a report circulating in a ticket queue. Treat the database as sensitive — it is a complete software map of every managed endpoint.

## Third-party transmission

Nothing leaves your infrastructure unless you switch it on.

| Feature | Sends | To | Default |
|---|---|---|---|
| `vulnerabilities` check | Package names and versions | api.osv.dev | **On** |
| `ai.enabled` | Software names, finding titles, and a per-request `machine-N` index — never a hostname, in either privacy mode | Anthropic API | Off |
| `notify.*` | Findings, per your severity threshold | Your webhook, Slack, or SMTP | Off |

The vulnerability check is on by default and does send package names and versions to OSV. It sends no hostnames and no identifiers, and it only queries Linux packages. Disable it by removing `vulnerabilities` from `settings.checks` if that transmission is unacceptable in your environment.

The AI layer never receives hostnames, usernames, install paths, or the full inventory — only software names and finding titles. This holds in `identified` mode too: hosts are replaced with a throwaway `machine-1`, `machine-2` index local to the single request, which lets the model see that two findings share a machine and nothing more. It is off by default, and enabling it is still a disclosure decision about your estate's software profile.

## Practical guidance

- Run in `pseudonymous` mode unless you have a documented reason not to.
- Keep the database and salt on a host with restricted access, and back them up as sensitive data.
- If you commit `decisions.yml` to git — recommended, it is the audit trail — remember it contains a list of software present on your estate. Use a private repository.
- Tell your workforce. A monitoring tool discovered rather than announced costs more trust than it is worth, and in some jurisdictions the disclosure is not optional.
- Route findings to a security team, not to end users. fleetdrift is built that way on purpose: untargeted "you have risky software" messages generate helpdesk load, get muted, and make the security team adversarial to the people whose cooperation it needs.

## Questions

If something here is unclear or incomplete for your assessment, open an issue. Getting this document right is more useful than another detection rule.
