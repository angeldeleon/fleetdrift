# Contributing

Issues and pull requests both welcome.

## Setup

```bash
git clone https://github.com/angeldeleon/fleetdrift
cd fleetdrift
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Before opening a PR

```bash
ruff check .          # lint, including security rules
ruff format .
mypy
bandit -r src/ -c pyproject.toml
pytest                # no network required
```

CI runs all of these plus `pip-audit`.

## The easiest useful contribution

**A catalog entry.** `src/fleetdrift/rules/catalog.py` maps software families to a risk category. One entry, a few name patterns, real value to everyone running the tool.

Please include a sentence on what the software actually does and why the severity fits. And keep patterns specific: matching is token-based rather than substring, but a pattern like `agent` will still flag half an estate.

## Four things a review will catch

**Never add a way to supply a query.** `sources/queries.py` is fixed in-tree for a reason: osquery can read any file on the endpoint, so a config-injectable query turns a monitoring tool into a fleet-wide exfiltration primitive — and the config file is usually the least-protected artefact in a deployment. If a new finding needs new data, add the query to the pack, and say in the PR exactly what it collects and why the finding justifies collecting it. That trade is the point of the review.

**A failed collection is not an empty fleet.** Three states, never two: the software is present, it is definitively absent, or you could not find out. Collapsing the third into the second is what makes a monitoring tool produce confident false alarms — a host whose inventory request timed out reading as "everything was uninstalled", and then as "everything was reinstalled" the next day. Skip the host, count it, and say so.

**Severity has to mean something.** `CRITICAL` is exploitable-right-now: a cryptominer, a credential dumper, a C2 framework. `HIGH` is a serious capability with no benign explanation on a typical endpoint. Dual-use tooling — nmap, Wireshark — sits at `LOW`, because a report that flags a security engineer's own toolkit at HIGH teaches the team to ignore it, and then the cryptominer gets ignored too.

**Endpoint data is attacker-controlled.** Software names, publishers and paths come from the machines being watched. In the scenario this tool exists to detect, that is the attacker. Anything you interpolate into a report, a Slack message, an email or a prompt must go through the sanitisers in `validation.safe_text` and the renderer escapes. There are tests for this; extend them if you add a sink.

## The AI layer

Proposals only, and only ever `status: pending`. If a change would let a model produce an approved decision, change a severity, or influence a finding, it will not be merged. The value of the design is that `git log decisions.yml` is an audit trail with a human's name on every classification — that property is worth more than any convenience.

## Security

Do not open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).

Changes touching `validation.py`, `httpclient.py`, `privacy.py` or `sources/queries.py` get a closer read and need tests.

## Style

- Comments explain *why*, not *what*.
- No new dependencies without a strong reason. There are two, and that is a feature.
- No `subprocess`, no `eval`, no dynamic imports.

## License

Contributions are licensed under Apache 2.0, matching the project.
