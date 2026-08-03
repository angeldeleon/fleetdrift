"""Command-line interface.

Exit codes are the contract with CI and cron:

* ``0`` — scan completed, nothing at or above the fail-on threshold
* ``1`` — scan completed, findings at or above the threshold
* ``2`` — the scan could not run, or ran degraded (no hosts collected)

Keeping "found problems" (1) distinct from "could not check" (2) matters: a
pipeline that treats them alike eventually goes green because the collector
broke, which is the worst possible failure for a monitoring tool.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .ai import propose_classifications, summarize
from .config import ALL_CHECKS, load_config
from .logging_setup import configure_logging
from .models import ScanReport, Severity
from .notify import notify
from .privacy import PrivacyMode
from .report import render
from .rules.decisions import STATUS_PENDING, DecisionStore
from .runner import scan, state_scope
from .sources.base import SourceError
from .sources.queries import QUERIES, render_pack
from .store import SnapshotStore, StateError
from .validation import ValidationError

log = logging.getLogger("fleetdrift")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fleetdrift",
        description=(
            "Endpoint software drift detection for security teams. Read-only: it "
            "consumes osquery inventory a fleet already collects and never writes "
            "to a managed machine."
        ),
    )
    parser.add_argument("--version", action="version", version=f"fleetdrift {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0, help="increase log verbosity")
    common.add_argument("-q", "--quiet", action="store_true", help="only log errors")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser(
        "scan", parents=[common], help="collect inventory, report findings and drift"
    )
    scan_parser.add_argument("-c", "--config", required=True, help="path to the YAML config file")
    scan_parser.add_argument(
        "-o", "--output", default="-", help="write the report here ('-' for stdout, the default)"
    )
    scan_parser.add_argument("-f", "--format", default="markdown", choices=("markdown", "md", "json", "html"))
    scan_parser.add_argument(
        "--no-save", action="store_true", help="do not update the baseline (useful for a dry run)"
    )
    scan_parser.add_argument(
        "--fail-on",
        default=None,
        choices=[s.value for s in Severity],
        help="minimum severity that sets exit code 1; overrides the config",
    )
    scan_parser.add_argument("--no-notify", action="store_true", help="skip all notification delivery")
    scan_parser.add_argument("--no-ai", action="store_true", help="skip LLM summarisation")
    scan_parser.set_defaults(func=cmd_scan)

    triage_parser = sub.add_parser(
        "triage",
        parents=[common],
        help="draft classifications for unclassified software (writes pending entries for review)",
    )
    triage_parser.add_argument("-c", "--config", required=True)
    triage_parser.set_defaults(func=cmd_triage)

    decisions_parser = sub.add_parser(
        "decisions", parents=[common], help="show decisions awaiting human review"
    )
    decisions_parser.add_argument("-c", "--config", required=True)
    decisions_parser.set_defaults(func=cmd_decisions)

    pack_parser = sub.add_parser(
        "pack", parents=[common], help="print the osquery query pack this tool consumes"
    )
    pack_parser.add_argument(
        "--explain", action="store_true", help="describe each query in prose instead of emitting JSON"
    )
    pack_parser.set_defaults(func=cmd_pack)

    validate_parser = sub.add_parser(
        "validate", parents=[common], help="validate a config file without collecting anything"
    )
    validate_parser.add_argument("-c", "--config", required=True)
    validate_parser.set_defaults(func=cmd_validate)

    return parser


# --------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    if args.fail_on:
        config.settings.fail_on = Severity.parse(args.fail_on)

    store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
    try:
        store.check_schema()
    except StateError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    try:
        report = scan(config, store=store, save=not args.no_save)
    except SourceError as exc:
        log.error("collection failed: %s", exc)
        return EXIT_ERROR
    except StateError as exc:
        log.error("state error: %s", exc)
        return EXIT_ERROR

    if config.ai.enabled and not args.no_ai:
        report.ai_summary = summarize(report, config.ai)

    _write_report(report, args.output, args.format)

    if not args.no_notify:
        for error in notify(report, config.notify, user_agent=config.settings.user_agent):
            log.error("%s", error)

    return _exit_code(report, config.settings.fail_on)


def cmd_triage(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    if not config.ai.enabled:
        log.error("triage needs ai.enabled: true in the config")
        return EXIT_ERROR

    try:
        report = scan(config, store=None, save=False)
    except SourceError as exc:
        log.error("collection failed: %s", exc)
        return EXIT_ERROR

    if not report.unknown_software:
        print("Nothing to triage: all observed software is already classified or allowlisted.")
        return EXIT_OK

    proposals = propose_classifications(report.unknown_software, config.ai)
    if not proposals:
        log.error("no proposals were produced (check the API key and network)")
        return EXIT_ERROR

    decisions = DecisionStore(config.policy.decisions_path)
    added = decisions.add_proposals(proposals)

    print(f"Wrote {added} proposal(s) to {config.policy.decisions_path}, all status: pending.")
    print()
    print("They have no effect until reviewed. For each entry you agree with, set")
    print("  status: approved   and fill in   reviewed_by:")
    print("Set status: rejected to dismiss one without it being proposed again.")
    print()
    print("Then commit the file — its git history is your audit trail.")
    return EXIT_OK


def cmd_decisions(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
        decisions = DecisionStore(config.policy.decisions_path)
        entries = decisions.load()
    except ValidationError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    pending = [d for d in entries.values() if d.status == STATUS_PENDING]
    approved = [d for d in entries.values() if d.active]

    print(f"{len(entries)} decision(s) in {config.policy.decisions_path}")
    print(f"  {len(approved)} approved and in effect")
    print(f"  {len(pending)} awaiting review")

    if pending:
        print()
        print("Awaiting review:")
        for decision in sorted(pending, key=lambda d: d.name):
            print(
                f"  {decision.name:<40} {decision.verdict:<6} "
                f"{decision.category.value:<18} {decision.severity.value:<8} "
                f"({decision.proposed_by})"
            )
        print()
        print("Nothing above affects a scan until you set status: approved.")
    return EXIT_OK


def cmd_pack(args: argparse.Namespace) -> int:
    if args.explain:
        print("fleetdrift consumes exactly these osquery queries. Nothing else is read.\n")
        for name, query in sorted(QUERIES.items()):
            print(f"{name}  [{query.platform}]")
            print(f"  {query.description}")
            print(f"  {query.sql}")
            print()
        print("There is no way to add a query through configuration. See sources/queries.py.")
        return EXIT_OK

    print(json.dumps(render_pack(), indent=2))
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    print("Config is valid.")
    print(f"  source:      {config.source.type}")
    print(f"  checks:      {', '.join(config.settings.checks)}")
    print(f"  privacy:     {config.privacy_mode.value}")
    print(f"  fail_on:     {config.settings.fail_on.value}")
    print(f"  allowlist:   {len(config.policy.allowlist)} entr(y/ies)")
    print(f"  denylist:    {len(config.policy.denylist)} entr(y/ies)")

    if config.privacy_mode is PrivacyMode.IDENTIFIED:
        print()
        print("  NOTE: privacy.mode is 'identified'. Reports will contain real hostnames.")

    missing: list[str] = []
    if config.source.type == "fleet" and config.source.fleet and not config.source.fleet.api_token():
        missing.append(config.source.fleet.api_token_env)
    if config.notify.slack_webhook_url_env and not config.notify.slack_webhook_url():
        missing.append(config.notify.slack_webhook_url_env)
    if config.notify.webhook_url_env and not config.notify.webhook_url():
        missing.append(config.notify.webhook_url_env)
    if config.ai.enabled and not config.ai.api_key():
        missing.append(config.ai.api_key_env)

    if missing:
        print()
        print("Referenced but unset environment variable(s): " + ", ".join(missing))

    unknown_checks = set(config.settings.checks) - set(ALL_CHECKS)
    if unknown_checks:  # pragma: no cover - config parsing rejects these first
        print(f"Unknown checks: {', '.join(sorted(unknown_checks))}")
        return EXIT_ERROR

    return EXIT_OK


# --------------------------------------------------------------------------


def _write_report(report: ScanReport, output: str, fmt: str) -> None:
    rendered = render(report, fmt)
    if output == "-":
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    log.info("wrote %s report to %s", fmt, path)


def _exit_code(report: ScanReport, fail_on: Severity) -> int:
    if report.scan_degraded:
        # Zero hosts collected. Reporting "no findings" here would be a lie, and
        # exiting 0 would turn a broken collector into a green dashboard.
        log.error("scan collected no hosts; refusing to report a clean result")
        return EXIT_ERROR

    highest = report.max_severity
    if highest is not None and highest >= fail_on:
        log.info("highest severity %s meets the %s threshold", highest.value, fail_on.value)
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(getattr(args, "verbose", 0), quiet=getattr(args, "quiet", False))

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
    except (ValidationError, SourceError, StateError) as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except Exception:  # noqa: BLE001 - exit 1 means "findings", never "crashed"
        # Python exits 1 on an unhandled exception, which is indistinguishable
        # from EXIT_FINDINGS. Anything unexpected must surface as EXIT_ERROR.
        log.exception("unexpected error; the scan did not complete")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
