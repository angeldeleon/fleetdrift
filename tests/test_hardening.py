"""Regression tests for the hardening pass.

Each corresponds to a specific defect found during adversarial review. Grouped
separately from the feature tests so it stays obvious that deleting one
re-opens a known hole.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import stat
from unittest import mock

import pytest

from fleetdrift import ai, notify
from fleetdrift.analyze import Analyzer
from fleetdrift.config import (
    AIConfig,
    FleetSourceConfig,
    NotifyConfig,
    ResultLogSourceConfig,
    parse_config,
)
from fleetdrift.drift import diff_inventories
from fleetdrift.httpclient import _origin
from fleetdrift.models import (
    Finding,
    FindingKind,
    Host,
    HostSnapshot,
    Inventory,
    Platform,
    RiskCategory,
    ScanReport,
    Severity,
    SoftwareItem,
)
from fleetdrift.notify import _escape_code
from fleetdrift.privacy import Pseudonymiser
from fleetdrift.report import _md, _md_block, _md_url, _render_findings, render_html
from fleetdrift.rules.catalog import BUILTIN_CATALOG, CatalogMatcher
from fleetdrift.rules.decisions import DecisionStore
from fleetdrift.runner import state_scope
from fleetdrift.sources.base import SourceError
from fleetdrift.sources.fleet import FleetSource
from fleetdrift.sources.resultlog import ResultLogSource
from fleetdrift.store import SnapshotStore, StateError
from fleetdrift.validation import ValidationError, normalize_software_name, safe_text


def _host(host_id: str = "h1") -> Host:
    return Host(host_id=host_id, display=f"{host_id}.corp", platform=Platform.MACOS)


def _sw(name: str, host_id: str = "h1") -> SoftwareItem:
    return SoftwareItem(host_id=host_id, name=name, version="1.0", source="apps")


def _diff(previous, current):
    return diff_inventories(
        previous,
        current,
        catalog=CatalogMatcher(),
        decisions=DecisionStore("/nonexistent/decisions.yml"),
        ignore=set(),
        allowlist=set(),
        host_label=lambda h: h.display,
    )


def _finding(*, software: str, title: str = "appeared on 1 host") -> Finding:
    return Finding(
        host_display="host-abc123",
        host_id="h1",
        software=software,
        version="1.0",
        kind=FindingKind.DRIFT,
        severity=Severity.HIGH,
        category=RiskCategory.REMOTE_ACCESS,
        title=title,
        detail="New since the last scan.",
    )


class TestMarkdownInjection:
    """Software names are attacker-chosen; reports get read in tickets."""

    def test_link_and_image_syntax_is_neutralised(self) -> None:
        payload = "AnyDesk ![](https://evil.example/beacon.png) [Remediate](https://evil.example/phish)"
        rendered = _md(payload)
        assert "](https://evil.example" not in rendered
        assert "\\[" in rendered and "\\!" in rendered

    def test_backtick_cannot_break_out_of_a_code_span(self) -> None:
        rendered = _md("Zoom` is on the denylist **owned**")
        # Escaped, not stripped: the name still reads correctly, but the
        # backtick can no longer close the code span it is rendered inside.
        assert "\\`" in rendered
        assert not re.search(r"(?<!\\)`", rendered)
        # Emphasis markers are deliberately left alone: the worst they do is
        # make text bold, and escaping them mangled every `remote_access`.
        assert "**owned**" in rendered

    def test_arrows_and_ordinary_text_survive(self) -> None:
        assert _md("1.2 -> 1.3") == "1.2 -> 1.3"
        assert _md("Microsoft Visual C++ Redistributable") == "Microsoft Visual C++ Redistributable"

    def test_rendered_finding_line_keeps_code_spans_readable_and_inert(self) -> None:
        """The two properties a code-span value has to hold at once.

        Regression: the finding line escaped its code-span values with ``_md``,
        so an analyst saw ``AnyDesk \\!\\[\\]\\(...\\)`` — backslashes render
        literally inside backticks. Switching to ``_code`` fixes the display,
        and must not reintroduce a way out of the span.
        """
        payload = "AnyDesk ![](https://evil.example/px.png) [Fix](https://evil.example/phish)"
        rendered = "\n".join(_render_findings([_finding(software=payload)]))
        # Readable: the code span holds the real name, not a backslash soup.
        assert f"`{payload}`" in rendered
        # Inert: the span is the ONLY place the raw link syntax appears. The
        # title, which renders as prose, still goes through _md.
        assert "](https://evil.example" not in rendered.replace(f"`{payload}`", "")

    def test_a_backtick_in_a_name_cannot_close_the_span(self) -> None:
        rendered = "\n".join(_render_findings([_finding(software="Zoom` [Fix](https://evil.example) x")]))
        span = rendered.split(" — `")[1].split("`")[0]
        assert "`" not in span
        assert "'" in span  # replaced rather than escaped

    def test_slack_code_span_is_closed_against_backticks(self) -> None:
        assert "`" not in _escape_code("Zoom` *owned*")
        assert "&lt;" in _escape_code("<https://evil.example|Fix>")

    def test_a_bare_url_cannot_autolink_in_prose(self) -> None:
        """Regression: the escape set covers link *syntax*, and a bare URL uses
        none of it. GitHub-flavoured Markdown, and most of the ticket systems a
        report is pasted into, autolink `https://…` on sight -- so a package
        named "Update Required https://evil.example/patch" put a live phishing
        link in the finding line an analyst reads, which is what the escaping
        exists to prevent. Quarantined in a code span, where no CommonMark
        implementation autolinks."""
        assert _md("Update Required https://evil.example/patch") == (
            "Update Required `https://evil.example/patch`"
        )
        assert _md("see www.evil.example now") == "see `www.evil.example` now"
        assert _md("mail mailto:ops@evil.example") == "mail `mailto:ops@evil.example`"

    def test_a_bare_url_in_a_title_is_quarantined_end_to_end(self) -> None:
        title = "AnyDesk https://evil.example/patch is not code-signed"
        rendered = "\n".join(_render_findings([_finding(software="AnyDesk", title=title)]))
        assert "`https://evil.example/patch`" in rendered
        assert " https://evil.example" not in rendered, "an autolinkable URL survived"

    def test_ordinary_names_are_not_dragged_into_a_code_span(self) -> None:
        assert _md("Microsoft Visual C++ Redistributable") == "Microsoft Visual C++ Redistributable"
        assert _md("1.2 -> 1.3") == "1.2 -> 1.3"

    def test_reference_urls_must_be_plain_links(self) -> None:
        assert _md_url("https://osv.dev/vulnerability/CVE-2024-1") != ""
        assert _md_url("https://evil.example/x) [pwn](https://evil.example") == ""
        assert _md_url("javascript:alert(1)") == ""
        assert _md_url("not a url") == ""


class TestRedirectScope:
    """allow_internal exists for a named Fleet server, not for wherever it points."""

    def test_origin_comparison(self) -> None:
        assert _origin("https://a.example/x") == _origin("https://a.example:443/y")
        assert _origin("https://a.example/x") != _origin("https://b.example/x")

    # The behavioural counterpart lives in tests/test_httpclient.py
    # (TestGuardStillApplies): it drives a real cross-origin redirect against
    # loopback servers instead of inspecting the source of safe_request.


class TestBaselineIntegrity:
    def test_empty_previous_snapshot_is_not_a_baseline(self) -> None:
        """Fleet returns [] for a host that enrolled but has not reported yet."""
        previous = {"h1": HostSnapshot(host=_host(), software=[])}
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(
            HostSnapshot(host=_host(), software=[_sw("TeamViewer"), _sw("Slack"), _sw("Zoom")])
        )
        assert _diff(previous, current) == []

    def test_a_populated_baseline_still_detects_drift(self) -> None:
        previous = {"h1": HostSnapshot(host=_host(), software=[_sw("Slack")])}
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(HostSnapshot(host=_host(), software=[_sw("Slack"), _sw("TeamViewer")]))
        assert any("TeamViewer" in f.software for f in _diff(previous, current))


class TestStateScoping:
    def test_two_configs_get_different_scopes(self) -> None:
        a = parse_config({"source": {"type": "resultlog", "resultlog": {"path": "/nonexistent/a.log"}}})
        b = parse_config({"source": {"type": "resultlog", "resultlog": {"path": "/nonexistent/b.log"}}})
        assert state_scope(a) != state_scope(b)

    def test_the_same_config_is_stable(self) -> None:
        payload = {"source": {"type": "resultlog", "resultlog": {"path": "/nonexistent/a.log"}}}
        assert state_scope(parse_config(payload)) == state_scope(parse_config(payload))

    def test_scopes_do_not_see_each_others_snapshots(self, tmp_path) -> None:
        """Sharing a state file must not silently disable drift detection."""
        path = tmp_path / "state.db"
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("Slack")]))

        SnapshotStore(path, scope="prod").save(inventory)
        assert SnapshotStore(path, scope="prod").latest_snapshot_id() is not None
        assert SnapshotStore(path, scope="staging").latest_snapshot_id() is None

    def test_pruning_is_scoped(self, tmp_path) -> None:
        path = tmp_path / "state.db"
        prod = SnapshotStore(path, scope="prod", retain=2)
        staging = SnapshotStore(path, scope="staging", retain=2)
        for _ in range(5):
            prod.save(Inventory(collected_at="t", source="test"))
        staging.save(Inventory(collected_at="t", source="test"))
        assert prod.snapshot_count() == 2
        assert staging.snapshot_count() == 1


class TestPrivacyLeakage:
    """Pseudonymous mode must hold across every output surface, not just display."""

    def test_findings_carry_no_raw_identifier(self, tmp_path) -> None:
        from fleetdrift.analyze import Analyzer

        config = parse_config(
            {
                "source": {"type": "resultlog", "resultlog": {"path": "/dev/null"}},
                "settings": {"checks": ["catalog", "signature"]},
            }
        )
        pseudonymiser = Pseudonymiser(tmp_path / "salt")
        inventory = Inventory(collected_at="t", source="test")
        host = Host(
            host_id="alice-macbook.corp.example.com",
            display="alice-macbook.corp.example.com",
            platform=Platform.MACOS,
        )
        item = SoftwareItem(
            host_id=host.host_id,
            name="AnyDesk",
            version="8",
            source="apps",
            install_path="/Users/alice.smith/Applications/AnyDesk.app",
            signed=False,
        )
        inventory.hosts.append(HostSnapshot(host=host, software=[item]))

        analyzer = Analyzer(
            config,
            catalog=CatalogMatcher(),
            decisions=DecisionStore("/nonexistent"),
            host_label=lambda h: pseudonymiser.host_label(h.host_id, h.display),
            identified=False,
        )
        findings = analyzer.analyze(inventory)
        blob = json.dumps([f.to_dict() for f in findings])

        assert "alice-macbook" not in blob
        assert "alice.smith" not in blob, "install path re-identifies the pseudonymised host"

    def test_identified_mode_keeps_the_install_path(self, tmp_path) -> None:
        from fleetdrift.analyze import Analyzer

        config = parse_config(
            {
                "source": {"type": "resultlog", "resultlog": {"path": "/dev/null"}},
                "settings": {"checks": ["signature"]},
            }
        )
        inventory = Inventory(collected_at="t", source="test")
        host = _host()
        inventory.hosts.append(
            HostSnapshot(
                host=host,
                software=[
                    SoftwareItem(
                        host_id=host.host_id,
                        name="Thing",
                        source="apps",
                        install_path="/Users/alice/Thing.app",
                        signed=False,
                    )
                ],
            )
        )
        analyzer = Analyzer(
            config,
            catalog=CatalogMatcher(),
            decisions=DecisionStore("/nonexistent"),
            host_label=lambda h: h.display,
            identified=True,
        )
        findings = analyzer.analyze(inventory)
        assert any("install_path" in f.evidence for f in findings)

    def test_collection_errors_name_no_hosts(self, tmp_path) -> None:
        """Error strings reach the report and the outbound webhook."""
        path = tmp_path / "results.log"
        rows = [{"name": f"App {i}", "version": "1"} for i in range(6000)]
        path.write_text(
            json.dumps(
                {
                    "name": "fleetdrift_macos_apps",
                    "hostIdentifier": "alice-macbook.corp.example.com",
                    "unixTime": 1,
                    "snapshot": rows,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        inventory = ResultLogSource(ResultLogSourceConfig(path=str(path))).collect()
        assert inventory.errors
        assert not any("alice-macbook" in err for err in inventory.errors)


class TestResultLogTruncation:
    def test_exceeding_the_line_cap_fails_rather_than_reading_the_oldest(self, tmp_path, monkeypatch) -> None:
        """Reading the head of an append-only log reports stale software as current."""
        import fleetdrift.sources.resultlog as module

        monkeypatch.setattr(module, "_MAX_LINES", 2)
        path = tmp_path / "results.log"
        lines = [
            json.dumps(
                {
                    "name": "fleetdrift_macos_apps",
                    "hostIdentifier": "h1",
                    "unixTime": i,
                    "snapshot": [{"name": f"App{i}", "version": "1"}],
                }
            )
            for i in range(5)
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(SourceError, match="exceeds"):
            ResultLogSource(ResultLogSourceConfig(path=str(path))).collect()


class TestSaltHandling:
    def test_a_symlinked_salt_path_is_refused(self, tmp_path) -> None:
        """Following the link would leak the salt and chmod an arbitrary file."""
        victim = tmp_path / "victim"
        victim.write_bytes(b"x" * 32)
        os.chmod(victim, 0o644)
        link = tmp_path / "salt"
        link.symlink_to(victim)

        with pytest.raises(ValueError, match="cannot read salt"):
            Pseudonymiser(link).host_label("h1", "host")

        assert stat.S_IMODE(os.stat(victim).st_mode) == 0o644, "victim was chmod'd through the link"

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
    def test_a_fifo_salt_path_fails_instead_of_hanging(self, tmp_path) -> None:
        """Regression: opening a FIFO for reading blocks until a writer appears,
        and it blocks inside os.open -- before the regular-file check below can
        reject it. A named pipe in the state directory therefore hung every
        scheduled run forever, with no timeout and no log line, so the reports
        just stopped arriving. Same attacker as the symlink case above.
        """
        path = tmp_path / "salt"
        os.mkfifo(path)
        with pytest.raises(ValueError, match="not a regular file"):
            Pseudonymiser(path).host_label("h1", "host")

    def test_normal_creation_still_works(self, tmp_path) -> None:
        salt = tmp_path / "salt"
        label = Pseudonymiser(salt).host_label("h1", "host")
        assert label.startswith("host-")
        assert stat.S_IMODE(os.stat(salt).st_mode) == 0o600


class TestOutputBounds:
    def test_unknown_software_is_capped_in_serialised_output(self) -> None:
        report = ScanReport(
            started_at="t",
            finished_at="t",
            tool_version="0",
            source="test",
            hosts_scanned=1,
            unknown_software=[f"package {i}" for i in range(5000)],
        )
        payload = report.to_dict()
        assert len(payload["unknown_software"]) == 200
        assert payload["unknown_software_total"] == 5000

    def _webhook_payload(self, config: NotifyConfig, findings: list) -> dict:
        captured: dict = {}

        def fake(method, url, **kwargs):
            captured.update(kwargs.get("json_body") or {})

            class _R:
                status_code = 200

            return _R()

        report = ScanReport(
            started_at="t",
            finished_at="t",
            tool_version="0.1.0",
            source="test",
            hosts_scanned=1,
            findings=findings,
        )
        with mock.patch.object(notify, "safe_request", fake):
            assert notify.notify(report, config) == []
        return captured

    def test_the_webhook_honours_the_finding_cap(self, monkeypatch) -> None:
        """Regression: Slack and email honoured notify.max_findings_per_message
        and the webhook did not, so it serialised every finding at or above the
        threshold. On a large estate with enforce_allowlist on that is tens of
        megabytes in one POST, and the scan that found the most became the one
        whose alert the receiver dropped."""
        monkeypatch.setenv("FLEETDRIFT_TEST_WEBHOOK", "https://hooks.example/x")
        config = NotifyConfig(
            webhook_url_env="FLEETDRIFT_TEST_WEBHOOK",
            min_severity=Severity.INFO,
            max_findings_per_message=5,
        )
        payload = self._webhook_payload(config, [_finding(software=f"s{i}") for i in range(200)])

        assert len(payload["findings"]) == 5
        # Whole, so a receiver can tell it is looking at a subset.
        assert payload["findings_total"] == 200
        assert payload["findings_truncated"] is True
        assert payload["counts_by_severity"]["high"] == 200

    def test_a_short_finding_list_is_not_marked_truncated(self, monkeypatch) -> None:
        monkeypatch.setenv("FLEETDRIFT_TEST_WEBHOOK", "https://hooks.example/x")
        config = NotifyConfig(
            webhook_url_env="FLEETDRIFT_TEST_WEBHOOK",
            min_severity=Severity.INFO,
            max_findings_per_message=20,
        )
        payload = self._webhook_payload(config, [_finding(software="s0")])
        assert payload["findings_total"] == 1
        assert payload["findings_truncated"] is False


class TestDatabasePermissions:
    def test_database_is_never_world_readable_even_briefly(self, tmp_path) -> None:
        path = tmp_path / "state.db"
        store = SnapshotStore(path, scope="test")
        store.save(Inventory(collected_at="t", source="test"))
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


class TestOfflineValidation:
    """`validate` must work without network, and the guard must still fire."""

    def test_config_parsing_does_not_resolve_dns(self, monkeypatch) -> None:
        import socket

        def _explode(*args, **kwargs):
            raise AssertionError("config parsing performed a DNS lookup")

        monkeypatch.setattr(socket, "getaddrinfo", _explode)
        config = parse_config({"source": {"type": "fleet", "fleet": {"url": "https://fleet.example.com"}}})
        assert config.source.fleet is not None

    def test_shape_checks_still_apply_offline(self, monkeypatch) -> None:
        import socket

        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(AssertionError("resolved"))
        )
        from fleetdrift.validation import ValidationError

        for bad in ("http://fleet.example.com", "https://user:pw@fleet.example.com", "ftp://x.example"):
            with pytest.raises(ValidationError):
                parse_config({"source": {"type": "fleet", "fleet": {"url": bad}}})

    def test_the_guard_fires_at_request_time(self) -> None:
        from fleetdrift.httpclient import safe_request
        from fleetdrift.validation import ValidationError

        for url in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1/", "http://10.0.0.1/"):
            with pytest.raises(ValidationError):
                safe_request("GET", url, allow_http=True)

    def test_the_shipped_example_config_is_valid(self) -> None:
        from pathlib import Path

        from fleetdrift.config import load_config

        example = Path(__file__).resolve().parent.parent / "fleet.example.yml"
        if example.exists():
            config = load_config(example)
            assert config.source.type == "fleet"


class TestNameNormalisation:
    """A rule that cannot see a name is a rule that does not exist."""

    def test_non_latin_names_are_not_erased(self) -> None:
        """Regression: `[^a-z0-9]` reduced any non-Latin name to "".

        Callers skip empty normalised names, so such software was not flagged,
        not listed as unclassified, and produced no drift finding. Renaming a
        binary into another script bought total invisibility.
        """
        assert normalize_software_name("网络密码") == "网络密码"
        assert normalize_software_name("Слак") == "слак"
        assert normalize_software_name("Café") == "café"

    def test_every_builtin_catalog_pattern_is_reachable(self) -> None:
        """The bug above left a shipped credential-dumper rule as dead code."""
        for entry in BUILTIN_CATALOG:
            for pattern in entry.patterns:
                assert normalize_software_name(pattern), f"{entry.id}: {pattern!r} normalises to ''"

    def test_fullwidth_spelling_cannot_evade_a_rule(self) -> None:
        assert normalize_software_name("ＡｎｙＤｅｓｋ") == normalize_software_name("AnyDesk")
        assert CatalogMatcher().match(normalize_software_name("ＡｎｙＤｅｓｋ"))

    def test_ordinary_normalisation_still_holds(self) -> None:
        for variant in ("AnyDesk.app", "AnyDesk (64-bit)", "AnyDesk 8.0.8", "anydesk"):
            assert normalize_software_name(variant) == "anydesk"

    def test_symbol_only_names_are_not_erased(self) -> None:
        """The same total invisibility as above, reached by a different spelling.

        The separator strip is right for letters and digits and wrong for a name
        made only of punctuation, symbols or emoji: `+++` and a single emoji
        reduced to "" and hit the same "skip empty names" branch in every
        caller. The attacker picks the name, so this is a rename away.
        """
        for name in ("+++", "🔒", "...", "· ·"):
            assert normalize_software_name(name), f"{name!r} normalises to ''"

    def test_a_symbol_only_name_is_still_a_stable_key(self) -> None:
        """Drift needs the same package to produce the same key across runs."""
        assert normalize_software_name("+++ 1.0") == normalize_software_name("+++ 2.0")
        assert normalize_software_name("🔒") == normalize_software_name("🔒 3.4.5")


class TestSymbolOnlyNames:
    """What the empty normalisation cost, checked where an operator would feel it."""

    def _analyze(self, item):
        config = parse_config(
            {
                "source": {"type": "resultlog", "resultlog": {"path": "/nonexistent/a.log"}},
                "settings": {"checks": ["catalog", "signature"]},
            }
        )
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[item]))
        analyzer = Analyzer(
            config,
            catalog=CatalogMatcher(),
            decisions=DecisionStore("/nonexistent/decisions.yml"),
            host_label=lambda h: h.display,
        )
        return analyzer.analyze(inventory), analyzer

    def test_an_unsigned_symbol_only_name_still_reaches_the_report(self) -> None:
        """The signature check does not look at the name at all, and was skipped
        anyway: the empty-name guard sits above every check in the loop, so an
        unsigned binary called `+++` produced nothing whatsoever."""
        findings, analyzer = self._analyze(dataclasses.replace(_sw("+++"), signed=False))
        assert [f for f in findings if f.category is RiskCategory.UNSIGNED]
        assert analyzer.unknown_software, "an unclassifiable name must still be triageable"

    def test_a_symbol_only_name_still_produces_a_drift_finding(self) -> None:
        """Drift is what covers the software no rule has a name for, which is
        exactly the software this bug made invisible."""
        previous = {"h1": HostSnapshot(host=_host(), software=[_sw("Slack")])}
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(HostSnapshot(host=_host(), software=[_sw("Slack"), _sw("🔒")]))
        assert [f for f in _diff(previous, current) if f.kind is FindingKind.DRIFT]


class TestHostileUnicode:
    def test_lone_surrogates_cannot_deny_the_whole_scan(self) -> None:
        """A hostile fleet manager can return "\\ud800" via JSON.

        Every later encode -- report, fingerprint, SQLite -- raised
        UnicodeEncodeError, so one crafted name blocked scanning of the entire
        estate and hid every other finding.
        """
        cleaned = safe_text("Zoom\ud800")
        cleaned.encode("utf-8")  # must not raise
        assert "Zoom" in cleaned

    def test_bidi_override_cannot_disguise_a_name(self) -> None:
        """Trojan Source: U+202E makes "XMRig<RLO> gpn.exe" display as
        "XMRig exe.npg", so the report names a different file than the one
        actually installed. Escapes, not literals -- a literal U+202E here
        would make this test file itself unreadable."""
        assert safe_text("XMRig\u202e gpn.exe") == "XMRig gpn.exe"
        assert safe_text("a\u200bb\u2066c") == "abc"
        assert safe_text("x\ufeffy") == "xy"


class TestCheckGating:
    def _report_for(self, checks):
        config = parse_config(
            {
                "source": {"type": "resultlog", "resultlog": {"path": "/nonexistent/a.log"}},
                "settings": {"checks": checks},
            }
        )
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("xmrig"), _sw("Adobe Flash Player")]))
        analyzer = Analyzer(
            config,
            catalog=CatalogMatcher(),
            decisions=DecisionStore("/nonexistent/decisions.yml"),
            host_label=lambda h: h.display,
        )
        return analyzer.analyze(inventory)

    def test_eol_is_a_real_gate_not_a_silent_no_op(self) -> None:
        """Regression: "eol" was accepted by config and read by nothing.

        `checks: [eol]` validated cleanly and then detected precisely nothing --
        a permanently green, permanently blind scanner.
        """
        categories = {f.category for f in self._report_for(["eol"])}
        assert RiskCategory.EOL_SOFTWARE in categories
        assert RiskCategory.CRYPTOMINER not in categories

    def test_catalog_alone_excludes_eol(self) -> None:
        categories = {f.category for f in self._report_for(["catalog"])}
        assert RiskCategory.CRYPTOMINER in categories
        assert RiskCategory.EOL_SOFTWARE not in categories

    def test_both_together_report_both(self) -> None:
        categories = {f.category for f in self._report_for(["catalog", "eol"])}
        assert {RiskCategory.CRYPTOMINER, RiskCategory.EOL_SOFTWARE} <= categories


class TestSummaryBlockInjection:
    """The AI summary is model output, and the model's input is attacker-chosen."""

    def test_a_forged_table_or_rule_cannot_restructure_the_report(self) -> None:
        payload = "___\n**CLOSED BY SECURITY**\n* forged bullet\n| Host | Status |\n| --- | --- |"
        rendered = _md_block(payload)
        for line in rendered.split("\n"):
            assert not line.startswith(("_", "*", "|", "-", "#", ">", "+", "=")), line

    def test_a_tilde_fence_cannot_swallow_the_findings_below_it(self) -> None:
        """`~~~` is the tilde spelling of a fenced code block. The backtick
        spelling was already escaped, this one was not, and a fence that is
        never closed runs to the end of the document -- so every finding under
        the Summary heading rendered as preformatted text instead."""
        rendered = _md_block("The fleet looks fine.\n~~~\nnothing to see")
        assert "\n\\~~~\n" in rendered

    def test_a_leading_number_is_suppressed_without_a_stray_backslash(self) -> None:
        """Over-escaping. CommonMark honours a backslash only before ASCII
        punctuation, so escaping the digit suppressed the ordered list and
        showed the reader "\\3 machines gained AnyDesk". Escape the marker."""
        assert _md_block("3 machines gained AnyDesk overnight.") == "3 machines gained AnyDesk overnight."
        assert _md_block("3. AnyDesk") == "3\\. AnyDesk"

    def test_a_bare_url_in_the_summary_cannot_autolink(self) -> None:
        assert _md_block("Check https://evil.example/patch today.") == (
            "Check `https://evil.example/patch` today."
        )

    def test_ordinary_prose_is_untouched(self) -> None:
        assert _md_block("Three hosts gained remote-access tools.\n\nReview them.") == (
            "Three hosts gained remote-access tools.\n\nReview them."
        )


class TestStateFileSymlink:
    """The database holds real hostnames even in pseudonymous mode."""

    def test_a_symlink_to_an_existing_file_is_refused(self, tmp_path) -> None:
        """Regression: the O_NOFOLLOW open was guarded by `if not path.exists()`.

        Path.exists() follows symlinks, so a link aimed at an existing
        attacker-owned file skipped the guard entirely and sqlite3.connect()
        followed it. Only a link to a *missing* target failed closed.
        """
        victim = tmp_path / "leak.db"
        victim.write_bytes(b"")
        os.chmod(victim, 0o666)  # noqa: S103 - the attacker-owned file this test simulates
        link = tmp_path / "state.db"
        link.symlink_to(victim)

        with pytest.raises(StateError):
            SnapshotStore(link, scope="p").save(Inventory(collected_at="t", source="x"))
        assert victim.stat().st_size == 0  # nothing was written through the link

    def test_a_symlink_to_a_missing_file_is_refused(self, tmp_path) -> None:
        link = tmp_path / "state.db"
        link.symlink_to(tmp_path / "absent.db")
        with pytest.raises(StateError):
            SnapshotStore(link, scope="p").save(Inventory(collected_at="t", source="x"))

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
    def test_a_fifo_state_path_fails_instead_of_hanging(self, tmp_path) -> None:
        """The same blocking open as the salt file, and the same consequence:
        the run never returns rather than refusing the path."""
        path = tmp_path / "state.db"
        os.mkfifo(path)
        with pytest.raises(StateError, match="not a regular file"):
            SnapshotStore(path, scope="p").save(Inventory(collected_at="t", source="x"))

    def test_loose_permissions_are_repaired(self, tmp_path) -> None:
        path = tmp_path / "state.db"
        SnapshotStore(path, scope="p").save(Inventory(collected_at="t", source="x"))
        os.chmod(path, 0o644)
        SnapshotStore(path, scope="p").save(Inventory(collected_at="t", source="x"))
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


class TestHtmlCompleteness:
    """ "No findings" and "the scan did not work" must not look identical."""

    def _report(self, **kw) -> ScanReport:
        base = {
            "started_at": "t",
            "finished_at": "t",
            "tool_version": "0.1.0",
            "source": "test",
            "hosts_scanned": 1,
            "findings": [],
        }
        base.update(kw)
        return ScanReport(**base)

    def test_collection_errors_reach_the_html_report(self) -> None:
        """Regression: HTML rendered only counts and findings.

        A run that collected one host of four, against a baseline sharing no
        hosts, produced an HTML page saying "No findings" -- while Markdown and
        JSON both carried the notes explaining that drift was non-functional.
        """
        html_out = render_html(
            self._report(
                baseline_available=True,
                collection_errors=["3 host(s) reported an empty software list and were skipped"],
            )
        )
        assert "Collection notes" in html_out
        assert "empty software list" in html_out

    def test_a_first_run_says_so_in_html(self) -> None:
        html_out = render_html(self._report(baseline_available=False))
        assert "No baseline" in html_out

    def test_collection_errors_are_escaped_in_html(self) -> None:
        html_out = render_html(
            self._report(baseline_available=True, collection_errors=["<img src=x onerror=1>"])
        )
        assert "<img" not in html_out
        assert "&lt;img" in html_out

    def test_a_clean_run_shows_no_notice(self) -> None:
        assert "Collection notes" not in render_html(self._report(baseline_available=True))


class TestSlackBlocks:
    """Slack mrkdwn has no backslash escape, so context is the only defence."""

    def _blocks(self, **kw):
        captured = {}

        def fake(method, url, **kwargs):
            captured.update(kwargs.get("json_body") or {})

            class _R:
                status_code = 200
                text = "ok"

            return _R()

        report = ScanReport(
            started_at="t",
            finished_at="t",
            tool_version="0.1.0",
            source="test",
            hosts_scanned=1,
        )
        findings = kw.get("findings") or [_finding(software="x")]
        with mock.patch.object(notify, "safe_request", fake):
            notify._post_slack(
                "https://hooks.example/x",
                report,
                findings,
                limit=kw.get("limit", 20),
                user_agent="t",
            )
        return captured["blocks"]

    def test_a_crafted_name_cannot_format_the_alert(self) -> None:
        """Regression: title and detail went through an escaper that handled
        only &, < and >, so an endpoint-chosen name controlled bold, code spans
        and emoji in the alert an on-call analyst reads."""
        payload = "Zoom` :white_check_mark: *ALL CLEAR - no action needed* `x"
        blocks = self._blocks(findings=[_finding(software=payload, title=f"{payload} appeared")])
        prose = [b for b in blocks if b.get("text", {}).get("type") == "plain_text"]
        assert prose, "the finding prose must not be rendered as mrkdwn"
        for block in prose:
            assert block["text"]["emoji"] is False  # :white_check_mark: stays literal
        # The one mrkdwn block per finding is ours; the name inside it sits in a
        # code span with its backticks neutralised.
        mrkdwn = [b for b in blocks if b.get("text", {}).get("type") == "mrkdwn"]
        assert all("`x" not in b["text"]["text"].replace("`", "", 1) for b in mrkdwn[3:])

    def test_the_block_count_stays_under_slacks_limit(self) -> None:
        """notify.max_findings_per_message accepts 100; Slack rejects >50 blocks,
        so the scan that found the most was the one that alerted least."""
        findings = [_finding(software=f"s{i}") for i in range(100)]
        blocks = self._blocks(findings=findings, limit=100)
        assert len(blocks) <= 50
        assert any("more. See the full report" in str(b) for b in blocks)


class TestAiPrivacy:
    def test_identified_mode_still_sends_no_hostname(self) -> None:
        """PRIVACY.md promises unconditionally that the AI layer never receives
        hostnames. It was sending host_display, which is the real hostname under
        privacy.mode: identified."""
        report = ScanReport(
            started_at="t",
            finished_at="t",
            tool_version="0.1.0",
            source="test",
            hosts_scanned=1,
            findings=[
                dataclasses.replace(
                    _finding(software="AnyDesk"),
                    host_display="alice-macbook.corp.example.com",
                )
            ],
        )

        captured = {}

        def fake(method, url, **kwargs):
            captured.update(kwargs.get("json_body") or {})

            class _R:
                status_code = 200

                @staticmethod
                def json():
                    return {"content": [{"type": "text", "text": "ok"}]}

            return _R()

        config = AIConfig(enabled=True, summarize=True)
        with (
            mock.patch.object(ai, "safe_request", fake),
            mock.patch.dict(os.environ, {config.api_key_env: "sk-test"}),
        ):
            ai.summarize(report, config)

        body = json.dumps(captured)
        assert "alice-macbook" not in body
        assert "machine-1" in body


class TestDecisionReview:
    """An approved decision is the only kind that changes a finding."""

    def _store(self, tmp_path, body: str) -> DecisionStore:
        path = tmp_path / "decisions.yml"
        path.write_text(f"version: 1\ndecisions:\n{body}", encoding="utf-8")
        return DecisionStore(path)

    def test_an_approved_decision_needs_a_named_reviewer(self, tmp_path) -> None:
        """The file is described as an audit trail in which every classification
        carries a named reviewer, and nothing enforced it: a proposal could be
        promoted to "approved" -- taking full effect on category and severity --
        with nobody's name against it, which is the answer this design exists so
        that an auditor never has to accept."""
        store = self._store(tmp_path, "  - name: acme agent\n    status: approved\n    verdict: flag\n")
        with pytest.raises(ValidationError, match="reviewed_by"):
            store.load()

    def test_a_named_reviewer_makes_it_active(self, tmp_path) -> None:
        store = self._store(
            tmp_path,
            "  - name: acme agent\n    status: approved\n    verdict: flag\n    reviewed_by: angel\n",
        )
        decision = store.active_for("acme agent")
        assert decision is not None
        assert decision.reviewed_by == "angel"

    def test_a_pending_proposal_needs_no_reviewer(self, tmp_path) -> None:
        """A proposal is unreviewed by definition; only approval needs a name."""
        store = self._store(tmp_path, "  - name: acme agent\n    status: pending\n")
        assert store.active_for("acme agent") is None
        assert "acme agent" in store.known_names()


class TestFleetPaginationCap:
    def test_landing_exactly_on_max_hosts_is_reported(self) -> None:
        """Regression: the "covers a subset" note used `>`, but the loop stops
        as soon as len(hosts) reaches max_hosts. With max_hosts a multiple of
        page_size -- which the shipped defaults are, 25000/100 -- it landed
        exactly on the cap and the note never fired, so a truncated fleet was
        reported as a complete scan."""
        source = FleetSource.__new__(FleetSource)
        source.config = FleetSourceConfig(url="https://fleet.example", page_size=5)
        source.max_hosts = 10
        source._get = lambda path, params: {
            "hosts": [{"id": i, "uuid": f"u{i}", "hostname": f"h{i}"} for i in range(5)]
        }
        inventory = Inventory(collected_at="t", source="fleet")
        hosts = source._list_hosts(inventory)
        assert len(hosts) == 10
        assert any("max_hosts" in e for e in inventory.errors), inventory.errors


class TestEmptyCurrentSnapshotIsNotAnUninstall:
    """The mirror of the empty-baseline guard, and the one that was missing.

    "The host reported nothing this run" and "everything was uninstalled" are
    different facts. Reporting the first as the second announces remediation
    that did not happen, which is worse than saying nothing.
    """

    def test_a_host_that_reported_nothing_produces_no_removals(self) -> None:
        previous = {"h1": HostSnapshot(host=_host(), software=[_sw("AnyDesk")])}
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(HostSnapshot(host=_host(), software=[]))
        assert _diff(previous, current) == []

    def test_a_real_uninstall_is_still_reported(self) -> None:
        previous = {"h1": HostSnapshot(host=_host(), software=[_sw("AnyDesk"), _sw("Slack")])}
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(HostSnapshot(host=_host(), software=[_sw("Slack")]))
        assert any("removed" in f.title for f in _diff(previous, current))


class TestResultLogIsOpenedThroughADescriptor:
    """A results log lives in a drop directory shared with whatever ships it."""

    def _source(self, path) -> ResultLogSource:
        return ResultLogSource(ResultLogSourceConfig(path=str(path)))

    def test_a_symlinked_results_log_is_refused(self, tmp_path) -> None:
        target = tmp_path / "secrets.log"
        target.write_text("{}\n", encoding="utf-8")
        link = tmp_path / "results.log"
        link.symlink_to(target)

        with pytest.raises(SourceError, match="cannot open results log"):
            self._source(link).collect()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
    def test_a_fifo_results_log_fails_rather_than_hanging(self, tmp_path) -> None:
        """O_NONBLOCK is the difference between a failure and a hung cron job."""
        path = tmp_path / "results.log"
        os.mkfifo(path)

        with pytest.raises(SourceError, match="not a regular file"):
            self._source(path).collect()

    def test_a_missing_results_log_still_says_so(self, tmp_path) -> None:
        with pytest.raises(SourceError, match="not found"):
            self._source(tmp_path / "absent.log").collect()

    def test_a_real_log_is_still_read(self, tmp_path) -> None:
        path = tmp_path / "results.log"
        record = {
            "name": "fleetdrift_macos_apps",
            "hostIdentifier": "h1",
            "unixTime": 100,
            "snapshot": [{"name": "Slack.app", "version": "4.0"}],
            "decorations": {"hostname": "h1.corp", "platform": "darwin"},
        }
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        inventory = self._source(path).collect()
        assert inventory.host_count == 1


class TestOperatorSuppliedFilesAreOpenedThroughADescriptor:
    """The catalog and the decision file are read from the checked-out repo."""

    def test_a_symlinked_catalog_is_refused(self, tmp_path) -> None:
        from fleetdrift.rules.catalog import load_catalog

        target = tmp_path / "elsewhere.yml"
        target.write_text("entries: []\n", encoding="utf-8")
        link = tmp_path / "catalog.yml"
        link.symlink_to(target)

        with pytest.raises(ValidationError, match="cannot open catalog file"):
            load_catalog(link)

    def test_a_symlinked_decision_file_is_refused(self, tmp_path) -> None:
        target = tmp_path / "elsewhere.yml"
        target.write_text("version: 1\ndecisions: []\n", encoding="utf-8")
        link = tmp_path / "decisions.yml"
        link.symlink_to(target)

        with pytest.raises(ValidationError, match="cannot open decision file"):
            DecisionStore(link).load()

    def test_a_missing_decision_file_is_still_just_an_empty_store(self, tmp_path) -> None:
        assert DecisionStore(tmp_path / "absent.yml").load() == {}

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs only")
    def test_a_fifo_decision_file_fails_rather_than_hanging(self, tmp_path) -> None:
        path = tmp_path / "decisions.yml"
        os.mkfifo(path)
        with pytest.raises(ValidationError, match="not a regular file"):
            DecisionStore(path).load()


class TestStateDirectoryChain:
    """O_NOFOLLOW covers the final component only."""

    def test_a_symlinked_state_directory_is_refused(self, tmp_path) -> None:
        elsewhere = tmp_path / "attacker"
        elsewhere.mkdir()
        link = tmp_path / ".fleetdrift"
        link.symlink_to(elsewhere)

        with pytest.raises(StateError, match="is a symlink"):
            SnapshotStore(link / "fleetdrift.db", scope="p").save(Inventory(collected_at="t", source="x"))
        assert list(elsewhere.iterdir()) == []


class TestReportPathIsNotFollowed:
    """A report is written into a shared artefact directory on a build agent."""

    def _report(self) -> ScanReport:
        return ScanReport(started_at="t", finished_at="t", tool_version="0", source="test")

    def test_the_report_is_written_owner_only(self, tmp_path) -> None:
        from fleetdrift.cli import _write_report

        path = tmp_path / "report.json"
        _write_report(self._report(), str(path), "json")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_permissive_file_from_a_previous_run_is_tightened(self, tmp_path) -> None:
        from fleetdrift.cli import _write_report

        path = tmp_path / "report.md"
        path.write_text("stale", encoding="utf-8")
        os.chmod(path, 0o644)
        _write_report(self._report(), str(path), "markdown")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_symlinked_output_path_is_refused(self, tmp_path) -> None:
        from fleetdrift.cli import _write_report

        target = tmp_path / "victim.txt"
        target.write_text("original", encoding="utf-8")
        os.chmod(target, 0o644)
        link = tmp_path / "report.md"
        link.symlink_to(target)

        with pytest.raises(ValidationError, match="cannot write report"):
            _write_report(self._report(), str(link), "markdown")

        assert target.read_text(encoding="utf-8") == "original"
        # The chmod is the second half of the attack: it locks the owner out.
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


class TestEvidenceIsScrubbedAtSerialisation:
    """Evidence carries osquery row fields and an operator's catalog entries."""

    def _finding(self, evidence: dict) -> Finding:
        return Finding(
            host_display="h1",
            host_id="h1",
            software="Thing",
            version="1.0",
            kind=FindingKind.POSTURE,
            severity=Severity.LOW,
            category=RiskCategory.UNKNOWN,
            title="t",
            detail="d",
            evidence=evidence,
        )

    def test_a_credential_shaped_key_is_redacted(self) -> None:
        from fleetdrift.validation import REDACTED

        out = self._finding({"install_path": "/opt/x", "license_key": "ABCD-1234-EFGH"}).to_dict()
        assert out["evidence"]["license_key"] == REDACTED
        assert out["evidence"]["install_path"] == "/opt/x"
        assert "ABCD-1234-EFGH" not in json.dumps(out)

    def test_a_huge_host_list_is_bounded(self) -> None:
        out = self._finding({"hosts": [f"h{i}" for i in range(500)]}).to_dict()
        assert len(out["evidence"]["hosts"]) == 51
        assert out["evidence"]["hosts"][-1].endswith("more")


class TestSerialisedReportIsBounded:
    def test_findings_are_capped_and_the_total_stays_whole(self) -> None:
        from fleetdrift.models import MAX_SERIALISED_FINDINGS as cap

        findings = [
            Finding(
                host_display="h1",
                host_id="h1",
                software=f"pkg{i}",
                version="1",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                category=RiskCategory.UNKNOWN,
                title="t",
                detail="d",
            )
            for i in range(cap + 4)
        ]
        out = ScanReport(
            started_at="t", finished_at="t", tool_version="0", source="test", findings=findings
        ).to_dict()
        assert len(out["findings"]) == cap
        assert out["findings_total"] == cap + 4
        assert out["findings_truncated"] is True


class TestADevicePathIsStillWritable:
    """`-o /dev/null` is a reasonable thing to write in a pipeline that only
    wants the exit code. The 0600 is for a real file; chmod-ing a character
    device is either a permission error or, as root, a machine-wide change."""

    def test_writing_to_dev_null_neither_fails_nor_chmods_it(self) -> None:
        from fleetdrift.cli import _write_report

        before = stat.S_IMODE(os.stat("/dev/null").st_mode)
        _write_report(
            ScanReport(started_at="t", finished_at="t", tool_version="0", source="test"),
            "/dev/null",
            "json",
        )
        assert stat.S_IMODE(os.stat("/dev/null").st_mode) == before
