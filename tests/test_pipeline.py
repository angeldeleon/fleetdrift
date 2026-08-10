"""Config, sources, analysis, drift, privacy and reporting."""

from __future__ import annotations

import json
import os
import stat

import pytest

from fleetdrift.analyze import Analyzer
from fleetdrift.config import parse_config
from fleetdrift.drift import diff_inventories
from fleetdrift.models import (
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
from fleetdrift.normalize import software_list_from_rows
from fleetdrift.privacy import PrivacyMode, Pseudonymiser
from fleetdrift.report import _md, render_html, render_markdown
from fleetdrift.rules.catalog import CatalogMatcher
from fleetdrift.rules.decisions import DecisionStore
from fleetdrift.sources.queries import QUERIES, is_known_query, render_pack
from fleetdrift.sources.resultlog import ResultLogSource
from fleetdrift.store import SnapshotStore
from fleetdrift.validation import ValidationError

# --------------------------------------------------------------------------


def _config(**overrides):
    base = {
        "source": {"type": "resultlog", "resultlog": {"path": "/dev/null"}},
        "settings": {"checks": ["catalog", "denylist", "allowlist", "signature"]},
    }
    base.update(overrides)
    return parse_config(base)


def _host(host_id="h1", platform=Platform.MACOS) -> Host:
    return Host(host_id=host_id, display=f"{host_id}.corp.example", platform=platform)


def _sw(name, host_id="h1", version="1.0", source="apps", signed=None) -> SoftwareItem:
    return SoftwareItem(host_id=host_id, name=name, version=version, source=source, signed=signed)


def _analyzer(config, decisions_path=None):
    return Analyzer(
        config,
        catalog=CatalogMatcher(),
        decisions=DecisionStore(decisions_path or "/nonexistent/decisions.yml"),
        host_label=lambda h: h.display,
    )


# --------------------------------------------------------------------------


class TestConfigParsing:
    def test_minimal(self) -> None:
        config = _config()
        assert config.source.type == "resultlog"
        assert config.privacy_mode is PrivacyMode.PSEUDONYMOUS
        assert config.settings.fail_on is Severity.HIGH

    def test_unknown_keys_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown key"):
            parse_config({"source": {"type": "resultlog", "resultlog": {"path": "/x"}}, "policyy": {}})

    def test_there_is_no_way_to_supply_a_query(self) -> None:
        """The single most important config property."""
        for attempt in (
            {"query": "SELECT * FROM file"},
            {"sql": "SELECT * FROM users"},
            {"queries": ["SELECT 1"]},
        ):
            payload = {"source": {"type": "resultlog", "resultlog": {"path": "/x", **attempt}}}
            with pytest.raises(ValidationError):
                parse_config(payload)

    def test_yaml_is_loaded_safely(self, tmp_path) -> None:
        from fleetdrift.config import load_config

        path = tmp_path / "evil.yml"
        path.write_text("source: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
        with pytest.raises(ValidationError):
            load_config(path)

    def test_webhook_url_in_env_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="NAME of an environment"):
            _config(notify={"slack_webhook_url_env": "https://hooks.slack.com/services/T/B/x"})

    def test_enforce_allowlist_requires_an_allowlist(self) -> None:
        with pytest.raises(ValidationError, match="would flag every package"):
            _config(policy={"enforce_allowlist": True})

    def test_allowlist_and_denylist_cannot_overlap(self) -> None:
        with pytest.raises(ValidationError, match="both"):
            _config(policy={"allowlist": ["Zoom"], "denylist": ["zoom"]})

    def test_email_address_injection_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="illegal character"):
            _config(
                notify={
                    "email": {
                        "smtp_host": "smtp.example.com",
                        "from_address": "a@b.com\nBcc: attacker@evil.example",
                        "to_addresses": ["sec@b.com"],
                    }
                }
            )

    def test_fleet_internal_url_requires_opt_in(self) -> None:
        with pytest.raises(ValidationError):
            parse_config({"source": {"type": "fleet", "fleet": {"url": "https://10.0.0.5"}}})
        config = parse_config(
            {"source": {"type": "fleet", "fleet": {"url": "https://10.0.0.5", "allow_internal": True}}}
        )
        assert config.source.fleet is not None


class TestQueryPack:
    def test_pack_reads_only_software_tables(self) -> None:
        forbidden = ("from file", "from users", "shell_history", "process_events", "carve", "select *")
        for query in QUERIES.values():
            sql = query.sql.lower()
            for term in forbidden:
                assert term not in sql, f"{query.name} touches {term!r}"

    def test_unknown_queries_are_not_consumed(self) -> None:
        assert is_known_query("pack/fleetdrift/fleetdrift_macos_apps")
        assert not is_known_query("pack/other/exfiltrate_ssh_keys")
        assert not is_known_query("")

    def test_rendered_pack_is_snapshot_only(self) -> None:
        pack = render_pack()
        assert pack["queries"]
        for entry in pack["queries"].values():
            assert entry["snapshot"] is True


class TestResultLogSource:
    def _write(self, tmp_path, records) -> str:
        path = tmp_path / "results.log"
        path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        return str(path)

    def test_reads_snapshots(self, tmp_path) -> None:
        from fleetdrift.config import ResultLogSourceConfig

        path = self._write(
            tmp_path,
            [
                {
                    "name": "pack/fleetdrift/fleetdrift_macos_apps",
                    "hostIdentifier": "h1",
                    "unixTime": 100,
                    "snapshot": [{"name": "Slack.app", "version": "4.0"}],
                    "decorations": {"hostname": "h1.corp", "platform": "darwin"},
                }
            ],
        )
        inventory = ResultLogSource(ResultLogSourceConfig(path=path)).collect()
        assert inventory.host_count == 1
        assert inventory.hosts[0].software[0].name == "Slack.app"
        assert inventory.hosts[0].host.platform is Platform.MACOS

    def test_ignores_queries_outside_the_pack(self, tmp_path) -> None:
        """An operator's own packs must not be silently ingested."""
        from fleetdrift.config import ResultLogSourceConfig

        path = self._write(
            tmp_path,
            [
                {
                    "name": "pack/theirs/browser_history",
                    "hostIdentifier": "h1",
                    "unixTime": 100,
                    "snapshot": [{"name": "very-private-url", "version": "1"}],
                }
            ],
        )
        inventory = ResultLogSource(ResultLogSourceConfig(path=path)).collect()
        assert inventory.host_count == 0

    def test_latest_snapshot_wins(self, tmp_path) -> None:
        from fleetdrift.config import ResultLogSourceConfig

        path = self._write(
            tmp_path,
            [
                {
                    "name": "fleetdrift_macos_apps",
                    "hostIdentifier": "h1",
                    "unixTime": 100,
                    "snapshot": [{"name": "Old.app", "version": "1"}],
                },
                {
                    "name": "fleetdrift_macos_apps",
                    "hostIdentifier": "h1",
                    "unixTime": 200,
                    "snapshot": [{"name": "New.app", "version": "2"}],
                },
            ],
        )
        inventory = ResultLogSource(ResultLogSourceConfig(path=path)).collect()
        names = [i.name for i in inventory.hosts[0].software]
        assert names == ["New.app"]

    def test_malformed_lines_are_counted_not_fatal(self, tmp_path) -> None:
        from fleetdrift.config import ResultLogSourceConfig

        path = tmp_path / "results.log"
        path.write_text("not json\n{}\n", encoding="utf-8")
        inventory = ResultLogSource(ResultLogSourceConfig(path=str(path))).collect()
        assert any("malformed" in err for err in inventory.errors)


class TestNormalisation:
    def test_control_characters_are_stripped_at_ingestion(self) -> None:
        items, _ = software_list_from_rows(
            "h1", [{"name": "Zoom\n\n:white_check_mark: all clear", "version": "1"}]
        )
        assert "\n" not in items[0].name

    def test_unknown_signed_is_not_unsigned(self) -> None:
        """Linux packages report no signature; that must not flag the estate."""
        items, _ = software_list_from_rows("h1", [{"name": "bash", "version": "5"}])
        assert items[0].signed is None

    def test_duplicates_are_collapsed(self) -> None:
        rows = [{"name": "Slack", "version": "1"}, {"name": "Slack", "version": "1"}]
        items, _ = software_list_from_rows("h1", rows)
        assert len(items) == 1

    def test_nameless_rows_are_dropped(self) -> None:
        items, _ = software_list_from_rows("h1", [{"version": "1"}, {"name": "", "version": "2"}])
        assert items == []


class TestAnalysis:
    def test_catalog_match_produces_a_finding(self) -> None:
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("AnyDesk.app")]))
        findings = _analyzer(_config()).analyze(inventory)
        assert any(f.category is RiskCategory.REMOTE_ACCESS for f in findings)

    def test_ignore_wins_over_everything(self) -> None:
        config = _config(policy={"ignore": ["AnyDesk"]})
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("AnyDesk.app")]))
        assert _analyzer(config).analyze(inventory) == []

    def test_approved_allow_decision_suppresses_the_catalog(self, tmp_path) -> None:
        path = tmp_path / "decisions.yml"
        path.write_text(
            "version: 1\ndecisions:\n  - name: anydesk\n    status: approved\n"
            "    verdict: allow\n    category: remote_access\n    severity: high\n"
            "    reviewed_by: angel\n",
            encoding="utf-8",
        )
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("AnyDesk.app")]))
        assert _analyzer(_config(), decisions_path=path).analyze(inventory) == []

    def test_unsigned_software_is_flagged(self) -> None:
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("Homebrew Thing", signed=False)]))
        findings = _analyzer(_config()).analyze(inventory)
        assert any(f.category is RiskCategory.UNSIGNED for f in findings)

    def test_unknown_signature_is_not_flagged(self) -> None:
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("bash", signed=None)]))
        findings = _analyzer(_config()).analyze(inventory)
        assert not any(f.category is RiskCategory.UNSIGNED for f in findings)

    def test_unclassified_software_is_collected_not_reported(self) -> None:
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("Acme Widget Pro")]))
        analyzer = _analyzer(_config())
        assert analyzer.analyze(inventory) == []
        assert "acme widget pro" in analyzer.unknown_software

    def test_per_host_finding_cap(self) -> None:
        inventory = Inventory(collected_at="t", source="test")
        software = [_sw(f"Unsigned Thing {i}", version=str(i), signed=False) for i in range(80)]
        inventory.hosts.append(HostSnapshot(host=_host(), software=software))
        findings = _analyzer(_config()).analyze(inventory)
        assert any(f.kind is FindingKind.OPERATIONAL and "not reported" in f.title for f in findings)


class TestDrift:
    def _diff(self, before: list[str], after: list[str], *, hosts: int = 1):
        catalog = CatalogMatcher()
        decisions = DecisionStore("/nonexistent/decisions.yml")
        previous = {
            f"h{i}": HostSnapshot(host=_host(f"h{i}"), software=[_sw(n, host_id=f"h{i}") for n in before])
            for i in range(hosts)
        }
        current = Inventory(collected_at="t", source="test")
        for i in range(hosts):
            current.hosts.append(
                HostSnapshot(host=_host(f"h{i}"), software=[_sw(n, host_id=f"h{i}") for n in after])
            )
        return diff_inventories(
            previous,
            current,
            catalog=catalog,
            decisions=decisions,
            ignore=set(),
            allowlist=set(),
            host_label=lambda h: h.display,
        )

    def test_no_baseline_yields_no_drift(self) -> None:
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(HostSnapshot(host=_host(), software=[_sw("AnyDesk")]))
        assert (
            diff_inventories(
                None,
                current,
                catalog=CatalogMatcher(),
                decisions=DecisionStore("/nonexistent"),
                ignore=set(),
                allowlist=set(),
                host_label=lambda h: h.display,
            )
            == []
        )

    def test_unchanged_fleet_is_silent(self) -> None:
        assert self._diff(["Slack", "AnyDesk"], ["Slack", "AnyDesk"]) == []

    def test_new_risky_software_is_reported_at_its_catalog_severity(self) -> None:
        findings = self._diff(["Slack"], ["Slack", "TeamViewer"])
        assert any(f.severity is Severity.HIGH and f.kind is FindingKind.DRIFT for f in findings)

    def test_fleetwide_rollout_is_downgraded(self) -> None:
        """A deployment to the whole estate is a rollout, not an intrusion."""
        findings = self._diff(["Slack"], ["Slack", "TeamViewer"], hosts=20)
        drift = [f for f in findings if f.kind is FindingKind.DRIFT and "TeamViewer" in f.software]
        assert drift and drift[0].severity <= Severity.LOW
        assert "deployed across" in drift[0].title

    def test_targeted_install_keeps_full_severity(self) -> None:
        catalog = CatalogMatcher()
        decisions = DecisionStore("/nonexistent")
        previous = {
            f"h{i}": HostSnapshot(host=_host(f"h{i}"), software=[_sw("Slack", host_id=f"h{i}")])
            for i in range(20)
        }
        current = Inventory(collected_at="t", source="test")
        for i in range(20):
            extra = [_sw("TeamViewer", host_id=f"h{i}")] if i < 2 else []
            current.hosts.append(
                HostSnapshot(host=_host(f"h{i}"), software=[_sw("Slack", host_id=f"h{i}"), *extra])
            )
        findings = diff_inventories(
            previous,
            current,
            catalog=catalog,
            decisions=decisions,
            ignore=set(),
            allowlist=set(),
            host_label=lambda h: h.display,
        )
        assert any(f.severity is Severity.HIGH for f in findings)

    def test_allowlisted_software_does_not_drift(self) -> None:
        catalog = CatalogMatcher()
        previous = {"h0": HostSnapshot(host=_host("h0"), software=[])}
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(HostSnapshot(host=_host("h0"), software=[_sw("TeamViewer", host_id="h0")]))
        findings = diff_inventories(
            previous,
            current,
            catalog=catalog,
            decisions=DecisionStore("/nonexistent"),
            ignore=set(),
            allowlist={"teamviewer"},
            host_label=lambda h: h.display,
        )
        assert findings == []

    def test_a_brand_new_host_is_not_two_hundred_incidents(self) -> None:
        catalog = CatalogMatcher()
        previous = {"h0": HostSnapshot(host=_host("h0"), software=[])}
        current = Inventory(collected_at="t", source="test")
        current.hosts.append(HostSnapshot(host=_host("h-new"), software=[_sw("TeamViewer", host_id="h-new")]))
        findings = diff_inventories(
            previous,
            current,
            catalog=catalog,
            decisions=DecisionStore("/nonexistent"),
            ignore=set(),
            allowlist=set(),
            host_label=lambda h: h.display,
        )
        assert findings == []


class TestPrivacy:
    def test_pseudonyms_are_stable_across_instances(self, tmp_path) -> None:
        salt = tmp_path / "salt"
        first = Pseudonymiser(salt).host_label("uuid-1", "laptop.corp")
        second = Pseudonymiser(salt).host_label("uuid-1", "laptop.corp")
        assert first == second
        assert "laptop" not in first

    def test_different_hosts_get_different_pseudonyms(self, tmp_path) -> None:
        salt = tmp_path / "salt"
        p = Pseudonymiser(salt)
        assert p.host_label("uuid-1", "a") != p.host_label("uuid-2", "b")

    def test_identified_mode_returns_the_hostname(self, tmp_path) -> None:
        p = Pseudonymiser(tmp_path / "salt", mode=PrivacyMode.IDENTIFIED)
        assert p.host_label("uuid-1", "laptop.corp") == "laptop.corp"

    def test_salt_is_created_with_restrictive_permissions(self, tmp_path) -> None:
        salt = tmp_path / "salt"
        Pseudonymiser(salt).host_label("uuid-1", "x")
        assert stat.S_IMODE(os.stat(salt).st_mode) == 0o600

    def test_loose_permissions_are_tightened_on_load(self, tmp_path) -> None:
        salt = tmp_path / "salt"
        salt.write_bytes(b"x" * 32)
        os.chmod(salt, 0o644)
        Pseudonymiser(salt).host_label("uuid-1", "x")
        assert stat.S_IMODE(os.stat(salt).st_mode) == 0o600

    def test_different_salts_produce_different_pseudonyms(self, tmp_path) -> None:
        a = Pseudonymiser(tmp_path / "a").host_label("uuid-1", "x")
        b = Pseudonymiser(tmp_path / "b").host_label("uuid-1", "x")
        assert a != b


class TestStore:
    def test_roundtrip(self, tmp_path) -> None:
        store = SnapshotStore(tmp_path / "state.db")
        inventory = Inventory(collected_at="t", source="test")
        inventory.hosts.append(HostSnapshot(host=_host(), software=[_sw("Slack")]))
        snapshot_id = store.save(inventory)

        loaded = SnapshotStore(tmp_path / "state.db").load_snapshot(snapshot_id)
        assert "h1" in loaded
        assert loaded["h1"].software[0].name == "Slack"

    def test_database_permissions_are_restrictive(self, tmp_path) -> None:
        path = tmp_path / "state.db"
        store = SnapshotStore(path)
        store.save(Inventory(collected_at="t", source="test"))
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_old_snapshots_are_pruned(self, tmp_path) -> None:
        store = SnapshotStore(tmp_path / "state.db", retain=3)
        for _ in range(6):
            store.save(Inventory(collected_at="t", source="test"))
        assert store.snapshot_count() == 3


class TestReporting:
    def _report(self, findings) -> ScanReport:
        return ScanReport(
            started_at="t",
            finished_at="t",
            tool_version="0.1.0",
            source="test",
            hosts_scanned=1,
            findings=findings,
        )

    def test_markdown_escapes_endpoint_supplied_text(self) -> None:
        from fleetdrift.models import Finding

        finding = Finding(
            host_display="host-1",
            host_id="h1",
            software="<img src=x onerror=alert(1)>",
            version="1",
            kind=FindingKind.POSTURE,
            severity=Severity.HIGH,
            category=RiskCategory.UNKNOWN,
            title="Suspicious",
            detail="line one\nline two",
        )
        rendered = render_markdown(self._report([finding]))
        assert "<img" not in rendered
        assert "&lt;img" in rendered

    def test_html_escapes_everything(self) -> None:
        from fleetdrift.models import Finding

        finding = Finding(
            host_display="host-1",
            host_id="h1",
            software="<script>alert(1)</script>",
            version="",
            kind=FindingKind.POSTURE,
            severity=Severity.CRITICAL,
            category=RiskCategory.UNKNOWN,
            title="x",
            detail="y",
        )
        rendered = render_html(self._report([finding]))
        assert "<script>alert" not in rendered
        assert "&lt;script&gt;" in rendered

    def test_arrow_is_not_over_escaped(self) -> None:
        assert _md("1.2 -> 1.3") == "1.2 -> 1.3"

    def test_leading_blockquote_is_escaped(self) -> None:
        assert _md("> forged quote").startswith("&gt;")


class TestDegradedScan:
    def test_zero_hosts_is_degraded(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", source="test")
        assert report.scan_degraded is True

    def test_exit_code_is_error_not_ok(self) -> None:
        from fleetdrift.cli import EXIT_ERROR, _exit_code

        report = ScanReport(started_at="t", finished_at="t", tool_version="0", source="test")
        assert _exit_code(report, Severity.HIGH) == EXIT_ERROR

    def test_a_populated_scan_is_not_degraded(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", source="test", hosts_scanned=5)
        assert report.scan_degraded is False
