"""Catalog matching, decisions, and the AI trust boundary."""

from __future__ import annotations

import pytest

from fleetdrift.ai import _parse_proposals
from fleetdrift.models import RiskCategory, Severity
from fleetdrift.rules.catalog import BUILTIN_CATALOG, CatalogMatcher, load_catalog
from fleetdrift.rules.decisions import (
    STATUS_APPROVED,
    STATUS_PENDING,
    Decision,
    DecisionStore,
)
from fleetdrift.validation import ValidationError, normalize_software_name


class TestCatalogMatching:
    def setup_method(self) -> None:
        self.matcher = CatalogMatcher()

    @pytest.mark.parametrize(
        ("name", "category"),
        [
            ("AnyDesk", RiskCategory.REMOTE_ACCESS),
            ("TeamViewer.app", RiskCategory.REMOTE_ACCESS),
            ("XMRig", RiskCategory.CRYPTOMINER),
            ("mimikatz", RiskCategory.CREDENTIAL_TOOL),
            ("Cobalt Strike", RiskCategory.OFFENSIVE_TOOL),
            ("NordVPN", RiskCategory.UNSANCTIONED_VPN),
            ("qBittorrent", RiskCategory.FILE_SHARING),
            ("Adobe Flash Player", RiskCategory.EOL_SOFTWARE),
            ("NinjaRMM Agent", RiskCategory.REMOTE_ACCESS),
        ],
    )
    def test_known_software_matches(self, name: str, category: RiskCategory) -> None:
        hits = self.matcher.match(normalize_software_name(name))
        assert hits, f"expected a match for {name}"
        assert hits[0].category is category

    @pytest.mark.parametrize(
        "name",
        [
            "Slack",
            "Google Chrome",
            "Microsoft Word",
            "Visual Studio Code",
            "Zoom",
            "Docker Desktop",
            "1Password",
            "Notion",
        ],
    )
    def test_ordinary_software_does_not_match(self, name: str) -> None:
        """False positives on everyday software are what kill adoption."""
        assert self.matcher.match(normalize_software_name(name)) == []

    @pytest.mark.parametrize(
        "name",
        ["Manydesks Pro", "Teamviewership", "Xmrigger", "Notorvpn", "Superduper", "Torch Browser"],
    )
    def test_token_matching_avoids_substring_collisions(self, name: str) -> None:
        """Substring matching would flag every one of these."""
        assert self.matcher.match(normalize_software_name(name)) == []

    def test_most_severe_match_is_first(self) -> None:
        hits = self.matcher.match(normalize_software_name("XMRig"))
        assert hits[0].severity is Severity.CRITICAL

    def test_every_builtin_pattern_is_long_enough_to_be_safe(self) -> None:
        for entry in BUILTIN_CATALOG:
            for pattern in entry.patterns:
                assert len(pattern) >= 4, f"{entry.id} has a dangerously short pattern: {pattern!r}"

    def test_every_builtin_entry_has_remediation_or_detail(self) -> None:
        for entry in BUILTIN_CATALOG:
            assert entry.detail, f"{entry.id} has no detail"
            assert entry.title, f"{entry.id} has no title"


class TestCatalogExtension:
    def test_loads_extra_entries(self, tmp_path) -> None:
        path = tmp_path / "extra.yml"
        path.write_text(
            "entries:\n"
            "  - id: local.badware\n"
            "    patterns: [acmecorp legacy agent]\n"
            "    category: unknown\n"
            "    severity: high\n"
            "    title: Legacy agent\n",
            encoding="utf-8",
        )
        entries = load_catalog(path)
        matcher = CatalogMatcher(entries=entries)
        assert matcher.match(normalize_software_name("AcmeCorp Legacy Agent"))

    def test_rejects_a_dangerously_short_pattern(self, tmp_path) -> None:
        path = tmp_path / "extra.yml"
        path.write_text(
            "entries:\n  - id: bad\n    patterns: [ab]\n    category: unknown\n    severity: high\n",
            encoding="utf-8",
        )
        with pytest.raises(ValidationError, match="too short"):
            load_catalog(path)

    def test_rejects_unknown_keys(self, tmp_path) -> None:
        path = tmp_path / "extra.yml"
        path.write_text(
            "entries:\n  - id: bad\n    patterns: [something long]\n    sql: SELECT 1\n",
            encoding="utf-8",
        )
        with pytest.raises(ValidationError, match="unknown key"):
            load_catalog(path)


class TestDecisions:
    def test_pending_decisions_have_no_effect(self, tmp_path) -> None:
        """The whole design rests on this."""
        path = tmp_path / "decisions.yml"
        store = DecisionStore(path)
        store.add_proposals([Decision(name="acme agent", verdict="allow", category=RiskCategory.UNKNOWN)])

        reloaded = DecisionStore(path)
        assert reloaded.get("acme agent") is not None
        assert reloaded.get("acme agent").status == STATUS_PENDING  # type: ignore[union-attr]
        assert reloaded.active_for("acme agent") is None

    def test_approved_decisions_take_effect(self, tmp_path) -> None:
        path = tmp_path / "decisions.yml"
        path.write_text(
            "version: 1\ndecisions:\n"
            "  - name: acme agent\n    status: approved\n    verdict: allow\n"
            "    category: unknown\n    severity: low\n    reviewed_by: angel\n",
            encoding="utf-8",
        )
        store = DecisionStore(path)
        decision = store.active_for("acme agent")
        assert decision is not None
        assert decision.status == STATUS_APPROVED

    def test_proposals_never_overwrite_a_human_decision(self, tmp_path) -> None:
        path = tmp_path / "decisions.yml"
        path.write_text(
            "version: 1\ndecisions:\n"
            "  - name: anydesk\n    status: approved\n    verdict: flag\n"
            "    category: remote_access\n    severity: high\n    reviewed_by: angel\n",
            encoding="utf-8",
        )
        store = DecisionStore(path)
        added = store.add_proposals(
            [Decision(name="anydesk", verdict="allow", category=RiskCategory.UNKNOWN)]
        )
        assert added == 0
        decision = store.active_for("anydesk")
        assert decision is not None and decision.verdict == "flag"

    def test_file_is_written_with_restrictive_permissions(self, tmp_path) -> None:
        import os
        import stat

        path = tmp_path / "decisions.yml"
        DecisionStore(path).add_proposals([Decision(name="acme agent")])
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_rejects_unknown_status(self, tmp_path) -> None:
        path = tmp_path / "decisions.yml"
        path.write_text(
            "version: 1\ndecisions:\n  - name: acme\n    status: definitely-fine\n", encoding="utf-8"
        )
        with pytest.raises(ValidationError, match="status"):
            DecisionStore(path).load()


class TestAIProposalParsing:
    """The model proposes; the parser refuses anything it did not ask about."""

    def test_names_not_in_the_request_are_dropped(self) -> None:
        reply = (
            '[{"name": "acme agent", "category": "unknown", "severity": "low", '
            '"verdict": "allow", "note": "fine"},'
            ' {"name": "totally different thing", "category": "unknown", "severity": "low", '
            '"verdict": "allow", "note": "injected"}]'
        )
        proposals = _parse_proposals(reply, allowed={"acme agent"}, model="test")
        assert [p.name for p in proposals] == ["acme agent"]

    def test_invalid_enum_values_fall_back_safely(self) -> None:
        reply = '[{"name": "acme agent", "category": "sudo-make-me-a-sandwich", "severity": "apocalyptic", "verdict": "ignore"}]'
        proposals = _parse_proposals(reply, allowed={"acme agent"}, model="test")
        assert len(proposals) == 1
        assert proposals[0].category is RiskCategory.UNKNOWN
        assert proposals[0].severity is Severity.LOW
        assert proposals[0].verdict == "flag"

    def test_non_json_reply_is_discarded(self) -> None:
        assert _parse_proposals("I'm afraid I can't do that", allowed={"x"}, model="test") == []

    def test_fenced_json_is_tolerated(self) -> None:
        reply = '```json\n[{"name": "acme agent", "category": "unknown", "severity": "low", "verdict": "allow"}]\n```'
        assert len(_parse_proposals(reply, allowed={"acme agent"}, model="test")) == 1

    def test_every_proposal_is_pending(self) -> None:
        reply = (
            '[{"name": "acme agent", "category": "cryptominer", "severity": "critical", "verdict": "flag"}]'
        )
        proposals = _parse_proposals(reply, allowed={"acme agent"}, model="test")
        assert all(p.status == STATUS_PENDING for p in proposals)
        assert all(not p.active for p in proposals)
