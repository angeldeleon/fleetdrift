"""Trust-boundary tests.

The most important tests in the repository. Everything else produces a wrong
answer when it breaks; this produces an SSRF or an injected alert.
"""

from __future__ import annotations

import pytest

from fleetdrift.validation import (
    ValidationError,
    assert_http_url,
    assert_public_http_url,
    normalize_software_name,
    safe_text,
    validate_env_var_name,
)


class TestSSRFGuard:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/",
            "http://localhost/",
            "https://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",  # CGNAT
            "http://0.0.0.0/",
            "http://[fd00::1]/",  # unique local
            "http://[fe80::1]/",  # link local
            "http://[2002:a9fe:a9fe::]/",  # 6to4-wrapped link local
        ],
    )
    def test_rejects_internal_addresses(self, url: str) -> None:
        with pytest.raises(ValidationError):
            assert_public_http_url(url, require_https=False)

    @pytest.mark.parametrize(
        "url",
        ["file:///etc/passwd", "gopher://x.example/", "ftp://x.example/", "javascript:alert(1)", "", "   "],
    )
    def test_rejects_non_http_schemes(self, url: str) -> None:
        with pytest.raises(ValidationError):
            assert_public_http_url(url, require_https=False)

    def test_rejects_plain_http_by_default(self) -> None:
        with pytest.raises(ValidationError, match="scheme"):
            assert_public_http_url("http://example.com/")

    def test_rejects_embedded_credentials(self) -> None:
        with pytest.raises(ValidationError, match="credentials"):
            assert_public_http_url("https://user:pass@example.com/")

    def test_internal_is_allowed_only_when_opted_in(self) -> None:
        """An on-prem Fleet server is a legitimate internal target."""
        with pytest.raises(ValidationError):
            assert_http_url("https://10.0.0.5:8080/", allow_internal=False)
        assert assert_http_url("https://10.0.0.5:8080/", allow_internal=True) == "https://10.0.0.5:8080/"

    def test_opt_in_does_not_leak_to_webhooks(self) -> None:
        """assert_public_http_url has no way to permit internal addresses."""
        import inspect

        source = inspect.getsource(assert_public_http_url)
        assert "allow_internal=False" in source


class TestSafeText:
    def test_strips_control_characters(self) -> None:
        payload = "Zoom\n\n:white_check_mark: all clear"
        cleaned = safe_text(payload)
        assert "\n" not in cleaned
        assert cleaned == "Zoom :white_check_mark: all clear"

    def test_caps_length(self) -> None:
        assert len(safe_text("A" * 5000, limit=64)) <= 64

    def test_handles_non_strings(self) -> None:
        assert safe_text(None) == "None"
        assert safe_text(42) == "42"


class TestNormalizeSoftwareName:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("AnyDesk.app", "anydesk"),
            ("AnyDesk", "anydesk"),
            ("AnyDesk 8.0.8", "anydesk"),
            ("AnyDesk (64-bit)", "anydesk"),
            ("TeamViewer.exe", "teamviewer"),
            ("Google Chrome.app", "google chrome"),
            ("  Slack.app  ", "slack"),
            ("XMRig v6.21.0", "xmrig"),
            ("Microsoft Visual C++ 2015 Redistributable (x64)", "microsoft visual c 2015 redistributable"),
        ],
    )
    def test_normalisation(self, raw: str, expected: str) -> None:
        assert normalize_software_name(raw) == expected

    def test_installer_variants_collapse_to_one_key(self) -> None:
        """A rule must not be evadable by choosing a different installer."""
        variants = ["AnyDesk", "AnyDesk.app", "AnyDesk.exe", "AnyDesk (64-bit)", "anydesk 8.0.8"]
        assert len({normalize_software_name(v) for v in variants}) == 1


class TestEnvVarNames:
    def test_rejects_a_url_pasted_into_an_env_name_field(self) -> None:
        with pytest.raises(ValidationError, match="NAME of an environment"):
            validate_env_var_name("https://hooks.slack.com/services/T/B/x", where="notify.x")

    def test_rejects_invalid_identifiers(self) -> None:
        for bad in ("", "9LEADING", "has-dash", "has space", "../etc/passwd"):
            with pytest.raises(ValidationError):
                validate_env_var_name(bad, where="notify.x")

    def test_accepts_a_normal_name(self) -> None:
        assert validate_env_var_name("SLACK_WEBHOOK_URL", where="notify.x") == "SLACK_WEBHOOK_URL"
