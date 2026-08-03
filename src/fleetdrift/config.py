"""Configuration loading.

YAML parsed with ``yaml.safe_load`` — never ``load`` — so a config file cannot
instantiate Python objects. Unknown keys are rejected rather than ignored,
because a silently-ignored typo that disables a check is exactly the failure a
security tool must not have.

**There is deliberately no way to supply a query from configuration.** osquery
can read arbitrary files (``SELECT * FROM file WHERE path LIKE '/Users/%/.ssh/%'``
is valid SQL), so a config-injectable query would turn a monitoring tool into a
fleet-wide exfiltration primitive. The query pack is fixed in
:mod:`fleetdrift.sources.queries` and reviewed in-tree.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Severity
from .privacy import PrivacyMode
from .validation import (
    ValidationError,
    assert_http_url,
    normalize_software_name,
    safe_text,
    validate_env_var_name,
)

log = logging.getLogger(__name__)

ALL_CHECKS: tuple[str, ...] = (
    "catalog",
    "denylist",
    "allowlist",
    "signature",
    "eol",
    "vulnerabilities",
)

SOURCE_TYPES: tuple[str, ...] = ("fleet", "resultlog")

_MAX_CONFIG_BYTES = 5 * 1024 * 1024
_MAX_LIST_ENTRIES = 20000


@dataclass(slots=True)
class FleetSourceConfig:
    """Read-only connection to a Fleet (fleetdm.com) server."""

    url: str
    # Holds the NAME of an environment variable, never the token itself —
    # validate_env_var_name() rejects anything URL- or path-shaped.
    api_token_env: str = "FLEET_API_TOKEN"  # noqa: S105
    allow_internal: bool = False
    team_id: int | None = None
    label_id: int | None = None
    page_size: int = 100
    verify_tls: bool = True

    def api_token(self) -> str | None:
        return _read_env(self.api_token_env)


@dataclass(slots=True)
class ResultLogSourceConfig:
    """Reader for an osquery results log (newline-delimited JSON)."""

    path: str
    max_bytes: int = 512 * 1024 * 1024


@dataclass(slots=True)
class SourceConfig:
    type: str = "fleet"
    fleet: FleetSourceConfig | None = None
    resultlog: ResultLogSourceConfig | None = None


@dataclass(slots=True)
class PolicyConfig:
    """What the operator considers acceptable."""

    allowlist: tuple[str, ...] = ()
    denylist: tuple[str, ...] = ()
    ignore: tuple[str, ...] = ()
    catalog_extra: str | None = None
    decisions_path: str = ".fleetdrift/decisions.yml"
    # Reporting every non-allowlisted package on a 5,000-host estate produces
    # tens of thousands of findings on day one and gets the tool switched off.
    # Off unless the operator has a curated allowlist and means it.
    enforce_allowlist: bool = False


@dataclass(slots=True)
class NotifyEmailConfig:
    smtp_host: str = ""
    smtp_port: int = 587
    use_starttls: bool = True
    username_env: str | None = None
    password_env: str | None = None
    from_address: str = ""
    to_addresses: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.smtp_host and self.from_address and self.to_addresses)

    def username(self) -> str | None:
        return _read_env(self.username_env)

    def password(self) -> str | None:
        return _read_env(self.password_env)


@dataclass(slots=True)
class NotifyConfig:
    """Where findings go.

    Destination URLs are read from the *environment*, named here but never
    stored here, so a repository can carry a committed config without carrying
    a secret.
    """

    slack_webhook_url_env: str | None = None
    webhook_url_env: str | None = None
    email: NotifyEmailConfig = field(default_factory=NotifyEmailConfig)
    min_severity: Severity = Severity.HIGH
    max_findings_per_message: int = 20

    def slack_webhook_url(self) -> str | None:
        return _read_env(self.slack_webhook_url_env)

    def webhook_url(self) -> str | None:
        return _read_env(self.webhook_url_env)


@dataclass(slots=True)
class AIConfig:
    """Optional LLM assistance. See :mod:`fleetdrift.ai` for the trust boundary."""

    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-5"
    api_key_env: str = "ANTHROPIC_API_KEY"
    summarize: bool = True
    propose_unknown: bool = True
    max_items: int = 40

    def api_key(self) -> str | None:
        return _read_env(self.api_key_env)


@dataclass(slots=True)
class Settings:
    fail_on: Severity = Severity.HIGH
    http_timeout: float = 30.0
    max_hosts: int = 25000
    checks: tuple[str, ...] = ALL_CHECKS
    state_path: str = ".fleetdrift/fleetdrift.db"
    salt_path: str = ".fleetdrift/salt"
    user_agent: str = "fleetdrift (+https://github.com/angeldeleon/fleetdrift)"


@dataclass(slots=True)
class Config:
    source: SourceConfig
    settings: Settings = field(default_factory=Settings)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    privacy_mode: PrivacyMode = PrivacyMode.PSEUDONYMOUS


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------


def _read_env(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in {where}: {', '.join(unknown)} (allowed: {', '.join(sorted(allowed))})"
        )


def _bounded_int(value: Any, where: str, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be an integer") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def _bounded_float(value: Any, where: str, low: float, high: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be a number") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{where} must be true or false")
    return value


def _name_list(raw: Any, where: str) -> tuple[str, ...]:
    """Parse a list of software names into normalised matching keys."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationError(f"{where} must be a list of software names")
    if len(raw) > _MAX_LIST_ENTRIES:
        raise ValidationError(f"{where} has {len(raw)} entries; limit is {_MAX_LIST_ENTRIES}")
    names: list[str] = []
    for item in raw:
        normalized = normalize_software_name(item)
        if not normalized:
            raise ValidationError(f"{where} contains an entry that normalises to nothing: {item!r}")
        if normalized not in names:
            names.append(normalized)
    return tuple(names)


# --------------------------------------------------------------------------
# section parsers
# --------------------------------------------------------------------------


def _parse_source(raw: Any) -> SourceConfig:
    mapping = _require_mapping(raw, "source")
    if not mapping:
        raise ValidationError("config.source is required")
    _reject_unknown(mapping, {"type", "fleet", "resultlog"}, "source")

    source_type = str(mapping.get("type", "fleet")).strip().lower()
    if source_type not in SOURCE_TYPES:
        raise ValidationError(
            f"source.type {source_type!r} is not supported (expected: {', '.join(SOURCE_TYPES)})"
        )

    config = SourceConfig(type=source_type)

    if source_type == "fleet":
        fleet_raw = _require_mapping(mapping.get("fleet"), "source.fleet")
        _reject_unknown(
            fleet_raw,
            {"url", "api_token_env", "allow_internal", "team_id", "label_id", "page_size", "verify_tls"},
            "source.fleet",
        )
        url = fleet_raw.get("url")
        if not url:
            raise ValidationError("source.fleet.url is required")

        allow_internal = _bool(fleet_raw.get("allow_internal", False), "source.fleet.allow_internal")
        # Shape only. Resolving here would make `fleetdrift validate` require
        # network access and fail on a Fleet server that is merely offline;
        # the address check runs at connect time, which is where it counts.
        validated = assert_http_url(
            str(url), require_https=True, allow_internal=allow_internal, resolve=False
        )
        if allow_internal:
            log.warning(
                "source.fleet.allow_internal is enabled; the Fleet URL is not "
                "checked against public address space"
            )

        verify_tls = _bool(fleet_raw.get("verify_tls", True), "source.fleet.verify_tls")
        if not verify_tls:
            # Allowed for a self-signed on-prem deployment, but it means the API
            # token is exposed to anyone on-path, so it is never silent.
            log.warning(
                "source.fleet.verify_tls is disabled; the Fleet API token is exposed "
                "to any on-path attacker. Use a trusted certificate instead."
            )

        config.fleet = FleetSourceConfig(
            url=validated.rstrip("/"),
            api_token_env=validate_env_var_name(
                fleet_raw.get("api_token_env", "FLEET_API_TOKEN"), where="source.fleet.api_token_env"
            ),
            allow_internal=allow_internal,
            team_id=(
                _bounded_int(fleet_raw["team_id"], "source.fleet.team_id", 0, 10**9)
                if fleet_raw.get("team_id") is not None
                else None
            ),
            label_id=(
                _bounded_int(fleet_raw["label_id"], "source.fleet.label_id", 0, 10**9)
                if fleet_raw.get("label_id") is not None
                else None
            ),
            page_size=_bounded_int(fleet_raw.get("page_size", 100), "source.fleet.page_size", 1, 500),
            verify_tls=verify_tls,
        )
    else:
        log_raw = _require_mapping(mapping.get("resultlog"), "source.resultlog")
        _reject_unknown(log_raw, {"path", "max_bytes"}, "source.resultlog")
        path = log_raw.get("path")
        if not path:
            raise ValidationError("source.resultlog.path is required")
        config.resultlog = ResultLogSourceConfig(
            path=str(path),
            max_bytes=_bounded_int(
                log_raw.get("max_bytes", 512 * 1024 * 1024),
                "source.resultlog.max_bytes",
                1024,
                8 * 1024 * 1024 * 1024,
            ),
        )

    return config


def _parse_settings(raw: Any) -> Settings:
    mapping = _require_mapping(raw, "settings")
    _reject_unknown(
        mapping,
        {"fail_on", "http_timeout", "max_hosts", "checks", "state_path", "salt_path", "user_agent"},
        "settings",
    )
    settings = Settings()

    if "fail_on" in mapping:
        settings.fail_on = Severity.parse(str(mapping["fail_on"]))
    if "http_timeout" in mapping:
        settings.http_timeout = _bounded_float(mapping["http_timeout"], "settings.http_timeout", 1.0, 300.0)
    if "max_hosts" in mapping:
        settings.max_hosts = _bounded_int(mapping["max_hosts"], "settings.max_hosts", 1, 500000)
    if "state_path" in mapping:
        settings.state_path = str(mapping["state_path"])
    if "salt_path" in mapping:
        settings.salt_path = str(mapping["salt_path"])
    if "user_agent" in mapping:
        agent = safe_text(mapping["user_agent"], limit=200)
        if not agent:
            raise ValidationError("settings.user_agent must not be empty")
        settings.user_agent = agent

    if "checks" in mapping:
        checks_raw = mapping["checks"]
        if not isinstance(checks_raw, list):
            raise ValidationError("settings.checks must be a list")
        selected: list[str] = []
        for item in checks_raw:
            name = str(item).strip().lower()
            if name not in ALL_CHECKS:
                raise ValidationError(
                    f"settings.checks contains unknown check {item!r} (available: {', '.join(ALL_CHECKS)})"
                )
            if name not in selected:
                selected.append(name)
        if not selected:
            raise ValidationError("settings.checks is empty; omit the key to run all checks")
        settings.checks = tuple(selected)

    return settings


def _parse_policy(raw: Any) -> PolicyConfig:
    mapping = _require_mapping(raw, "policy")
    _reject_unknown(
        mapping,
        {"allowlist", "denylist", "ignore", "catalog_extra", "decisions_path", "enforce_allowlist"},
        "policy",
    )

    policy = PolicyConfig(
        allowlist=_name_list(mapping.get("allowlist"), "policy.allowlist"),
        denylist=_name_list(mapping.get("denylist"), "policy.denylist"),
        ignore=_name_list(mapping.get("ignore"), "policy.ignore"),
    )
    if "catalog_extra" in mapping and mapping["catalog_extra"]:
        policy.catalog_extra = str(mapping["catalog_extra"])
    if "decisions_path" in mapping and mapping["decisions_path"]:
        policy.decisions_path = str(mapping["decisions_path"])
    if "enforce_allowlist" in mapping:
        policy.enforce_allowlist = _bool(mapping["enforce_allowlist"], "policy.enforce_allowlist")

    if policy.enforce_allowlist and not policy.allowlist:
        raise ValidationError(
            "policy.enforce_allowlist is true but policy.allowlist is empty; "
            "that would flag every package on every host"
        )

    overlap = set(policy.allowlist) & set(policy.denylist)
    if overlap:
        raise ValidationError(
            f"software appears in both policy.allowlist and policy.denylist: {', '.join(sorted(overlap))}"
        )

    return policy


def _parse_email(raw: Any) -> NotifyEmailConfig:
    mapping = _require_mapping(raw, "notify.email")
    _reject_unknown(
        mapping,
        {
            "smtp_host",
            "smtp_port",
            "use_starttls",
            "username_env",
            "password_env",
            "from_address",
            "to_addresses",
        },
        "notify.email",
    )
    if not mapping:
        return NotifyEmailConfig()

    email = NotifyEmailConfig()
    email.smtp_host = safe_text(mapping.get("smtp_host", ""), limit=253)
    if "smtp_port" in mapping:
        email.smtp_port = _bounded_int(mapping["smtp_port"], "notify.email.smtp_port", 1, 65535)
    if "use_starttls" in mapping:
        email.use_starttls = _bool(mapping["use_starttls"], "notify.email.use_starttls")
    if mapping.get("username_env"):
        email.username_env = validate_env_var_name(mapping["username_env"], where="notify.email.username_env")
    if mapping.get("password_env"):
        email.password_env = validate_env_var_name(mapping["password_env"], where="notify.email.password_env")

    email.from_address = _email_address(mapping.get("from_address", ""), "notify.email.from_address")

    to_raw = mapping.get("to_addresses") or []
    if not isinstance(to_raw, list):
        raise ValidationError("notify.email.to_addresses must be a list")
    if len(to_raw) > 50:
        raise ValidationError("notify.email.to_addresses has more than 50 entries")
    email.to_addresses = tuple(
        _email_address(item, "notify.email.to_addresses") for item in to_raw if str(item).strip()
    )

    if email.smtp_host and not (email.from_address and email.to_addresses):
        raise ValidationError(
            "notify.email needs from_address and at least one to_addresses entry when smtp_host is set"
        )
    if email.smtp_host and not email.use_starttls and email.smtp_port != 465:
        log.warning(
            "notify.email.use_starttls is disabled on port %d; credentials and findings "
            "will cross the network in the clear",
            email.smtp_port,
        )
    return email


_EMAIL_RE = __import__("re").compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _email_address(value: Any, where: str) -> str:
    text = str(value).strip()
    if not text:
        return ""
    # Header-injection guard: a newline in an address splits the message and
    # lets a config add arbitrary headers or recipients.
    if any(c in text for c in "\r\n\t,;<>"):
        raise ValidationError(f"{where} contains an illegal character: {value!r}")
    if len(text) > 254 or not _EMAIL_RE.match(text):
        raise ValidationError(f"{where} is not a valid email address: {value!r}")
    return text


def _parse_notify(raw: Any) -> NotifyConfig:
    mapping = _require_mapping(raw, "notify")
    _reject_unknown(
        mapping,
        {
            "slack_webhook_url_env",
            "webhook_url_env",
            "email",
            "min_severity",
            "max_findings_per_message",
        },
        "notify",
    )

    notify = NotifyConfig()
    for key in ("slack_webhook_url_env", "webhook_url_env"):
        if mapping.get(key):
            setattr(notify, key, validate_env_var_name(mapping[key], where=f"notify.{key}"))

    if "min_severity" in mapping:
        notify.min_severity = Severity.parse(str(mapping["min_severity"]))
    if "max_findings_per_message" in mapping:
        notify.max_findings_per_message = _bounded_int(
            mapping["max_findings_per_message"], "notify.max_findings_per_message", 1, 100
        )
    notify.email = _parse_email(mapping.get("email"))
    return notify


def _parse_ai(raw: Any) -> AIConfig:
    mapping = _require_mapping(raw, "ai")
    _reject_unknown(
        mapping,
        {"enabled", "provider", "model", "api_key_env", "summarize", "propose_unknown", "max_items"},
        "ai",
    )
    ai = AIConfig()
    if "enabled" in mapping:
        ai.enabled = _bool(mapping["enabled"], "ai.enabled")
    if "provider" in mapping:
        provider = str(mapping["provider"]).strip().lower()
        if provider != "anthropic":
            raise ValidationError(f"ai.provider {provider!r} is not supported (only 'anthropic')")
        ai.provider = provider
    if "model" in mapping:
        model = safe_text(mapping["model"], limit=100)
        if not model:
            raise ValidationError("ai.model must not be empty")
        ai.model = model
    if "api_key_env" in mapping:
        ai.api_key_env = validate_env_var_name(mapping["api_key_env"], where="ai.api_key_env")
    if "summarize" in mapping:
        ai.summarize = _bool(mapping["summarize"], "ai.summarize")
    if "propose_unknown" in mapping:
        ai.propose_unknown = _bool(mapping["propose_unknown"], "ai.propose_unknown")
    if "max_items" in mapping:
        ai.max_items = _bounded_int(mapping["max_items"], "ai.max_items", 1, 200)
    return ai


def _parse_privacy(raw: Any) -> PrivacyMode:
    mapping = _require_mapping(raw, "privacy")
    _reject_unknown(mapping, {"mode"}, "privacy")
    if "mode" not in mapping:
        return PrivacyMode.PSEUDONYMOUS
    mode = PrivacyMode.parse(str(mapping["mode"]))
    if mode is PrivacyMode.IDENTIFIED:
        log.warning(
            "privacy.mode is 'identified': reports will contain real hostnames. "
            "Confirm this is compatible with your obligations before distributing them."
        )
    return mode


def load_config(path: str | Path) -> Config:
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        raise ValidationError(f"config file not found: {config_path}")

    size = config_path.stat().st_size
    if size > _MAX_CONFIG_BYTES:
        raise ValidationError(f"config file is too large ({size} bytes; limit 5 MiB)")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValidationError(f"config file is not valid YAML: {exc}") from exc

    return parse_config(raw)


def parse_config(raw: Any) -> Config:
    mapping = _require_mapping(raw, "config")
    if not mapping:
        raise ValidationError("config is empty")
    _reject_unknown(mapping, {"source", "settings", "policy", "notify", "ai", "privacy"}, "config")

    return Config(
        source=_parse_source(mapping.get("source")),
        settings=_parse_settings(mapping.get("settings")),
        policy=_parse_policy(mapping.get("policy")),
        notify=_parse_notify(mapping.get("notify")),
        ai=_parse_ai(mapping.get("ai")),
        privacy_mode=_parse_privacy(mapping.get("privacy")),
    )
