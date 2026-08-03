"""Logging configuration with secret redaction.

The tool handles a Fleet API token, webhook URLs, SMTP credentials and an LLM
API key. Those live in environment variables and get passed around as strings,
and the most common way a secret escapes is a well-meaning log line or an
exception message that happens to contain a URL.

This filter is the backstop, not the strategy. The rest of the codebase avoids
logging secrets at all; this catches the case where someone forgets.
"""

from __future__ import annotations

import logging
import re
import sys

# Ordered most-specific first, so a Slack URL is redacted whole rather than
# partially matched by the generic pattern.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"https://hooks\.slack\.com/services/\S+"), "https://hooks.slack.com/services/<redacted>"),
    (
        re.compile(r"https://discord(?:app)?\.com/api/webhooks/\S+"),
        "https://discord.com/api/webhooks/<redacted>",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "<redacted-api-key>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), "<redacted-token>"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "<redacted-token>"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*"), "Bearer <redacted>"),
    (re.compile(r"(?i)(api[_-]?key|token|secret|password)([\"'\s:=]+)([^\s\"',}]{8,})"), r"\1\2<redacted>"),
    # A URL with a query string may carry a credential.
    (re.compile(r"(https?://[^\s/]+)/\S*\?\S+"), r"\1/<redacted>"),
    # Most webhook providers put the secret in the path, not a query string.
    (re.compile(r"(https?://[^\s/]+)(?:/[^\s/]*)*?/[A-Za-z0-9_-]{16,}\S*"), r"\1/<redacted>"),
    (re.compile(r"(https?://)[^\s/@]+:[^\s/@]+@"), r"\1<redacted>@"),
)


def redact(text: str) -> str:
    """Return *text* with credential-shaped substrings replaced."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """Strip credential-shaped substrings from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - never let logging raise
            return True

        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()

        # Tracebacks are formatted separately and never pass through
        # getMessage(), so they need redacting explicitly.
        if record.exc_info:
            try:
                formatted = logging.Formatter().formatException(record.exc_info)
            except Exception:  # pragma: no cover - defensive
                formatted = ""
            if formatted:
                record.exc_text = redact(formatted)
                record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)

        return True


def configure_logging(verbosity: int = 0, *, quiet: bool = False) -> None:
    """Set up stderr logging.

    Logs go to stderr so `fleetdrift scan -o -` can pipe a clean report to
    stdout without log lines corrupting it.
    """
    if quiet:
        level = logging.ERROR
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # httpx logs full request URLs at INFO, which would defeat the point of
    # reading webhook URLs from the environment.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
