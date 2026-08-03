"""Report rendering: Markdown, JSON and a standalone HTML summary.

Everything endpoint-supplied is escaped here as well as at ingestion. Software
names come from the machines being watched, and reports get pasted into tickets,
chat and job summaries that render Markdown and HTML — so a package named
``Zoom<script>`` must not become a script tag, and one containing a newline must
not be able to forge an extra finding line.
"""

from __future__ import annotations

import html
import re
from typing import Any

from .models import FindingKind, ScanReport, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b3261e",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#b7791f",
    Severity.LOW: "#1e6fb8",
    Severity.INFO: "#5f6b7a",
}

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


# Markdown metacharacters that let attacker-chosen text do more than render as
# text: backtick breaks out of a code span, and the bracket/paren/bang set
# builds links and images. Emphasis markers (* _ ~) are deliberately NOT
# escaped — the worst they can do is make text bold, and escaping them made
# every `remote_access` render as `remote\_access`. A package named
# ``AnyDesk ![](https://evil/beacon.png) [Remediate](https://evil/phish)``
# would otherwise put a tracking pixel and a phishing link into the security
# report an analyst opens in a ticket.
_MD_ESCAPE_RE = re.compile(r"([`\[\]()!])")


def _md(text: object) -> str:
    """Neutralise endpoint-supplied text for Markdown.

    ``<`` is always escaped because it opens an HTML tag. ``>`` is significant
    only at the start of a line, where it begins a blockquote — escaping it
    everywhere would render every "1.2 -> 1.3" as "-&gt;".
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    escaped = _MD_ESCAPE_RE.sub(r"\\\1", collapsed).replace("<", "&lt;")
    if escaped.startswith(">"):
        escaped = "&gt;" + escaped[1:]
    return escaped


def _code(text: object) -> str:
    """Prepare a value for rendering inside a Markdown code span.

    Backslash escapes are inert inside backticks, so running :func:`_md` here
    would print the backslashes literally -- ``TeamViewer \\(64-bit\\)`` instead
    of ``TeamViewer (64-bit)``. Parentheses, brackets and ``!`` are harmless
    inside a code span and common in real names, so they are left alone.

    Two characters are still handled. The backtick would close the span, so it
    is replaced rather than escaped. ``<`` and ``>`` are entity-escaped even
    though a CommonMark-compliant renderer already escapes HTML inside a code
    span: reports get pasted into whatever a team happens to use, and a
    renderer that mishandles code spans should not be the only thing standing
    between an endpoint-chosen name and an ``<img>`` tag. The fidelity cost is
    accepted here because a legitimate software name does not contain ``<``.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    return collapsed.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def _md_url(value: object) -> str:
    """Render a reference URL, or drop it if it is not a plain http(s) link.

    Reference lists carry OSV identifiers and operator-supplied catalog
    references. A value containing ``)`` would break out of the link target.
    """
    text = " ".join(_CONTROL_CHARS_RE.sub(" ", str(value)).split())
    if not text.startswith(("https://", "http://")):
        return ""
    if any(ch in text for ch in "()<>[]` "):
        return ""
    return text


def _md_block(text: object) -> str:
    """Like :func:`_md` but preserves paragraph breaks, for the AI summary."""
    lines = [
        " ".join(_CONTROL_CHARS_RE.sub(" ", line).split())
        for line in str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]
    out: list[str] = []
    blanks = 0
    for line in lines:
        if line:
            blanks = 0
            escaped = _MD_ESCAPE_RE.sub(r"\\\1", line).replace("<", "&lt;")
            # A line beginning with >, #, -, *, _, |, + or = creates a
            # blockquote, heading, list, rule or table. This text is model
            # output, and the model's input includes attacker-chosen software
            # names, so it must not be able to restructure the report it lands
            # in. `*` and `_` open bullets and thematic breaks (`___`); `|`
            # opens a table row, and a table's `| --- |` separator was not
            # covered by the leading-`-` case because the `|` comes first --
            # which was enough to render a forged "all clear" table inside the
            # Summary section of a report an analyst reads.
            if escaped[:1] in (">", "#", "-", "+", "=", "*", "_", "|") or escaped[:1].isdigit():
                escaped = "\\" + escaped
            out.append(escaped)
        else:
            blanks += 1
            if blanks <= 1:
                out.append("")
    return "\n".join(out).strip()


def render_markdown(report: ScanReport, *, include_info: bool = True) -> str:
    counts = report.counts_by_severity()
    findings = [f for f in report.findings if include_info or f.severity > Severity.INFO]

    lines: list[str] = [
        "# fleetdrift report",
        "",
        f"- **Hosts scanned:** {report.hosts_scanned}",
        f"- **Software entries:** {report.software_seen}",
        f"- **Hosts with findings:** {report.affected_hosts()}",
        f"- **Source:** {_md(report.source)}",
        f"- **Finished:** {report.finished_at}",
        "- **Baseline:** "
        + (
            "compared against previous scan"
            if report.baseline_available
            else "none — this run establishes the baseline, so no drift findings are possible"
        ),
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} "
        f"| {counts['low']} | {counts['info']} |",
        "",
    ]

    if report.ai_summary:
        lines += [
            "## Summary",
            "",
            _md_block(report.ai_summary),
            "",
            "> _Generated by a language model from the findings below. Advisory only —"
            " the findings themselves are produced deterministically._",
            "",
        ]

    drift = [f for f in findings if f.kind is FindingKind.DRIFT]
    posture = [f for f in findings if f.kind is FindingKind.POSTURE]
    operational = [f for f in findings if f.kind is FindingKind.OPERATIONAL]

    if drift:
        lines += [f"## Changes since last scan ({len(drift)})", ""]
        lines += _render_findings(drift)
    if posture:
        lines += [f"## Current posture ({len(posture)})", ""]
        lines += _render_findings(posture)
    if operational:
        lines += [f"## Scan issues ({len(operational)})", ""]
        lines += _render_findings(operational)

    if report.collection_errors:
        lines += [f"## Collection notes ({len(report.collection_errors)})", ""]
        lines += [f"- {_md(err)}" for err in report.collection_errors[:50]]
        lines.append("")

    if report.unknown_software:
        lines += [
            f"## Unclassified software ({len(report.unknown_software)})",
            "",
            "Seen on the fleet but not matched by any rule and not yet decided on. "
            "These are not findings. Run `fleetdrift triage` to draft classifications "
            "for review.",
            "",
            "```",
            # Inside a fence, so escaping would show backslashes; the only
            # thing that matters is that a value cannot close the fence.
            *[_code(name).replace("```", "~~~") for name in report.unknown_software[:60]],
            "```",
            "",
        ]

    if not findings:
        lines += ["No findings. Every configured check passed.", ""]

    lines += ["---", f"_fleetdrift {report.tool_version}_", ""]
    return "\n".join(lines)


def _render_findings(findings: list[Any]) -> list[str]:
    """Render findings most-severe first, with the host on each line.

    Deliberately not grouped by host: at fleet scale the reader wants the worst
    thing on the estate first, not a tidy per-machine listing. Grouping while
    sorting by severity also made a single host appear under several headings.
    """
    lines: list[str] = []
    for finding in sorted(findings, key=lambda f: (-f.severity.rank, f.host_display, f.software)):
        emoji = _SEVERITY_EMOJI[finding.severity]
        software = f" — `{_code(finding.software)}`" if finding.software else ""
        version = f" `{_code(finding.version)}`" if finding.version else ""
        lines.append(
            f"{emoji} **{finding.severity.value.upper()} — {_md(finding.title)}**{software}{version}  "
        )
        lines.append(
            f"`{_code(finding.host_display)}` · `{_code(finding.category.value)}` · {_md(finding.detail)}"
        )
        if finding.remediation:
            lines += ["", f"> **Fix:** {_md(finding.remediation)}"]
        urls = [u for u in (_md_url(r) for r in finding.references[:5]) if u]
        if urls:
            lines += ["", "> " + " · ".join(f"[ref]({u})" for u in urls)]
        lines.append("")
    return lines


def render_json(report: ScanReport) -> str:
    return report.to_json()


def render_html(report: ScanReport) -> str:
    """A single self-contained HTML page. No external assets, no JavaScript."""
    counts = report.counts_by_severity()

    rows: list[str] = []
    for finding in sorted(report.findings, key=lambda f: (-f.severity.rank, f.host_display)):
        colour = _SEVERITY_COLOR[finding.severity]
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{colour}">'
            f"{html.escape(finding.severity.value.upper())}</span></td>"
            f"<td>{html.escape(finding.host_display)}</td>"
            f"<td><code>{html.escape(finding.software or '—')}</code>"
            f"{('<br><small>' + html.escape(finding.version) + '</small>') if finding.version else ''}</td>"
            f"<td>{html.escape(finding.category.value)}</td>"
            f"<td><strong>{html.escape(finding.title)}</strong><br>"
            f"<small>{html.escape(finding.detail)}</small></td>"
            "</tr>"
        )

    # Baseline status and collection notes are the difference between "the
    # fleet is clean" and "the scan did not work". Omitting them here -- while
    # Markdown and JSON both carried them -- meant an HTML report could show
    # "No findings" for a run that collected one host out of four and shared no
    # hosts with its baseline, so drift detection was entirely non-functional.
    notes: list[str] = []
    if not report.baseline_available:
        notes.append("No baseline: this run establishes one, so no drift findings are possible.")
    notes += [html.escape(err) for err in report.collection_errors[:50]]

    notice = ""
    if notes:
        items = "".join(f"<li>{n}</li>" for n in notes)
        notice = (
            '<section class="notice"><h2>Collection notes</h2>'
            f"<ul>{items}</ul>"
            "<p>These describe how complete the scan was. Read them before "
            "treating the table below as a full picture of the fleet.</p></section>"
        )

    summary = ""
    if report.ai_summary:
        summary = (
            '<section class="summary"><h2>Summary</h2><p>'
            + html.escape(report.ai_summary).replace("\n\n", "</p><p>").replace("\n", "<br>")
            + '</p><p class="note">Generated by a language model from the findings below. '
            "Advisory only — the findings themselves are produced deterministically.</p></section>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fleetdrift report</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        margin: 0; padding: 2rem; max-width: 1100px; margin-inline: auto; }}
 h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
 .meta {{ color: #6b7280; font-size: .875rem; margin-bottom: 1.5rem; }}
 .cards {{ display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
 .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: .6rem 1rem; min-width: 92px; }}
 .card b {{ display: block; font-size: 1.5rem; }}
 .card span {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }}
 table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
 th, td {{ text-align: left; padding: .55rem .6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
 th {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }}
 .sev {{ color: #fff; padding: .1rem .45rem; border-radius: 4px; font-size: .7rem; font-weight: 600; }}
 code {{ font-size: .85em; }}
 .summary {{ border-left: 3px solid #9ca3af; padding-left: 1rem; margin-bottom: 1.5rem; }}
 .summary .note {{ color: #6b7280; font-size: .8rem; }}
 .notice {{ border-left: 3px solid #d97706; padding-left: 1rem; margin-bottom: 1.5rem; }}
 .notice h2 {{ font-size: 1rem; margin: 0 0 .4rem; }}
 .notice ul {{ margin: 0 0 .5rem; padding-left: 1.1rem; }}
 .notice p {{ color: #6b7280; font-size: .8rem; margin: 0; }}
 footer {{ margin-top: 2rem; color: #6b7280; font-size: .8rem; }}
</style></head><body>
<h1>fleetdrift report</h1>
<p class="meta">{html.escape(str(report.hosts_scanned))} hosts ·
 {html.escape(str(report.software_seen))} software entries ·
 {html.escape(str(report.affected_hosts()))} hosts with findings ·
 source {html.escape(report.source)} · {html.escape(report.finished_at)}</p>
<div class="cards">
 <div class="card"><b>{counts["critical"]}</b><span>Critical</span></div>
 <div class="card"><b>{counts["high"]}</b><span>High</span></div>
 <div class="card"><b>{counts["medium"]}</b><span>Medium</span></div>
 <div class="card"><b>{counts["low"]}</b><span>Low</span></div>
 <div class="card"><b>{counts["info"]}</b><span>Info</span></div>
</div>
{notice}
{summary}
<table><thead><tr><th>Severity</th><th>Host</th><th>Software</th><th>Category</th><th>Finding</th></tr></thead>
<tbody>{"".join(rows) or '<tr><td colspan="5">No findings.</td></tr>'}</tbody></table>
<footer>fleetdrift {html.escape(report.tool_version)}</footer>
</body></html>
"""


def render(report: ScanReport, fmt: str, *, include_info: bool = True) -> str:
    renderers = {
        "markdown": lambda: render_markdown(report, include_info=include_info),
        "md": lambda: render_markdown(report, include_info=include_info),
        "json": lambda: render_json(report),
        "html": lambda: render_html(report),
    }
    # Resolve first, call outside the try, so a KeyError raised inside rendering
    # is not misreported as an unknown format.
    try:
        renderer = renderers[fmt.lower()]
    except KeyError as exc:
        raise ValueError(f"unknown output format {fmt!r} (expected: markdown, json, html)") from exc
    return renderer()
