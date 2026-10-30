"""Renders a SecurityReport as JSON, Markdown or a self-contained printable HTML page."""

import html
from collections.abc import Callable, Sequence
from typing import Literal

from backdoor_watch.reporting.report_model import SecurityReport

ReportFormat = Literal["json", "markdown", "html"]


def _md_cell(value: object) -> str:
    return str(value if value is not None else "—").replace("|", "\\|").replace("\n", " ")


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    if not rows:
        return "_None._\n"
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def _sections(report: SecurityReport) -> list[tuple[str, Sequence[str], list[list[object]]]]:
    return [
        ("Findings", ["Severity", "Category", "Title", "Detail"],
         [[f.severity.value.upper(), f.category, f.title, f.detail[:400]] for f in report.findings]),
        ("Defender detections", ["Threat", "Detected", "Resources"],
         [[t.name, t.detected_at, "; ".join(t.resources[:5])] for t in report.defender_threats]),
        ("Internet connections", ["Process", "PID", "Remote", "Host", "Sent", "Received"],
         [[c.process, c.pid, c.remote, c.remote_host, c.bytes_out, c.bytes_in] for c in report.external_connections]),
        ("Ports open to the network", ["Process", "PID", "Bound to"],
         [[c.process, c.pid, c.local] for c in report.network_listeners]),
        ("Non-Microsoft autostart entries", ["Type", "Name", "Command", "Signature"],
         [[e.kind.value, e.name, e.command[:300], e.signature.status if e.signature else "—"]
          for e in report.autostart_non_microsoft]),
        ("Non-Microsoft processes", ["Name", "Instances", "Signer", "Executable"],
         [[p.name, p.instances, p.signer or p.signature_status, p.exe] for p in report.non_microsoft_processes]),
        ("Data sent per process", ["Process", "Sent", "Received"],
         [[t.process_name, t.bytes_out, t.bytes_in] for t in report.traffic_by_process]),
        ("Notable activity", ["Time (epoch)", "Event", "Summary"],
         [[int(e.timestamp), e.kind.value, e.summary] for e in report.notable_events]),
    ]


def _defender_line(report: SecurityReport) -> str:
    d = report.defender
    if d is None:
        return "Defender status: unknown"
    others = ", ".join(d.active_antivirus) or "none"
    return f"Defender real-time: {d.real_time_protection} (mode {d.running_mode}); other active antivirus: {others}"


def render_markdown(report: SecurityReport) -> str:
    parts = [f"# Backdoor Watch report: {report.hostname}\n",
             f"Generated {report.generated_at} · admin: {report.is_admin} · redacted: {report.redacted}\n",
             f"{_defender_line(report)}\n",
             "## Summary\n", _md_table(["Metric", "Value"], list(report.summary.items()))]
    if report.ai_analysis:
        parts += [f"## AI analysis ({report.ai_analysis.provider.value} / {report.ai_analysis.model})\n",
                  report.ai_analysis.markdown + "\n"]
    for title, headers, rows in _sections(report):
        parts += [f"## {title}\n", _md_table(headers, rows)]
    return "\n".join(parts)


def _html_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    if not rows:
        return "<p><em>None.</em></p>"
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c if c is not None else '—'))}</td>" for c in row) + "</tr>"
                   for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


_HTML_STYLE = ("body{font:13px system-ui,sans-serif;margin:24px;color:#111}table{border-collapse:collapse;width:100%;"
               "margin-bottom:20px}th,td{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top;"
               "word-break:break-all}th{background:#eee}pre{white-space:pre-wrap;background:#f6f6f6;padding:10px}")


def render_html(report: SecurityReport) -> str:
    # Everything is escaped: report fields contain attacker-controlled strings (command lines, names).
    parts = [f"<h1>Backdoor Watch report: {html.escape(report.hostname)}</h1>",
             f"<p>Generated {html.escape(report.generated_at)} · admin: {report.is_admin} · "
             f"redacted: {report.redacted}<br>{html.escape(_defender_line(report))}</p>",
             "<h2>Summary</h2>", _html_table(["Metric", "Value"], list(report.summary.items()))]
    if report.ai_analysis:
        parts += [f"<h2>AI analysis ({html.escape(report.ai_analysis.model)})</h2>",
                  f"<pre>{html.escape(report.ai_analysis.markdown)}</pre>"]
    for title, headers, rows in _sections(report):
        parts += [f"<h2>{html.escape(title)}</h2>", _html_table(headers, rows)]
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>Backdoor Watch report</title>"
            f"<style>{_HTML_STYLE}</style></head><body>{''.join(parts)}</body></html>")


_RENDERERS: dict[str, tuple[Callable[[SecurityReport], str], str, str]] = {
    "json": (lambda r: r.model_dump_json(indent=2), "application/json", "json"),
    "markdown": (render_markdown, "text/markdown; charset=utf-8", "md"),
    "html": (render_html, "text/html; charset=utf-8", "html"),
}


def render(report: SecurityReport, report_format: ReportFormat) -> tuple[bytes, str, str]:
    """Returns (body, content type, file extension)."""
    renderer, content_type, extension = _RENDERERS[report_format]
    return renderer(report).encode("utf-8"), content_type, extension
