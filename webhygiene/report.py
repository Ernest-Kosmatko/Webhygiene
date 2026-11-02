from __future__ import annotations

import html
from datetime import datetime, timezone

from .checks import Finding

COLORS = {
    "high": "#b3261e",
    "medium": "#c77700",
    "low": "#7a6c00",
    "info": "#44546a",
    "pass": "#1f7a3a",
}


def to_text(url: str, findings: list[Finding]) -> str:
    lines = [f"Target: {url}", ""]
    for f in findings:
        lines.append(f"[{f.severity.upper():<6}] {f.check}: {f.detail}")
    return "\n".join(lines)


def to_html(url: str, findings: list[Finding]) -> str:
    rows = "\n".join(
        f"<tr><td><span class='sev' style='background:{COLORS.get(f.severity, '#555')}'>"
        f"{html.escape(f.severity)}</span></td>"
        f"<td>{html.escape(f.check)}</td><td>{html.escape(f.detail)}</td></tr>"
        for f in findings
    )
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>webhygiene report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:880px;color:#1b1b1b}}
table{{border-collapse:collapse;width:100%}}
td,th{{padding:.5rem .7rem;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}
.sev{{color:#fff;padding:.1rem .5rem;border-radius:3px;font-size:.8rem;text-transform:uppercase}}
small{{color:#666}}
</style></head><body>
<h1>Web hygiene report</h1>
<p><b>Target:</b> {html.escape(url)}<br><small>Generated {stamp}</small></p>
<table><tr><th>Severity</th><th>Check</th><th>Detail</th></tr>
{rows}
</table></body></html>
"""
