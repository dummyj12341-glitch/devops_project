"""
Build a single self-contained HTML security dashboard from all scanner reports.

usage: python security/generate_report.py [--reports reports] [--out reports/security-report.html]
"""
import argparse
import html
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import SEVERITIES, TOOLS, collect, count_by_severity, evaluate_gate  # noqa: E402

SEV_COLOR = {
    "CRITICAL": "#8e1b1b", "HIGH": "#d64541", "MEDIUM": "#e67e22",
    "LOW": "#d4ac0d", "INFO": "#7f8c8d",
}

CSS = """
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:#f4f6f9;color:#1f2933}
header{background:#1f2933;color:#fff;padding:24px 32px}
header h1{margin:0 0 6px;font-size:24px}
header .meta{opacity:.75;font-size:13px}
main{max-width:1200px;margin:0 auto;padding:24px 16px}
.gate{padding:18px 22px;border-radius:8px;color:#fff;font-size:20px;font-weight:600;margin-bottom:20px}
.gate small{display:block;font-size:13px;font-weight:400;margin-top:4px;opacity:.9}
.pass{background:#1e8449}.fail{background:#c0392b}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:#fff;border-radius:8px;padding:16px;border-top:5px solid;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card .n{font-size:32px;font-weight:700}.card .l{font-size:12px;letter-spacing:.06em;color:#52606d}
section{background:#fff;border-radius:8px;padding:18px 22px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h2{margin:0 0 14px;font-size:18px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e4e7eb;vertical-align:top}
th{background:#f5f7fa;font-weight:600}
td.num{text-align:center}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:#e4e7eb;min-width:160px}
.bar span{display:block;height:100%}
details{border:1px solid #e4e7eb;border-radius:6px;margin-bottom:10px}
summary{cursor:pointer;padding:10px 14px;font-weight:600;background:#f5f7fa}
details table{margin:0}
code{font-family:Consolas,monospace;font-size:12px;word-break:break-all}
.muted{color:#7b8794}
footer{text-align:center;color:#7b8794;font-size:12px;padding:20px}
"""


def esc(value):
    return html.escape(str(value))


def pill(sev):
    return f'<span class="pill" style="background:{SEV_COLOR[sev]}">{sev}</span>'


def bar(counts):
    total = sum(counts.values()) or 1
    parts = "".join(
        f'<span style="width:{counts[s] * 100 / total:.1f}%;background:{SEV_COLOR[s]}" title="{s}: {counts[s]}"></span>'
        for s in SEVERITIES if counts[s]
    )
    return f'<div class="bar">{parts}</div>'


def build(reports_dir, thresholds):
    findings, status = collect(reports_dir)
    counts = count_by_severity(findings)
    passed, violations = evaluate_gate(findings, thresholds)

    env = os.environ
    target = env.get("TARGET_APP", "app")
    build_info = " &middot; ".join(esc(x) for x in [
        f"Job: {env.get('JOB_NAME', 'local run')}",
        f"Build #{env.get('BUILD_NUMBER', '-')}",
        f"Target: {target}",
        f"Commit: {env.get('GIT_COMMIT', '-')[:10]}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ])

    gate_cls = "pass" if passed else "fail"
    gate_txt = "QUALITY GATE PASSED" if passed else "QUALITY GATE FAILED"
    limits = ", ".join(f"{s} &le; {v}" for s, v in thresholds.items() if s in SEVERITIES and v is not None)
    gate_detail = "No blocking vulnerabilities." if passed else esc("; ".join(violations))

    cards = "".join(
        f'<div class="card" style="border-color:{SEV_COLOR[s]}"><div class="n">{counts[s]}</div>'
        f'<div class="l">{s}</div></div>'
        for s in SEVERITIES
    )
    cards += (f'<div class="card" style="border-color:#3e4c59"><div class="n">{len(findings)}</div>'
              f'<div class="l">TOTAL</div></div>')

    tool_rows = ""
    for tool, meta in TOOLS.items():
        tf = [f for f in findings if f["tool"] == tool]
        tc = count_by_severity(tf)
        st = status[tool]
        st_html = "&#10003; ran" if st == "ran" else '<span class="muted">not run</span>'
        tool_rows += (
            f"<tr><td><b>{esc(tool)}</b></td><td>{esc(meta['category'])}</td><td>{st_html}</td>"
            + "".join(f'<td class="num">{tc[s] or "<span class=muted>0</span>"}</td>' for s in SEVERITIES)
            + f'<td class="num"><b>{len(tf)}</b></td><td>{bar(tc)}</td></tr>'
        )

    detail_blocks = ""
    for tool, meta in TOOLS.items():
        tf = [f for f in findings if f["tool"] == tool]
        if not tf:
            continue
        rows = "".join(
            f"<tr><td>{pill(f['severity'])}</td><td><code>{esc(f['rule'])}</code></td>"
            f"<td>{esc(f['title'])}</td><td><code>{esc(f['location'])}</code></td>"
            f"<td class='muted'>{esc(f['detail'])}</td></tr>"
            for f in tf
        )
        detail_blocks += (
            f"<details open><summary>{esc(tool)} &mdash; {esc(meta['category'])} ({len(tf)})</summary>"
            "<table><tr><th>Severity</th><th>Rule / ID</th><th>Finding</th><th>Location</th><th>Detail</th></tr>"
            f"{rows}</table></details>"
        )
    if not detail_blocks:
        detail_blocks = '<p class="muted">No findings. &#127881;</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DevSecOps Security Report</title><style>{CSS}</style></head>
<body>
<header><h1>DevSecOps Security Report</h1><div class="meta">{build_info}</div></header>
<main>
<div class="gate {gate_cls}">{gate_txt}<small>{gate_detail} &nbsp;|&nbsp; Policy: {limits}</small></div>
<div class="cards">{cards}</div>
<section><h2>Results by scanner</h2>
<table><tr><th>Tool</th><th>Category</th><th>Status</th>{''.join(f'<th>{s.title()}</th>' for s in SEVERITIES)}<th>Total</th><th>Distribution</th></tr>
{tool_rows}</table></section>
<section><h2>Findings</h2>{detail_blocks}</section>
</main>
<footer>Generated by the Jenkins DevSecOps pipeline &middot; Gitleaks &middot; Bandit &middot; pip-audit &middot; Trivy &middot; DAST probe</footer>
</body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--thresholds", default=str(Path(__file__).parent / "thresholds.json"))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out = Path(args.out or Path(args.reports) / "security-report.html")
    thresholds = json.loads(Path(args.thresholds).read_text())
    out.write_text(build(args.reports, thresholds), encoding="utf-8")
    print(f"Security report written to {out}")


if __name__ == "__main__":
    main()
