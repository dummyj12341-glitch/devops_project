"""
Normalize the JSON output of every scanner into one common finding format:

    {"tool", "category", "severity", "rule", "title", "location", "detail"}

Severity is one of CRITICAL, HIGH, MEDIUM, LOW, INFO.
Shared by quality_gate.py and generate_report.py.
"""
import json
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

TOOLS = {
    "gitleaks": {"file": "gitleaks.json", "category": "Secret Scanning"},
    "bandit": {"file": "bandit.json", "category": "SAST"},
    "pip-audit": {"file": "pip-audit.json", "category": "SCA (Dependencies)"},
    "trivy": {"file": "trivy.json", "category": "SCA / IaC / Secrets"},
    "dast": {"file": "dast.json", "category": "DAST"},
}


def _load(path):
    if not path.exists() or path.stat().st_size == 0:
        return None
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def _norm_sev(value):
    value = (value or "").upper()
    if value == "UNKNOWN":
        return "MEDIUM"
    return value if value in SEVERITIES else "INFO"


def _finding(tool, severity, rule, title, location, detail=""):
    return {
        "tool": tool,
        "category": TOOLS[tool]["category"],
        "severity": _norm_sev(severity),
        "rule": rule,
        "title": title,
        "location": location,
        "detail": detail,
    }


def parse_gitleaks(data):
    out = []
    for item in data or []:
        secret = item.get("Secret", "")
        masked = secret[:4] + "*" * max(len(secret) - 4, 0) if secret else ""
        out.append(_finding(
            "gitleaks", "HIGH", item.get("RuleID", ""), item.get("Description", "Secret detected"),
            f"{item.get('File', '')}:{item.get('StartLine', '')}", f"secret: {masked}",
        ))
    return out


def parse_bandit(data):
    out = []
    for r in (data or {}).get("results", []):
        out.append(_finding(
            "bandit", r.get("issue_severity"), f"{r.get('test_id')} {r.get('test_name')}",
            r.get("issue_text", ""), f"{r.get('filename')}:{r.get('line_number')}",
            f"confidence: {r.get('issue_confidence')}  {r.get('issue_cwe', {}).get('link', '')}",
        ))
    return out


def parse_trivy(data):
    out = []
    for res in (data or {}).get("Results", []) or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion") or "no fix"
            out.append(_finding(
                "trivy", v.get("Severity"), v.get("VulnerabilityID", ""),
                f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title') or ''}".strip(),
                target, f"fixed in: {fixed}",
            ))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine", "")
            out.append(_finding(
                "trivy", m.get("Severity"), m.get("ID", ""), m.get("Title", ""),
                f"{target}:{line}" if line else target, m.get("Message", ""),
            ))
        for s in res.get("Secrets") or []:
            out.append(_finding(
                "trivy", s.get("Severity"), s.get("RuleID", ""), s.get("Title", "Secret"),
                f"{target}:{s.get('StartLine', '')}",
            ))
    return out


def parse_pip_audit(data, trivy_severity):
    """pip-audit has no severity; borrow it from Trivy's DB when the CVE matches."""
    out = []
    seen = set()
    for dep in (data or {}).get("dependencies", []):
        for v in dep.get("vulns", []):
            if (dep.get("name"), v.get("id")) in seen:
                continue
            seen.add((dep.get("name"), v.get("id")))
            ids = [v.get("id", "")] + v.get("aliases", [])
            sev = next((trivy_severity[i] for i in ids if i in trivy_severity), "MEDIUM")
            fix = ", ".join(v.get("fix_versions") or []) or "no fix"
            cve = next((i for i in ids if i.startswith("CVE-")), v.get("id", ""))
            out.append(_finding(
                "pip-audit", sev, cve, f"{dep.get('name')} {dep.get('version')}",
                "requirements.txt", f"fixed in: {fix}",
            ))
    return out


def parse_dast(data):
    out = []
    for f in (data or {}).get("findings", []):
        out.append(_finding(
            "dast", f.get("severity"), f.get("id", ""), f.get("title", ""),
            f.get("url", ""), f.get("evidence", ""),
        ))
    return out


def collect(reports_dir):
    """Return (findings, tool_status) for all scanner reports in reports_dir."""
    reports_dir = Path(reports_dir)
    raw = {name: _load(reports_dir / meta["file"]) for name, meta in TOOLS.items()}
    status = {name: ("ran" if raw[name] is not None else "missing") for name in TOOLS}
    # gitleaks writes an empty list when clean, which is still a successful run
    if (reports_dir / "gitleaks.json").exists() and raw["gitleaks"] is None:
        status["gitleaks"] = "ran"

    trivy = parse_trivy(raw["trivy"])
    trivy_sev = {f["rule"]: f["severity"] for f in trivy if f["rule"].startswith(("CVE-", "GHSA-"))}

    findings = (
        parse_gitleaks(raw["gitleaks"])
        + parse_bandit(raw["bandit"])
        + parse_pip_audit(raw["pip-audit"], trivy_sev)
        + trivy
        + parse_dast(raw["dast"])
    )
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["tool"]))
    return findings, status


def count_by_severity(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def evaluate_gate(findings, thresholds):
    """Return (passed, violations). A threshold of null means 'no limit'."""
    counts = count_by_severity(findings)
    violations = []
    for sev in SEVERITIES:
        limit = thresholds.get(sev)
        if limit is not None and counts[sev] > limit:
            violations.append(f"{sev}: {counts[sev]} found (max allowed {limit})")
    return not violations, violations
