# Jenkins-Based DevSecOps Pipeline for Automated Vulnerability Detection

A Jenkins pipeline that builds and tests a Python Flask application and then scans it for
vulnerabilities on every commit: secret scanning, SAST, dependency scanning (SCA),
IaC/misconfiguration scanning and DAST. All the results are combined into one HTML security
report, and a **security quality gate** blocks the build when CRITICAL or HIGH issues are found.

The repo has two versions of the same app:

| Folder        | Purpose                                                            | Expected result      |
|---------------|--------------------------------------------------------------------|----------------------|
| `app/`        | Intentionally vulnerable (SQLi, command injection, SSTI, XSS, hardcoded secrets, pickle/yaml deserialization, MD5, debug mode, outdated deps, insecure Dockerfile) | **Gate FAILS** (build red) |
| `app_secure/` | Remediated version of the same app                                 | **Gate PASSES** (build green) |

## Architecture

```
 Developer ── git commit ──► Git repo ──(pollSCM)──► Jenkins pipeline
                                                          │
   ┌──────────────────────────────────────────────────────┘
   ▼
 Checkout ► Setup Tools ► Build & Unit Tests (pytest, JUnit)
   ▼
 Security Scans (parallel)
   ├─ Secret Scan ...... Gitleaks   ─► reports/gitleaks.json
   ├─ SAST ............. Bandit     ─► reports/bandit.json
   ├─ SCA .............. pip-audit  ─► reports/pip-audit.json
   └─ SCA/IaC/Secrets .. Trivy fs   ─► reports/trivy.json
   ▼
 DAST: start app, send attack payloads ─► reports/dast.json
   ▼
 Security Report (security/generate_report.py) ─► security-report.html (HTML Publisher)
   ▼
 Security Quality Gate (security/quality_gate.py + thresholds.json)
   └─ CRITICAL > 0 or HIGH > 0 ─► build FAILED (or UNSTABLE)
```

## Tools

| Stage            | Tool                     | Detects |
|------------------|--------------------------|---------|
| CI server        | Jenkins LTS (declarative pipeline) | Orchestration, triggers, reports |
| Unit tests       | pytest + JUnit plugin    | Functional regressions |
| Secret scanning  | Gitleaks 8.30            | API keys, tokens, passwords in source |
| SAST             | Bandit 1.9               | Insecure Python code patterns (CWE-mapped) |
| SCA              | pip-audit 2.10           | Dependencies with known CVEs (PyPI / OSV advisory DB) |
| SCA / IaC        | Trivy 0.76               | CVEs, Dockerfile misconfigurations, secrets |
| DAST             | `security/dast_probe.py` | SQLi, SSTI, XSS, command injection, debug console, missing headers on the running app |
| Report & gate    | `security/findings.py`, `generate_report.py`, `quality_gate.py` | Normalises all results, HTML dashboard, pass/fail policy |

## Quick start (Windows, no Docker)

Requirements: Java 17+ (for Jenkins), Python 3 with the `py` launcher, Git.

```powershell
# 1. Run the whole pipeline locally without Jenkins (quick check / demo fallback)
powershell -ExecutionPolicy Bypass -File scripts\run_pipeline_local.ps1 -Target app         # gate FAILS
powershell -ExecutionPolicy Bypass -File scripts\run_pipeline_local.ps1 -Target app_secure  # gate PASSES
start reports\security-report.html

# 2. Start a pre-configured Jenkins (plugins, admin user and job are created automatically)
powershell -ExecutionPolicy Bypass -File scripts\setup_jenkins.ps1
#    open http://localhost:8080  (admin / admin), job "devsecops-pipeline"
#    -> Build with Parameters -> TARGET_APP = app | app_secure

# 3. Stop Jenkins
powershell -ExecutionPolicy Bypass -File scripts\stop_jenkins.ps1
```

The first build downloads the scanners into `tools/` and `.venv-tools/` (`scripts/setup_tools.ps1`).
After that, builds reuse them.

## Demo script

1. Show `app/server.py` and point out the vulnerabilities in it.
2. In Jenkins, run **Build with Parameters → TARGET_APP=app**. The stage view shows the parallel
   scans; the build ends **FAILED** at *Security Quality Gate*.
3. Open **Security Report** on the build page: severity cards, a per-scanner table and every finding with its location.
4. Run it again with **TARGET_APP=app_secure**. The build goes **green** and the report shows 0 blocking findings.
5. Optional: commit a change (for example, put a hardcoded password back in) and Jenkins picks it up within 2 minutes through `pollSCM`.

## Quality gate policy

`security/thresholds.json` sets the maximum number of findings allowed at each severity (`null` means no limit):

```json
{ "CRITICAL": 0, "HIGH": 0, "MEDIUM": null, "LOW": null, "INFO": null }
```

Set the `FAIL_ON_HIGH=false` build parameter to mark the build UNSTABLE instead of FAILED.

## Project layout

```
app/ app_secure/          demo application (vulnerable / fixed)
tests/                    pytest suite, runs against either app (TARGET_APP env var)
security/                 gitleaks config, DAST probe, report generator, quality gate, thresholds
scripts/                  setup_tools, run_pipeline_local, setup_jenkins, stop_jenkins
jenkins-config/           plugin list + init.groovy.d (admin user, job creation)
Jenkinsfile               the pipeline
```

> ⚠️ `app/` is deliberately insecure and its "secrets" are fake. Never deploy it. The Jenkins
> settings in `setup_jenkins.ps1` (admin/admin, relaxed report CSP, local checkout) are for a local demo only.
