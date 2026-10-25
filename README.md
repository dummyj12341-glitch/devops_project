# Jenkins-Based DevSecOps Pipeline for Automated Vulnerability Detection

A full DevSecOps pipeline built from **Jenkins, Docker, SonarQube and Kubernetes**. On every commit it:

1. Builds and unit-tests a Python Flask application.
2. Scans the code with Gitleaks, Bandit, pip-audit, Trivy and SonarQube.
3. Builds a Docker image and scans it.
4. Deploys the image to a Kubernetes **staging** namespace.
5. Attacks the live pod with a DAST probe and OWASP ZAP.
6. Promotes the release to **production** only if the security gate passes.

Every result goes into one HTML security report published on the Jenkins build.

The repo has two versions of the same app:

| Folder        | Purpose | Expected result |
|---------------|---------|-----------------|
| `app/`        | Intentionally vulnerable: SQLi, command injection, SSTI, XSS, hardcoded secrets, pickle/yaml deserialization, MD5, debug mode, outdated dependencies, old base image, insecure Dockerfile, privileged Kubernetes pod | **Gate FAILS**: removed from staging, never reaches production |
| `app_secure/` | Remediated version of the same app | **Gate PASSES**: promoted to production |

## Architecture

```
 Developer ── git push ──► GitHub ──(pollSCM)──► Jenkins (Docker container, JCasC)
                                                    │  docker.sock / kubeconfig
     ┌──────────────────────────────────────────────┘
     ▼
 Checkout ► Build & Unit Tests (pytest + coverage, JUnit)
     ▼
 Static Analysis (parallel)
   ├─ Secrets ........ Gitleaks          ─► gitleaks.json
   ├─ SAST ........... Bandit            ─► bandit.json
   ├─ SCA ............ pip-audit         ─► pip-audit.json
   ├─ SCA/IaC ........ Trivy fs          ─► trivy.json
   ├─ K8s manifest ... Trivy config      ─► trivy-k8s.json
   └─ SAST/Quality ... SonarQube scanner ─► SonarQube server (quality gate via webhook)
     ▼
 SonarQube Quality Gate ─► sonarqube.json
     ▼
 Docker Build (devsecops-<app>:<build>) ► Trivy image scan ─► trivy-image.json
     ▼
 Deploy to Kubernetes ns "staging" (kind load + kubectl apply, NodePort 30080)
     ▼
 DAST (parallel): DAST probe ─► dast.json | OWASP ZAP baseline ─► zap.json
     ▼
 Security Report (HTML Publisher) ► Security Gate (thresholds.json)
     ├─ FAIL ─► delete from staging, build FAILED, production untouched
     └─ PASS ─► Promote to Kubernetes ns "production" (NodePort 30081)
```

All of it runs locally on Docker Desktop:

| Component | Runs as | URL |
|-----------|---------|-----|
| Jenkins LTS + JCasC | container `jenkins` (`infra/jenkins/Dockerfile`) | http://localhost:8080 (admin / admin) |
| SonarQube Community + Postgres | containers `sonarqube`, `sonar-db` | http://localhost:9000 (admin / see `infra/.env`) |
| Kubernetes | kind cluster `devsecops` (`k8s/kind-config.yaml`) | staging http://localhost:30080, production http://localhost:30081 |
| OWASP ZAP | container started by the pipeline | - |

## Tools

| Stage | Tool | Detects |
|-------|------|---------|
| CI/CD orchestration | **Jenkins** (declarative pipeline, Configuration as Code, Job DSL) | Triggers, stages, reports, promotion |
| Containerization | **Docker** | Builds the app image; runs Jenkins, SonarQube and ZAP |
| Code quality + SAST | **SonarQube** + sonar-scanner | Vulnerabilities, bugs, security hotspots, leaked secrets, coverage; quality gate |
| Deployment | **Kubernetes** (kind) + kubectl | Staging/production namespaces, rollout status, promotion |
| Secret scanning | Gitleaks 8.30 | API keys, tokens, passwords in source |
| SAST | Bandit 1.9 | Insecure Python patterns (CWE-mapped) |
| SCA | pip-audit 2.10 | Dependencies with known CVEs |
| SCA / IaC / image | Trivy 0.76 | Dependency CVEs, Dockerfile and Kubernetes misconfigurations, OS CVEs in the image |
| DAST | `security/dast_probe.py` + **OWASP ZAP** baseline | SQLi, SSTI, XSS, command injection, debug console, missing headers, on the deployed pod |
| Report & gate | `security/findings.py`, `generate_report.py`, `quality_gate.py` | Combines all 9 result files, HTML dashboard, pass/fail policy |

## Quick start (Windows + Docker Desktop)

Requirements: Docker Desktop (WSL2), kind, kubectl, Git. Install them with
`winget install Docker.DockerDesktop Kubernetes.kind Kubernetes.kubectl`. Give Docker at least 6 GB of RAM.

```powershell
# start everything: kind cluster, Jenkins, SonarQube, SonarQube token/webhook/quality gate
powershell -ExecutionPolicy Bypass -File scripts\up.ps1

# open http://localhost:8080 (admin / admin) -> devsecops-pipeline -> Build with Parameters
#   TARGET_APP = app         -> FAILS at the security gate, never reaches production
#   TARGET_APP = app_secure  -> passes, promoted to production (http://localhost:30081)

kubectl get pods -A -l app=devsecops-app      # see what is deployed where

# stop (keeps data) / remove everything
powershell -ExecutionPolicy Bypass -File scripts\down.ps1
powershell -ExecutionPolicy Bypass -File scripts\down.ps1 -Purge
```

The Jenkins job builds the branch that was checked out when `up.ps1` ran, cloned from the GitHub
`origin`. Push your commits before you build. `scripts\run_pipeline_local.ps1 -Target app` still
runs the code-level scans without Docker, as an offline fallback.

## Demo script

1. Show `app/server.py`, `app/Dockerfile` and `k8s/app/deployment.yaml` and point out the planted vulnerabilities.
2. In Jenkins, run **Build with Parameters → TARGET_APP=app**. The stage view shows the parallel scans, the Docker
   build, the staging deploy and the DAST stage. The build ends **FAILED** at *Security Gate*.
3. Open **Security Report** on the build page. It shows the Deployment box (production: BLOCKED), the severity cards,
   per-scanner results and every finding. Open SonarQube (http://localhost:9000) to show the failed quality gate.
4. Run `kubectl get pods -n staging` and `kubectl get pods -n production`. The vulnerable release was removed from
   staging and production is empty.
5. Run again with **TARGET_APP=app_secure**. The build goes green, the report shows 0 blocking findings, the app is
   promoted, and http://localhost:30081 serves the secure app from Kubernetes.
6. Optional: commit and push a change (for example, put a hardcoded password back in). Jenkins picks it up within
   2 minutes through `pollSCM`.

## Quality gate policy

`security/thresholds.json` sets the maximum number of findings allowed at each severity (`null` means no limit):

```json
{ "CRITICAL": 0, "HIGH": 0, "MEDIUM": null, "LOW": null, "INFO": null }
```

- A failed SonarQube quality gate counts as a HIGH finding. The SonarQube "DevSecOps" gate requires security rating A
  and reliability rating C or better on overall code.
- The image scan reports only OS CVEs that have a fix (`--ignore-unfixed`).
- Set the `FAIL_ON_HIGH=false` build parameter to mark the build UNSTABLE instead of FAILED. It is still not promoted.

## Project layout

```
app/ app_secure/          demo application (vulnerable / fixed) + Dockerfiles
tests/                    pytest suite, runs against either app (TARGET_APP env var)
security/                 parsers, DAST probe, SonarQube export, report generator, quality gate, thresholds
k8s/                      kind cluster config, namespaces, per-app Deployment + Service
infra/                    docker-compose (Jenkins, SonarQube, Postgres), Jenkins image, JCasC, plugins
scripts/                  up / down / bootstrap_sonar, run_pipeline_local + setup_tools (offline fallback)
Jenkinsfile               the pipeline
```

> ⚠️ `app/` is deliberately insecure and its "secrets" are fake. Never deploy it outside this demo. The platform
> settings (admin/admin, Docker socket mounted into Jenkins, relaxed report CSP) are for a local demo only.
