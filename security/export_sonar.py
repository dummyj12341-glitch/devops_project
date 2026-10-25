"""
Export a SonarQube project's analysis into reports/sonarqube.json so the
security report and quality gate can include it.

Saves the quality gate status, open issues and security hotspots.
Reads SONAR_HOST_URL and SONAR_AUTH_TOKEN (set by Jenkins' withSonarQubeEnv).

usage: python security/export_sonar.py --project devsecops-app [--out reports/sonarqube.json]
"""
import argparse
import base64
import json
import os
import sys
import urllib.parse
import urllib.request


def api(host, token, path, **params):
    url = f"{host.rstrip('/')}/api/{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - SonarQube server URL from Jenkins
        return json.load(resp)


def paged(host, token, path, key, **params):
    items, page = [], 1
    while True:
        data = api(host, token, path, p=page, ps=500, **params)
        items += data.get(key, [])
        total = data.get("paging", {}).get("total", data.get("total", 0))
        if page * 500 >= total:
            return items
        page += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--out", default="reports/sonarqube.json")
    args = ap.parse_args()

    host = os.environ.get("SONAR_HOST_URL", "http://sonarqube:9000")
    token = os.environ.get("SONAR_AUTH_TOKEN") or os.environ.get("SONAR_TOKEN")
    if not token:
        sys.exit("SONAR_AUTH_TOKEN is not set")

    gate = api(host, token, "qualitygates/project_status", projectKey=args.project)["projectStatus"]
    issues = paged(host, token, "issues/search", "issues", components=args.project, resolved="false")
    hotspots = paged(host, token, "hotspots/search", "hotspots", project=args.project, status="TO_REVIEW")

    report = {
        "project": args.project,
        "dashboard": f"http://localhost:9000/dashboard?id={args.project}",
        "qualityGate": gate,
        "issues": issues,
        "hotspots": hotspots,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"SonarQube {args.project}: quality gate {gate.get('status')}, "
          f"{len(issues)} issues, {len(hotspots)} hotspots -> {args.out}")


if __name__ == "__main__":
    main()
