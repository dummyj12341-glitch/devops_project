"""
Lightweight DAST (Dynamic Application Security Testing) probe.

Starts the target Flask app, waits for /health, sends a set of attack
payloads against the running app, records what succeeded and stops the app.
Uses only the Python standard library so it runs anywhere.

usage: python security/dast_probe.py --app-dir app --python .venv-app\\Scripts\\python.exe --out reports/dast.json
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone


def fetch(url, timeout=15):
    """Return (status, headers, body) -- never raises on HTTP errors."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec B310 - localhost target
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read().decode("utf-8", "replace")


class Probe:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.findings = []
        self.checks = []

    def url(self, path, **params):
        query = urllib.parse.urlencode(params)
        return f"{self.base}{path}" + (f"?{query}" if query else "")

    def record(self, check, vulnerable, severity, title, url, evidence=""):
        self.checks.append({"check": check, "vulnerable": vulnerable, "url": url})
        if vulnerable:
            self.findings.append({
                "id": check, "severity": severity, "title": title,
                "url": url, "evidence": evidence[:300],
            })
        mark = "VULNERABLE" if vulnerable else "ok"
        print(f"  [{mark:>10}] {check}: {title if vulnerable else url}")

    def security_headers(self):
        url = self.url("/")
        _, headers, _ = fetch(url)
        lower = {k.lower(): v for k, v in headers.items()}
        for header, sev in [
            ("content-security-policy", "MEDIUM"),
            ("x-frame-options", "MEDIUM"),
            ("x-content-type-options", "LOW"),
        ]:
            self.record(f"DAST-HDR-{header}", header not in lower, sev,
                        f"Missing security header: {header}", url)
        server = lower.get("server", "")
        self.record("DAST-SERVER-BANNER", "/" in server, "INFO",
                    "Server header discloses software version", url, f"Server: {server}")

    def sql_injection(self):
        url = self.url("/user", name="'")
        status, _, body = fetch(url)
        self.record("DAST-SQLI-ERROR", status >= 500 and "error" in body.lower(), "HIGH",
                    "SQL injection: database error leaked for quote input", url, body[:200])

        url = self.url("/user", name="x' OR '1'='1")
        status, _, body = fetch(url)
        try:
            rows = len(json.loads(body)) if status == 200 else 0
        except ValueError:
            rows = 0
        self.record("DAST-SQLI-BOOLEAN", rows > 1, "CRITICAL",
                    "SQL injection: tautology payload dumped all users", url, f"{rows} rows returned")

    def template_injection(self):
        url = self.url("/greet", name="{{7*191}}")
        _, _, body = fetch(url)
        self.record("DAST-SSTI", "1337" in body, "CRITICAL",
                    "Server-side template injection: {{7*191}} evaluated to 1337", url, body[:200])

    def xss(self):
        payload = "<script>alert('xss')</script>"
        url = self.url("/greet", name=payload)
        _, _, body = fetch(url)
        self.record("DAST-XSS-REFLECTED", payload in body, "HIGH",
                    "Reflected XSS: script payload returned unescaped", url, body[:200])

    def command_injection(self):
        marker = "INJ" + uuid.uuid4().hex[:8]
        sep = "&" if os.name == "nt" else ";"
        url = self.url("/ping", host=f"127.0.0.1 {sep} echo {marker}")
        _, _, body = fetch(url, timeout=30)
        self.record("DAST-CMDI", marker in body, "CRITICAL",
                    "OS command injection: injected echo command executed", url, f"marker {marker} found")

    def debug_console(self):
        url = self.url("/console")
        status, _, body = fetch(url)
        self.record("DAST-DEBUG-CONSOLE", status == 200 and "debugger" in body.lower(), "HIGH",
                    "Werkzeug interactive debugger console exposed (remote code execution)", url)

    def run_all(self):
        for check in (self.security_headers, self.sql_injection, self.template_injection,
                      self.xss, self.command_injection, self.debug_console):
            try:
                check()
            except Exception as exc:  # a broken check must not abort the scan
                print(f"  [     error] {check.__name__}: {exc}")


def port_in_use(port):
    import socket
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def stop_tree(proc):
    """Stop the app and every child (venv launcher + Werkzeug reloader spawn subprocesses)."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],  # nosec B603 B607
                       capture_output=True)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def wait_for(url, proc, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            if fetch(url, timeout=2)[0] == 200:
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-dir", required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--port", type=int, default=5050)
    ap.add_argument("--out", default="reports/dast.json")
    args = ap.parse_args()

    env = dict(os.environ, APP_HOST="127.0.0.1", APP_PORT=str(args.port), PYTHONUNBUFFERED="1")
    base = f"http://127.0.0.1:{args.port}"
    log_path = os.path.join(os.path.dirname(args.out) or ".", "dast-app.log")
    if port_in_use(args.port):
        print(f"ERROR: port {args.port} is already in use; stop the other process first")
        sys.exit(2)
    print(f"Starting {args.app_dir}/server.py on {base}")
    with open(log_path, "w") as log:
        proc = subprocess.Popen(  # nosec B603 - fixed argv
            [args.python, "server.py"], cwd=args.app_dir, env=env,
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            if not wait_for(base + "/health", proc):
                print("ERROR: application did not start; see", log_path)
                sys.exit(2)
            probe = Probe(base)
            probe.run_all()
        finally:
            stop_tree(proc)

    report = {
        "tool": "dast-probe",
        "target": base,
        "app_dir": args.app_dir,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "checks_run": len(probe.checks),
        "findings": probe.findings,
        "checks": probe.checks,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"DAST complete: {len(probe.findings)} findings from {len(probe.checks)} checks -> {args.out}")


if __name__ == "__main__":
    main()
