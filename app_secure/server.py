"""
SECURE (remediated) version of the demo application.

Every vulnerability in ../app/server.py is fixed here:
  * secrets come from environment variables, never source code
  * parameterized SQL queries
  * no shell, strict input validation for the ping target
  * user input is escaped by Jinja2 autoescaping (no render_template_string)
  * PBKDF2-SHA256 instead of MD5
  * yaml.safe_load / JSON instead of yaml.load / pickle
  * debug off, bound to localhost unless APP_HOST is set, security headers on every response
  * CSRF protection on state-changing requests (Flask-WTF)
  * dependencies pinned to current patched versions
"""
import hashlib
import ipaddress
import json
import os
import secrets
# subprocess is only used with a fixed argument list and no shell
import subprocess  # nosec B404

import yaml
from flask import Flask, abort, jsonify, render_template, request
from flask_wtf.csrf import CSRFProtect

from db import get_conn, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
# every state-changing request (POST /config) needs a CSRF token
csrf = CSRFProtect(app)
PW_SALT = os.environ.get("PW_SALT", "").encode() or secrets.token_bytes(16)

init_db()


@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def index():
    return render_template("index.html", variant="SECURE")


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT name, email, role FROM users WHERE name = ?", (name,)
        ).fetchall()
    finally:
        conn.close()
    return jsonify([{"name": r[0], "email": r[1], "role": r[2]} for r in rows])


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ip = str(ipaddress.ip_address(host))
    except ValueError:
        abort(400, "host must be an IP address")
    count = "-n" if os.name == "nt" else "-c"
    # fixed argv, validated IP address, no shell
    try:
        out = subprocess.run(  # nosec B603 B607
            ["ping", count, "1", ip], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        # no ping binary / no raw-socket capability in the hardened container
        abort(503, "ping is not available")
    return render_template("ping.html", output=out.stdout)


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template("greet.html", name=name)


@app.route("/hash")
def hash_password():
    pw = request.args.get("pw", "")
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), PW_SALT, 200_000)
    return jsonify(hash=digest.hex())


@app.route("/config", methods=["POST"])
def load_config():
    data = yaml.safe_load(request.data)
    return jsonify(loaded=str(data))


@app.route("/session")
def load_session():
    blob = request.cookies.get("session_data")
    if not blob:
        return jsonify(session=None)
    try:
        obj = json.loads(blob)
    except ValueError:
        abort(400, "invalid session data")
    return jsonify(session=obj)


if __name__ == "__main__":
    # localhost by default; the container image sets APP_HOST=0.0.0.0
    app.run(host=os.environ.get("APP_HOST", "127.0.0.1"), port=int(os.environ.get("APP_PORT", "5000")), debug=False)
