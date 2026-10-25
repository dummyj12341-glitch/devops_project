"""
VULNERABLE demo application -- DO NOT DEPLOY.

This Flask app intentionally contains common security flaws so that the
DevSecOps pipeline has something real to detect:
  * hardcoded credentials / secrets          -> Gitleaks, Trivy, Bandit
  * SQL injection                            -> Bandit, DAST probe
  * OS command injection                     -> Bandit
  * server-side template injection / XSS     -> DAST probe
  * insecure deserialization (pickle, yaml)  -> Bandit
  * weak hashing (MD5)                       -> Bandit
  * debug mode + bind to all interfaces      -> Bandit, DAST probe
  * outdated dependencies with known CVEs    -> pip-audit, Trivy
"""
import base64
import hashlib
import os
import pickle
import subprocess

import yaml
from flask import Flask, jsonify, render_template, render_template_string, request

from db import get_conn, init_db

# Explicit paths keep this legacy Flask version working on Python 3.14+ (pkgutil.get_loader was removed)
_HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, root_path=_HERE, instance_path=os.path.join(_HERE, "instance"))

# --- Hardcoded secrets (fake values, but they look real to scanners) ---
app.config["SECRET_KEY"] = "sup3r-s3cret-flask-key-2024"
AWS_ACCESS_KEY_ID = "AKIA2E0A8F3B244C9986"
AWS_SECRET_ACCESS_KEY = "Bq9xK3vT7mW2pL8nR4sY6uJ1hF5gD0aZcE3iO7kQ"
GITHUB_TOKEN = "ghp_4fT9kL2mN8pQ1rS6uV3wX7yZ0aB5cD2eF9gH"
DB_PASSWORD = "admin123"

init_db()


@app.route("/")
def index():
    return render_template("index.html", variant="VULNERABLE")


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = get_conn()
    # SQL injection: user input concatenated into the query
    query = "SELECT name, email, role FROM users WHERE name = '" + name + "'"
    try:
        rows = conn.execute(query).fetchall()
    except Exception as exc:  # leaks DB errors to the client
        return f"Database error: {exc}", 500
    finally:
        conn.close()
    return jsonify([{"name": r[0], "email": r[1], "role": r[2]} for r in rows])


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # OS command injection: shell=True with user input
    count = "-n" if os.name == "nt" else "-c"
    out = subprocess.run(f"ping {count} 1 " + host, shell=True, capture_output=True, text=True)
    return "<pre>" + out.stdout + "</pre>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # SSTI / XSS: user input rendered as a template
    return render_template_string("<h1>Hello " + name + "!</h1>")


@app.route("/hash")
def hash_password():
    pw = request.args.get("pw", "")
    # Weak hash algorithm
    return jsonify(hash=hashlib.md5(pw.encode()).hexdigest())


@app.route("/config", methods=["POST"])
def load_config():
    # Unsafe YAML loading allows arbitrary object construction
    data = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(loaded=str(data))


@app.route("/session")
def load_session():
    blob = request.cookies.get("session_data")
    if not blob:
        return jsonify(session=None)
    # Insecure deserialization of attacker-controlled data
    obj = pickle.loads(base64.b64decode(blob))
    return jsonify(session=str(obj))


if __name__ == "__main__":
    # Debug mode exposes the Werkzeug debugger; 0.0.0.0 binds every interface
    host = os.environ.get("APP_HOST", "0.0.0.0")
    app.run(host=host, port=int(os.environ.get("APP_PORT", "5000")), debug=True)
