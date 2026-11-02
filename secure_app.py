"""
Remediated version of vulnerable_app.py (Task 3).
Run:  export SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
      export ADMIN_PASSWORD_HASH=<werkzeug hash>   # generate_password_hash("...")
      python secure_app.py
"""
import json
import os
import re
import sqlite3
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# FIX: secrets come from the environment, never from source code
app.secret_key = os.environ["SECRET_KEY"]
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
DB = "users.db"
FILES_DIR = Path("files").resolve()
ALLOWED_REDIRECT_HOSTS = {"example.com"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# FIX: hardened session cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db():
    return sqlite3.connect(DB)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    # FIX: input validation
    if not USERNAME_RE.match(username) or not EMAIL_RE.match(email) or len(password) < 12:
        abort(400, "Invalid input (password must be 12+ characters)")
    # FIX: salted, slow hash (scrypt) instead of MD5
    pw_hash = generate_password_hash(password)
    db = get_db()
    # FIX: parameterized query
    db.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
               (username, pw_hash, email))
    db.commit()
    return "Registered", 201


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    row = get_db().execute("SELECT id, password FROM users WHERE username=?",
                           (username,)).fetchone()
    if row and check_password_hash(row[1], password):
        session.clear()
        session["user_id"] = row[0]             # FIX: signed server-side session
        return f"Welcome {escape(username)}"    # FIX: output escaping
    return "Invalid credentials", 401           # generic message


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    # FIX: authentication + authorization (users may only view their own profile)
    if session["user_id"] != user_id:
        abort(403)
    row = get_db().execute("SELECT username, email FROM users WHERE id=?",
                           (user_id,)).fetchone()
    if not row:
        abort(404)
    return f"<h1>{escape(row[0])}</h1><p>{escape(row[1])}</p>"


@app.route("/search")
def search():
    return f"<h2>Results for: {escape(request.args.get('q', ''))}</h2>"


@app.route("/ping")
@login_required
def ping():
    import ipaddress
    import subprocess
    try:
        host = str(ipaddress.ip_address(request.args.get("host", "127.0.0.1")))
    except ValueError:
        abort(400, "Invalid IP address")
    # FIX: no shell, argument list, validated input, timeout
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True,
                         text=True, timeout=5, check=False)
    return f"<pre>{escape(out.stdout)}</pre>"


@app.route("/read")
@login_required
def read_file():
    target = (FILES_DIR / request.args.get("file", "readme.txt")).resolve()
    # FIX: path must stay inside FILES_DIR
    if FILES_DIR not in target.parents or not target.is_file():
        abort(404)
    return target.read_text()


@app.route("/load", methods=["POST"])
@login_required
def load():
    # FIX: JSON instead of pickle (no code execution on deserialization)
    try:
        data = json.loads(request.data)
    except ValueError:
        abort(400)
    return jsonify(data)


@app.route("/redirect")
def go():
    url = request.args.get("url", "/")
    host = urlparse(url).netloc
    # FIX: allow-list of redirect targets
    if host and host not in ALLOWED_REDIRECT_HOSTS:
        abort(400)
    from flask import redirect
    return redirect(url)


@app.route("/admin", methods=["POST"])
def admin():
    # FIX: password in POST body, compared as a hash
    if ADMIN_PASSWORD_HASH and check_password_hash(
            ADMIN_PASSWORD_HASH, request.form.get("password", "")):
        return "Admin panel"
    abort(403)


if __name__ == "__main__":
    # FIX: debug off, bound to localhost; use a real WSGI server (gunicorn) + HTTPS in production
    app.run(host="127.0.0.1", debug=False)
