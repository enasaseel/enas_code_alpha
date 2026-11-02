"""
INTENTIONALLY VULNERABLE demo app (Task 3 - code under review).
DO NOT deploy. It exists only to be audited.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, make_response, redirect, request

app = Flask(__name__)
app.secret_key = "super-secret-key-123"          # hardcoded secret
ADMIN_PASSWORD = "admin123"                      # hardcoded credential
DB = "users.db"


def get_db():
    return sqlite3.connect(DB)


def init_db():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
               "username TEXT, password TEXT, email TEXT)")
    db.commit()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    email = request.form["email"]
    pw_hash = hashlib.md5(password.encode()).hexdigest()      # weak hash, no salt
    db = get_db()
    db.execute(f"INSERT INTO users (username, password, email) "
               f"VALUES ('{username}', '{pw_hash}', '{email}')")   # SQL injection
    db.commit()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = hashlib.md5(request.form["password"].encode()).hexdigest()
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username='" + username +
                     "' AND password='" + password + "'").fetchone()   # SQL injection
    if row:
        resp = make_response("Welcome " + username)            # reflected XSS
        resp.set_cookie("user", username)                       # insecure cookie, forgeable
        return resp
    return "Invalid credentials", 401


@app.route("/profile/<int:user_id>")
def profile(user_id):
    # No authentication / authorization check (IDOR)
    row = get_db().execute("SELECT username, email FROM users WHERE id=?",
                           (user_id,)).fetchone()
    return f"<h1>{row[0]}</h1><p>{row[1]}</p>" if row else "Not found"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h2>Results for: {q}</h2>"                         # reflected XSS


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)   # command injection


@app.route("/read")
def read_file():
    name = request.args.get("file", "readme.txt")
    with open(os.path.join("files", name)) as f:                # path traversal
        return f.read()


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                      # insecure deserialization


@app.route("/redirect")
def go():
    return redirect(request.args.get("url", "/"))               # open redirect


@app.route("/admin")
def admin():
    if request.args.get("password") == ADMIN_PASSWORD:          # password in URL, no rate limit
        return "Admin panel"
    return "Forbidden", 403


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", debug=True)                         # debug + exposed on all interfaces
