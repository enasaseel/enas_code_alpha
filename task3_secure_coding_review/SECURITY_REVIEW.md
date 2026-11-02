# Secure Coding Review Report

**Target:** `vulnerable_app.py` – a small Flask + SQLite web app (registration, login, profile, search, ping, file reader, etc.)
**Language / framework:** Python 3 / Flask
**Methods:** (1) automated static analysis with **Bandit**, (2) manual line-by-line code review against the **OWASP Top 10**
**Remediated version:** `secure_app.py`

> The target app was written for this exercise with deliberate flaws. Never deploy it.

## 1. Summary

| Method | Findings |
|---|---|
| Bandit (static analysis) | **12 issues** – 4 High, 4 Medium, 4 Low (`bandit_vulnerable.txt`) |
| Manual review | **16 distinct vulnerabilities** (includes 5 that Bandit cannot detect) |
| Bandit on `secure_app.py` | 3 Low (all are informational notes about calling `ping` via `subprocess`, which is validated and run without a shell) |

**Key lesson:** static analysers are great for dangerous *functions* (`md5`, `shell=True`, `pickle`, `debug=True`) but cannot understand *logic* flaws such as missing authorization, XSS, path traversal and open redirects. Both methods are needed.

## 2. Findings

| # | Vulnerability | Severity | Location | CWE / OWASP | Found by |
|---|---|---|---|---|---|
| 1 | SQL injection in registration | **High** | `/register` | CWE-89 / A03 Injection | Bandit B608 + manual |
| 2 | SQL injection in login (auth bypass: `' OR '1'='1' --`) | **Critical** | `/login` | CWE-89 / A03 | Bandit B608 + manual |
| 3 | OS command injection (`shell=True`, user input concatenated) | **Critical** | `/ping` | CWE-78 / A03 | Bandit B602 + manual |
| 4 | Insecure deserialization with `pickle.loads` (remote code execution) | **Critical** | `/load` | CWE-502 / A08 | Bandit B301/B403 + manual |
| 5 | Flask `debug=True` (Werkzeug debugger = remote code execution) | **High** | `app.run` | CWE-94 / A05 Misconfiguration | Bandit B201 |
| 6 | Weak password hashing: unsalted MD5 | **High** | `/register`, `/login` | CWE-327 / A02 Crypto failures | Bandit B324 |
| 7 | Hardcoded secret key and admin password | **High** | top of file | CWE-259, CWE-798 / A07 | Bandit B105 |
| 8 | Missing access control: any visitor can read any profile (IDOR) | **High** | `/profile/<id>` | CWE-639, CWE-862 / A01 Broken Access Control | Manual |
| 9 | Path traversal (`?file=../../etc/passwd`) | **High** | `/read` | CWE-22 / A01 | Manual |
| 10 | Forgeable authentication cookie (`user=<username>`, no signature, no flags) | **High** | `/login` | CWE-565, CWE-1004 / A07 | Manual |
| 11 | Reflected XSS | Medium | `/search`, `/login` | CWE-79 / A03 | Manual |
| 12 | Binding to all interfaces (`0.0.0.0`) | Medium | `app.run` | CWE-605 / A05 | Bandit B104 |
| 13 | Open redirect | Medium | `/redirect` | CWE-601 / A01 | Manual |
| 14 | Admin password sent in the URL query string, no rate limiting (leaks in logs/history, brute-forceable) | Medium | `/admin` | CWE-598, CWE-307 / A07 | Manual |
| 15 | No input validation / password policy | Medium | `/register` | CWE-20 / A04 Insecure design | Manual |
| 16 | No security headers (CSP, HSTS, X-Frame-Options, nosniff) | Low | global | CWE-693 / A05 | Manual |

## 3. Details and remediation for the main issues

### 1–2. SQL injection
```python
# VULNERABLE
db.execute("SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'")
# Input  admin' --   turns the query into:  ... WHERE username='admin' --' AND password='...'
```
```python
# FIXED – parameterized query: data can never become SQL
db.execute("SELECT id, password FROM users WHERE username=?", (username,))
```
Also: validate input with an allow-list regex and use a least-privilege DB account.

### 3. Command injection
```python
# VULNERABLE – ?host=8.8.8.8;cat /etc/passwd runs two commands
subprocess.check_output("ping -c 1 " + host, shell=True)
```
```python
# FIXED – validate as an IP, pass an argument list, no shell, timeout
host = str(ipaddress.ip_address(request.args["host"]))
subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
```

### 4. Insecure deserialization
`pickle.loads()` on user data lets an attacker execute arbitrary code during loading.
**Fix:** use a data-only format (`json.loads`) and never unpickle untrusted data.

### 5 & 12. Debug mode and exposure
`debug=True` exposes an interactive console; `0.0.0.0` exposes it to the whole network.
**Fix:** `debug=False`, bind to `127.0.0.1`, and run behind gunicorn/nginx with HTTPS in production.

### 6. Weak password storage
MD5 is fast and unsalted → rainbow tables and GPU cracking recover passwords in seconds.
**Fix:** `generate_password_hash()` / `check_password_hash()` (salted scrypt/PBKDF2). Argon2 or bcrypt are also good choices.

### 7. Hardcoded secrets
Anyone with repo access can forge session cookies and log in as admin.
**Fix:** load from environment variables / a secrets manager; rotate any secret that was ever committed.

### 8. IDOR / broken access control
`/profile/1`, `/profile/2`, … leak every user's data.
**Fix:** require login and check `session["user_id"] == user_id` (deny by default).

### 9. Path traversal
`os.path.join("files", "../../etc/passwd")` escapes the folder.
**Fix:** resolve the path and verify it is inside the allowed directory:
```python
target = (FILES_DIR / name).resolve()
if FILES_DIR not in target.parents: abort(404)
```

### 10. Forgeable cookie
Setting `user=alice` in the browser is enough to become alice.
**Fix:** use Flask's signed `session`, with `HttpOnly`, `Secure`, `SameSite` flags.

### 11. Reflected XSS
`/search?q=<script>…</script>` runs JavaScript in the victim's browser.
**Fix:** escape output (`markupsafe.escape` or Jinja2 auto-escaping templates) and add a Content-Security-Policy.

### 13. Open redirect
`/redirect?url=https://evil.example` is useful for phishing from a trusted domain.
**Fix:** allow-list of destinations or relative paths only.

### 14–16. Other hardening
Send credentials in POST bodies, add rate limiting (e.g. Flask-Limiter) and account lockout, enforce a password policy (12+ chars), set security headers.

## 4. Secure coding best practices (checklist)

- Never trust input: validate on the server with allow-lists, encode on output.
- Use parameterized queries / an ORM for all database access.
- Avoid `eval`, `exec`, `pickle`, `shell=True` on anything influenced by users.
- Hash passwords with a slow, salted algorithm; never store them in plaintext or MD5/SHA-1.
- Keep secrets out of source control; use env vars or a vault.
- Enforce authentication **and** authorization on every route (deny by default).
- Use HTTPS, secure cookie flags and security headers.
- Disable debug features and return generic error messages in production.
- Keep dependencies updated and scan them (`pip-audit`, `safety`).
- Run static analysis (Bandit, Semgrep) in CI and do peer code review.
- Log security events without logging secrets.

## 5. How to reproduce

```bash
pip install -r requirements.txt
bandit -r vulnerable_app.py          # 12 findings
bandit -r secure_app.py              # only 3 Low informational notes
```

## 6. Conclusion
The original app had critical flaws leading to authentication bypass, data theft and remote code execution. After remediation every Medium/High issue found by Bandit is gone and the logic-level flaws (IDOR, XSS, traversal, redirect, cookies) are fixed through validation, authorization checks and output escaping. Security should be built in from the start, using automated tools **and** manual review.
