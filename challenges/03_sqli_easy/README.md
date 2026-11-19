# 03 — SQL Injection: Login Bypass · Easy · 100 pts

**OWASP:** A03:2021 Injection · **Course ref:** Ch05 SQL Injection (authentication bypass), Lab4.

## Scenario / Briefing (shown to students in-app)
A login form is the front door of every app. This one builds its database query by gluing your input straight into a
SQL string — so your input isn't only *data*, it can become part of the *command*. The classic question: what happens
when your username contains a quote?
**Your objective:** log in as the administrator without knowing the password.

## Walkthrough
1. Log in normally as `ahmed` / `password101` — you are a user, no flag. The page prints the query that ran.
2. Enter a single quote `'` as the username → *Database error: unrecognized token* → the input is inside the SQL.
3. Username `admin' --`, any password. The query becomes
   ```sql
   SELECT id, username, role FROM users WHERE username = 'admin' -- ' AND password = 'x'
   ```
   Everything after `--` is a comment, so the password check disappears → logged in as admin → flag.
   Alternative: `' OR '1'='1' --` (always true; the first row is the admin).

Flag: `FLAG{sql1_auth_bypass_comment}`

## The bug
`do_login()` concatenates `username` and `password` into the SQL string (`# ======= VULN HERE =======`).
Verbose database errors are also shown to the user, which helps attackers.

## The fix
Parameterized queries (prepared statements) — the driver sends data separately from the command:
```python
con.execute("SELECT id, username, role FROM users WHERE username = ? AND password = ?", (username, password))
```
Also: store password hashes (bcrypt/argon2), not plaintext, and show a generic error message.
