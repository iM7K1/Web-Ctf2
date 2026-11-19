#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 03 — SQL Injection: Login Bypass · Easy · 100 pts
===========================================================
The login query is built by STRING CONCATENATION over a real sqlite3 database.
  username:  admin' --        (comments out the password check)
  username:  ' OR '1'='1' --  (always-true WHERE; first row is the admin)

Run:  python3 app.py
"""
import os, sys, secrets, sqlite3, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "sqli_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "app.db")


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    con.executemany("INSERT INTO users(username, password, role) VALUES (?,?,?)", [
        ("admin", secrets.token_hex(16), "admin"),   # first row -> ' OR '1'='1' lands here
        ("ahmed", "password101", "user"),
        ("sara",  "password103", "user"),
    ])
    con.commit()
    con.close()


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            self.login_page(result=qs.get("result", [None])[0])
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/login":
            data = common.parse_form(self)
            self.do_login(data.get("username", ""), data.get("password", ""))
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_login(self, username, password):
        # ======= VULN HERE =======
        # User input is glued into the SQL string, so a quote ends the string literal and
        # the rest of the input becomes SQL. Fix: parameterized query —
        #   con.execute("SELECT ... WHERE username = ? AND password = ?", (username, password))
        query = ("SELECT id, username, role FROM users "
                 "WHERE username = '" + username + "' AND password = '" + password + "'")
        # ==========================
        con = sqlite3.connect(DB)
        try:
            row = con.execute(query).fetchone()
        except sqlite3.Error as e:
            # Verbose errors are a bug too (they help attackers) — kept on purpose for learning.
            self.login_page(error=f"Database error: {e}", query=query)
            return
        finally:
            con.close()

        if not row:
            self.login_page(error="Invalid username or password.", query=query)
            return

        _id, user, role = row
        if role == "admin":
            inner = (f"<p class='ok'>✅ Logged in as <b>{html.escape(user)}</b> (role: admin) "
                     f"— without the password.</p><div class='flag'>🚩 {html.escape(FLAG)}</div>")
        else:
            inner = (f"<p>Logged in as <b>{html.escape(user)}</b> (role: {html.escape(role)}).</p>"
                     f"<p class='note'>Only the administrator account can see the flag.</p>")
        body = f"""
        <h2>Welcome back</h2>
        {inner}
        <p class="note">Query that ran:</p><pre><code>{html.escape(query)}</code></pre>
        <p><a href="/">Back to login</a></p>"""
        self.send_html(common.render(body, C["title"], self.challenge))

    def login_page(self, error="", query="", result=None):
        err = f"<p class='bad'>{html.escape(error)}</p>" if error else ""
        q = (f"<p class='note'>Query that ran:</p><pre><code>{html.escape(query)}</code></pre>"
             if query else "")
        body = f"""
        <h2>Admin Portal — Sign in</h2>
        <p class="note">Customer demo login: <code>ahmed</code> / <code>password101</code>.
           The <code>admin</code> password is unknown to you.</p>
        {err}{q}
        <form method="POST" action="/login">
          <label>Username</label><input name="username" autocomplete="off">
          <label>Password</label><input name="password" type="password">
          <button type="submit">Log in</button>
        </form>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    init_db()
    common.serve(C, Handler)
