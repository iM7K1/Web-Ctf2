#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 02 — Broken Access Control: forced browsing + client-controlled role · Hard · 250 pts
==============================================================================================
A normal customer logs in. The staff console at /admin is NOT linked anywhere in the UI —
it is only "hidden" (and listed in robots.txt). The server then decides who is an admin
by reading a cookie the browser controls:  role=user  ->  role=admin.

Run:  python3 app.py
"""
import os, sys, secrets, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "idor_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]

USERS = {
    "ahmed": {"password": "password101", "name": "Ahmed Hassan", "balance": "500"},
    "sara":  {"password": "password103", "name": "Sara Ali",     "balance": "1200"},
}
SESSIONS = {}  # token -> username

ROBOTS = """User-agent: *
Disallow: /admin
Disallow: /backup/
"""


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def current_user(self):
        return SESSIONS.get(self.cookies().get("session"))

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        result = qs.get("result", [None])[0]
        path = u.path.rstrip("/") or "/"

        if path == "/":
            if self.current_user():
                self.dashboard(result)
            else:
                self.login_page(result=result)
            return
        if path == "/dashboard":
            self.dashboard(result)
            return
        if path == "/robots.txt":
            common.send_raw(self, ROBOTS.encode(), "text/plain; charset=utf-8")
            return
        if path == "/admin":
            self.admin_page(result)
            return
        if path == "/logout":
            SESSIONS.pop(self.cookies().get("session"), None)
            self.redirect("/", [("Set-Cookie", "session=; Path=/; Max-Age=0"),
                                ("Set-Cookie", "role=; Path=/; Max-Age=0")])
            return
        self.send_html(common.render("<h2>404 — Not Found</h2>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/login":
            data = common.parse_form(self)
            user, pw = data.get("username", ""), data.get("password", "")
            if user in USERS and USERS[user]["password"] == pw:
                tok = secrets.token_hex(16)
                SESSIONS[tok] = user
                # The role is handed to the browser in a plain, editable cookie.
                self.redirect("/dashboard", [("Set-Cookie", f"session={tok}; Path=/; HttpOnly"),
                                             ("Set-Cookie", "role=user; Path=/")])
            else:
                self.login_page(error="Invalid credentials. Use ahmed / password101.")
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    # ---- pages ----
    def login_page(self, error="", result=None):
        err = f"<p class='bad'>{html.escape(error)}</p>" if error else ""
        body = f"""
        <h2>QuickBank — Sign in</h2>
        <p class="note">Demo customer account: <code>ahmed</code> / <code>password101</code></p>
        {err}
        <form method="POST" action="/login">
          <label>Username</label><input name="username" value="ahmed" autocomplete="off">
          <label>Password</label><input name="password" type="password" value="password101">
          <button type="submit">Log in</button>
        </form>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def dashboard(self, result=None):
        me = self.current_user()
        if not me:
            self.redirect("/")
            return
        u = USERS[me]
        # Note: no link to /admin anywhere — "hidden" is the only protection.
        body = f"""
        <h2>Welcome, {html.escape(u['name'])}</h2>
        <div class="row"><span>Username</span><b>{html.escape(me)}</b></div>
        <div class="row"><span>Balance</span><b>${html.escape(u['balance'])}</b></div>
        <div class="row"><span>Role</span><b>{html.escape(self.cookies().get('role', 'user'))}</b></div>
        <p class="note">Menu: <a href="/dashboard">Dashboard</a> &nbsp;·&nbsp; <a href="/logout">Log out</a></p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))

    def admin_page(self, result=None):
        me = self.current_user()
        if not me:
            self.send_html(common.render(
                "<h2>401 — Please <a href='/'>log in</a> first.</h2>", C["title"], self.challenge), 401)
            return

        # ======= VULN HERE =======
        # Authorization is decided by a value the CLIENT controls (the "role" cookie).
        # Fix: store the role server-side with the session (SESSIONS[tok] -> {user, role})
        #      and check that, deny-by-default:  if server_role(me) != "admin": 403.
        role = self.cookies().get("role", "user")
        is_admin = role == "admin"
        # ==========================

        if not is_admin:
            body = f"""
            <h2 class="bad">403 — Staff only</h2>
            <p>This console is restricted to administrators.</p>
            <p class="note">Signed in as <b>{html.escape(me)}</b> with role
               <code>{html.escape(role)}</code>.</p>
            <p><a href="/dashboard">Back to dashboard</a></p>"""
            self.send_html(common.render(body, C["title"], self.challenge, result), 403)
            return

        body = f"""
        <h2>🛡️ QuickBank Staff Console</h2>
        <p class="warn">⚠️ Customer <b>{html.escape(me)}</b> reached the admin console by
           setting a client-side cookie — that's vertical privilege escalation.</p>
        <div class="row"><span>Customers</span><b>{len(USERS)}</b></div>
        <div class="row"><span>Vault master key</span><b>👇</b></div>
        <div class="flag">🚩 {html.escape(FLAG)}</div>
        <p><a href="/dashboard">Back to dashboard</a></p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    common.serve(C, Handler)
