#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
common.py — shared engine for the Web App Pentesting CTF
========================================================
Provides, for every challenge:
  - a shared English dark theme + page() renderer
  - a central scoreboard (shared sqlite DB across all challenge processes)
  - a Hints panel (progressive, button-revealed)
  - a flag-submission box that awards points once per challenge
  - the CHALLENGES registry used by the scoreboard/index page

Standard library only. All servers bind to 127.0.0.1 only.
"""

import os
import sqlite3
import html
import http.server
import urllib.parse

# --------------------------------------------------------------------------
# Scoreboard DB (shared file so every challenge process writes to one board)
# --------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scoreboard.db")


def _db():
    con = sqlite3.connect(DB_PATH, timeout=5)
    con.execute("CREATE TABLE IF NOT EXISTS solves "
                "(cid TEXT PRIMARY KEY, points INTEGER, solved_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    con.execute("CREATE TABLE IF NOT EXISTS hints_used (cid TEXT PRIMARY KEY, n INTEGER)")
    return con


def mark_solved(cid, points):
    con = _db()
    con.execute("INSERT OR IGNORE INTO solves(cid, points) VALUES(?,?)", (cid, points))
    con.commit()
    con.close()


def is_solved(cid):
    con = _db()
    row = con.execute("SELECT 1 FROM solves WHERE cid=?", (cid,)).fetchone()
    con.close()
    return row is not None


def total_score():
    con = _db()
    row = con.execute("SELECT COALESCE(SUM(points),0) FROM solves").fetchone()
    con.close()
    return row[0]


def solved_ids():
    con = _db()
    rows = con.execute("SELECT cid FROM solves").fetchall()
    con.close()
    return {r[0] for r in rows}


# --------------------------------------------------------------------------
# CHALLENGE REGISTRY
# id | title | type | difficulty | points | port | flag | hints[]
# NOTE: only 01_idor_easy is implemented as the reference build.
#       Claude Code fills in the rest following the same pattern (see SPEC).
# --------------------------------------------------------------------------
CHALLENGES = [
    # ---- Broken Access Control / IDOR ----
    {"id": "idor_easy", "title": "IDOR — Change the ID", "type": "Broken Access Control",
     "owasp": "A01:2021 Broken Access Control",
     "difficulty": "Easy", "points": 100, "port": 8001,
     "flag": "FLAG{idor_h0rizontal_pr1v_esc}",
     "scenario": ("You've been hired to test <b>QuickBank</b>, a small online bank, and given one ordinary "
                  "customer login (user 101). The developers insist every customer can only ever see their "
                  "own dashboard. When a page picks which record to show using a number you can see and "
                  "change, always ask the key question: <i>does the server check that the record is actually "
                  "yours?</i><br><b>Your objective:</b> read another customer's private account and recover the flag."),
     "hints": ["Your account page puts your user id in the URL.",
               "The server never checks that the id belongs to you.",
               "Logged in as 101? Try /account?id=102."]},
    {"id": "idor_hard", "title": "IDOR — Admin Panel (forced browsing + role)", "type": "Broken Access Control",
     "owasp": "A01:2021 Broken Access Control",
     "difficulty": "Hard", "points": 250, "port": 8002,
     "flag": "FLAG{broken_access_vertical_esc}",
     "scenario": ("Same bank, bigger prize. Customers use the normal dashboard, but staff have an admin "
                  "console <i>somewhere</i>. It isn't in your menu — yet 'hidden' is not the same as "
                  "'protected'. Between forgotten links and a server that trusts the <i>browser</i> to declare "
                  "who is an admin, you should be able to walk right in.<br><b>Your objective:</b> discover the "
                  "staff-only area and escalate from 'user' to 'admin' to grab the flag."),
     "hints": ["Content discovery: not every path is linked in the menu.",
               "Inspect your session cookie / a hidden parameter — what marks you as a normal user?",
               "Find /admin and present yourself as role=admin."]},

    # ---- SQL Injection ----
    {"id": "sqli_easy", "title": "SQLi — Login Bypass", "type": "SQL Injection",
     "owasp": "A03:2021 Injection",
     "difficulty": "Easy", "points": 100, "port": 8003,
     "flag": "FLAG{sql1_auth_bypass_comment}",
     "scenario": ("A login form is the front door of every app. This one builds its database query by gluing "
                  "your input straight into a SQL string — so your input isn't only <i>data</i>, it can become "
                  "part of the <i>command</i>. The classic question: what happens when your username contains a "
                  "quote?<br><b>Your objective:</b> log in as the administrator without knowing the password."),
     "hints": ["The login query is built by string concatenation.",
               "A single quote in the username breaks out of the string.",
               "Try  admin' --  or  ' OR '1'='1' --  in the username field."]},
    {"id": "sqli_hard", "title": "SQLi — UNION Data Extraction", "type": "SQL Injection",
     "owasp": "A03:2021 Injection",
     "difficulty": "Hard", "points": 250, "port": 8004,
     "flag": "FLAG{un1on_based_data_dump}",
     "scenario": ("You're testing a product-search page. Behind it, a query pulls rows from the database and "
                  "prints them on the page. If you can bolt your <i>own</i> SELECT onto theirs, the page will "
                  "happily print whatever you ask for — including a table it was never meant to show. (This is "
                  "exactly the credit-card extraction technique from the Mutillidae lab.)<br><b>Your objective:</b> "
                  "use a UNION query to dump the hidden <code>secrets</code> table and read the flag."),
     "hints": ["The search box reflects rows from a query into the page.",
               "Match the column count first: ' ORDER BY N -- until it breaks.",
               "' UNION SELECT col1, col2 FROM secrets --  (like the credit_cards lab)."]},

    # ---- Cross-Site Scripting ----
    {"id": "xss_easy", "title": "XSS — Reflected", "type": "Cross-Site Scripting",
     "owasp": "A03:2021 Injection (XSS)",
     "difficulty": "Easy", "points": 100, "port": 8005,
     "flag": "FLAG{r3flected_xss_proven}",
     "scenario": ("This site has a search box that echoes your term back onto the page. If it drops your text "
                  "in without encoding it, your text stops being text and becomes <i>code the browser runs</i>. "
                  "The 'hello world' of this bug is making the page run a script you supplied.<br>"
                  "<b>Your objective:</b> get your JavaScript to execute and trigger <code>solve()</code> to reveal the flag."),
     "hints": ["The search term is echoed into the page with no encoding.",
               "Prove script execution — the 'hello world' of XSS.",
               "?q=<script>solve()</script>  (the page exposes a solve() helper)."]},
    {"id": "xss_hard", "title": "XSS — Stored + Filter Bypass (steal admin cookie)", "type": "Cross-Site Scripting",
     "owasp": "A03:2021 Injection (Stored XSS)",
     "difficulty": "Hard", "points": 250, "port": 8006,
     "flag": "FLAG{st0red_xss_filter_bypass}",
     "scenario": ("A guestbook stores every visitor's comment and shows it to everyone who opens the page "
                  "later — including an <b>admin</b> who reviews new comments. Store a script in a comment and "
                  "it runs in <i>the admin's</i> browser, with the admin's session. The catch: the word "
                  "<code>script</code> is blocked — but blocking a keyword is not a defense (Ch7). Events like "
                  "<code>onerror</code> and <code>onload</code> run code too.<br><b>Your objective:</b> store a "
                  "payload that survives the filter, fires in the admin's browser, and steals the cookie holding the flag."),
     "hints": ["Comments are stored and shown to everyone, including an admin bot.",
               "The word 'script' is blacklisted — blacklists fail (Ch7).",
               "Use an event handler: <img src=x onerror=...> or <svg onload=...> to exfiltrate the admin cookie."]},

    # ---- Path Traversal / LFI ----
    {"id": "lfi_easy", "title": "Path Traversal — Read a File", "type": "Path Traversal / LFI",
     "owasp": "A01:2021 Broken Access Control / A05 Misconfiguration",
     "difficulty": "Easy", "points": 100, "port": 8007,
     "flag": "FLAG{path_traversal_dotdot}",
     "scenario": ("A document portal lets you download files by name: <code>?file=report.txt</code>, reading "
                  "straight from a folder on the server. But if it never checks that the name stays <i>inside</i> "
                  "that folder, then <code>../</code> lets you climb out and read anything the server can.<br>"
                  "<b>Your objective:</b> escape the downloads folder and read the secret flag file elsewhere on disk."),
     "hints": ["The viewer reads files from a folder by name in the URL.",
               "There is no check that the path stays inside that folder.",
               "?file=../../secret/flag.txt"]},
    {"id": "lfi_hard", "title": "LFI — Traversal with Filter Bypass", "type": "Path Traversal / LFI",
     "owasp": "A01:2021 Broken Access Control / A05 Misconfiguration",
     "difficulty": "Hard", "points": 250, "port": 8008,
     "flag": "FLAG{lfi_encoded_traversal_bypass}",
     "scenario": ("Same portal, now with a 'fix': the developer strips <code>../</code> from your input. But "
                  "they strip it only <i>once</i>, and they forgot about encoding. Nested sequences that "
                  "<i>become</i> <code>../</code> after stripping, or URL-encoded slashes, sail right past "
                  "(Ch7 evasion).<br><b>Your objective:</b> defeat the naive filter and reach the flag file anyway."),
     "hints": ["Plain ../ is stripped by a naive filter.",
               "The filter only removes the literal string once (Ch7 evasion).",
               "Try URL-encoding (..%2f) or nesting (....//) to rebuild the traversal."]},

    # ---- File Upload ----
    {"id": "upload_easy", "title": "File Upload — Unrestricted", "type": "Insecure File Upload",
     "owasp": "A05:2021 Security Misconfiguration / Insecure Design",
     "difficulty": "Easy", "points": 100, "port": 8009,
     "flag": "FLAG{unrestricted_upload_served}",
     "scenario": ("A profile page lets you upload an avatar — and accepts <i>any</i> file, then serves it back "
                  "from the site's own address. A file served from the site runs <i>as</i> the site: upload a "
                  "page with a script and it executes in the app's origin. (This is the safe cousin of the DVWA "
                  "shell-upload lab.)<br><b>Your objective:</b> upload a file that runs your code and reveals the flag."),
     "hints": ["The avatar uploader accepts any file type.",
               "Uploaded files are served back and rendered by type.",
               "Upload an .html/.svg that calls solve() — it runs in the app's origin."]},
    {"id": "upload_hard", "title": "File Upload — Bypass the Extension Filter", "type": "Insecure File Upload",
     "owasp": "A05:2021 Security Misconfiguration / Insecure Design",
     "difficulty": "Hard", "points": 250, "port": 8010,
     "flag": "FLAG{upload_filter_bypass_exec}",
     "scenario": ("Now the uploader tries to be careful: it blocks dangerous extensions <i>and</i> checks the "
                  "file's declared type. But the checks are shallow — double extensions, odd capitalization, and "
                  "a spoofed <code>Content-Type</code> all slip through (Ch7).<br><b>Your objective:</b> smuggle "
                  "an executable file past the filter and trigger it to get the flag."),
     "hints": ["The uploader blocks dangerous extensions and checks Content-Type.",
               "The checks are weak: double extensions / case / content-type spoofing (Ch7).",
               "Smuggle an executable-rendered file past the filter so the server 'runs' it."]},
]

CHALLENGE_BY_ID = {c["id"]: c for c in CHALLENGES}


# --------------------------------------------------------------------------
# Theme + page renderer (English, LTR)
# --------------------------------------------------------------------------
THEME = """
  :root { --bg:#0b1220; --card:#131c2e; --line:#273349; --fg:#e6edf6;
          --muted:#8aa0bd; --accent:#4f8cff; --accent2:#2563eb;
          --ok:#22c55e; --okbg:#052e16; --warn:#fbbf24; --bad:#f87171; }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,'Segoe UI',Roboto,sans-serif; background:var(--bg);
         color:var(--fg); margin:0; padding:32px; line-height:1.55; }
  .wrap { max-width:640px; margin:24px auto; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:16px;
          padding:28px; box-shadow:0 12px 40px rgba(0,0,0,.45); margin-bottom:20px; }
  h1,h2 { margin-top:0; } a { color:var(--accent); }
  .meta { display:flex; gap:8px; flex-wrap:wrap; margin:4px 0 18px; }
  .tag { font-size:12px; padding:3px 10px; border-radius:999px; border:1px solid var(--line);
         color:var(--muted); background:#0e1626; }
  .tag.easy { color:#86efac; border-color:#166534; }
  .tag.hard { color:#fca5a5; border-color:#7f1d1d; }
  .tag.pts  { color:var(--warn); border-color:#854d0e; }
  input,button,textarea { font-size:15px; }
  input,textarea { width:100%; padding:11px; margin:6px 0 14px; border-radius:10px;
          border:1px solid var(--line); background:#0b1424; color:var(--fg); }
  button { background:var(--accent2); color:#fff; border:0; padding:11px 18px;
           border-radius:10px; cursor:pointer; } button:hover { background:#1d4ed8; }
  .row { display:flex; justify-content:space-between; padding:9px 0; border-bottom:1px solid var(--line); }
  .flag { background:var(--okbg); border:1px solid var(--ok); color:#4ade80; padding:13px;
          border-radius:10px; margin-top:14px; word-break:break-all; font-family:monospace; }
  .hint-box { background:#0e1626; border:1px solid var(--line); border-radius:10px; padding:4px 14px; margin-top:14px; }
  .hint-box summary { cursor:pointer; color:var(--warn); padding:10px 0; font-weight:600; }
  .hint-box ol { color:var(--muted); font-size:14px; }
  .scenario { background:#0e1a2e; border:1px solid #1e3a5f; border-left:4px solid var(--accent);
              border-radius:10px; padding:14px 16px; margin:4px 0 18px; font-size:14px; color:#cdddf2; }
  .scenario b.lbl { display:block; color:var(--accent); margin-bottom:6px;
              text-transform:uppercase; font-size:12px; letter-spacing:.5px; }
  .tag.owasp { color:#c4b5fd; border-color:#5b21b6; background:#1e1433; }
  .note { color:var(--muted); font-size:13px; }
  code { background:#0b1424; padding:2px 6px; border-radius:6px; color:var(--warn); }
  .ok { color:var(--ok); } .bad { color:var(--bad); } .warn { color:var(--warn); }
  .navbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; }
  .navbar a { font-size:13px; }
"""


def render(inner_html, title="CTF", challenge=None, result=None):
    """Wrap challenge content with header, hints panel, and flag-submit box."""
    header = ""
    hints_html = ""
    submit_html = ""
    if challenge:
        c = challenge
        dcls = "easy" if c["difficulty"] == "Easy" else "hard"
        solved = is_solved(c["id"])
        solved_badge = "<span class='tag' style='color:#4ade80;border-color:#166534'>SOLVED ✓</span>" if solved else ""
        header = f"""
        <div class="navbar">
          <a href="http://127.0.0.1:8000/">&larr; Scoreboard</a>
          <span class="note">Web App Pentesting CTF</span>
        </div>
        <h1>{html.escape(c['title'])}</h1>
        <div class="meta">
          <span class="tag owasp">{html.escape(c.get('owasp', c['type']))}</span>
          <span class="tag {dcls}">{c['difficulty']}</span>
          <span class="tag pts">{c['points']} pts</span>
          {solved_badge}
        </div>
        <div class="scenario">
          <b class="lbl">📖 Scenario / Briefing</b>
          {c.get('scenario', '')}
        </div>"""

        hints_items = "".join(f"<li>{html.escape(h)}</li>" for h in c["hints"])
        hints_html = f"""
        <details class="hint-box">
          <summary>💡 Hints (click to reveal)</summary>
          <ol>{hints_items}</ol>
        </details>"""

        res = ""
        if result == "correct":
            res = "<p class='ok'>✅ Correct flag! Points awarded.</p>"
        elif result == "wrong":
            res = "<p class='bad'>❌ Wrong flag. Keep trying.</p>"
        submit_html = f"""
        <div class="card">
          <h2>Submit flag</h2>
          {res}
          <form method="POST" action="/submit">
            <input name="flag" placeholder="FLAG{{...}}" autocomplete="off">
            <button type="submit">Submit</button>
          </form>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><style>{THEME}</style></head>
<body><div class="wrap">
  <div class="card">
    {header}
    {inner_html}
    {hints_html}
  </div>
  {submit_html}
</div></body></html>"""


# --------------------------------------------------------------------------
# Base handler: gives every challenge the /submit flag endpoint for free.
# A challenge subclasses this and implements do_GET (and extra POSTs).
# --------------------------------------------------------------------------
class CTFHandler(http.server.BaseHTTPRequestHandler):
    CHALLENGE_ID = None  # set by each challenge

    @property
    def challenge(self):
        return CHALLENGE_BY_ID.get(self.CHALLENGE_ID)

    def cookies(self):
        jar = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                jar[k] = v
        return jar

    def send_html(self, body, status=200, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def redirect(self, location, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", location)
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()

    def handle_flag_submit(self):
        """Shared POST /submit — call from each challenge's do_POST."""
        length = int(self.headers.get("Content-Length", 0))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        submitted = data.get("flag", [""])[0].strip()
        c = self.challenge
        if c and submitted == c["flag"]:
            mark_solved(c["id"], c["points"])
            self.redirect("/?result=correct")
        else:
            self.redirect("/?result=wrong")

    def log_message(self, fmt, *args):
        print(f"  [{self.CHALLENGE_ID}] {self.address_string()} {self.requestline}")


# --------------------------------------------------------------------------
# Helpers shared by challenges 02-10 (additive; the reference 01 doesn't need them)
# --------------------------------------------------------------------------
import json
import socketserver
import email.parser
import email.policy


def read_body(handler):
    length = int(handler.headers.get("Content-Length", 0) or 0)
    return handler.rfile.read(length) if length > 0 else b""


def parse_form(handler):
    """application/x-www-form-urlencoded body -> {name: value} (first value wins)."""
    data = urllib.parse.parse_qs(read_body(handler).decode("utf-8", "replace"), keep_blank_values=True)
    return {k: v[0] for k, v in data.items()}


def parse_multipart(handler):
    """multipart/form-data -> {field: {"filename", "content_type", "data"}} (stdlib only; no cgi module)."""
    ctype = handler.headers.get("Content-Type", "")
    body = read_body(handler)
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + ctype.encode("latin-1") + b"\r\n\r\n" + body)
    out = {}
    if not msg.is_multipart():
        return out
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        out[name] = {
            "filename": part.get_filename(),
            # the client-declared Content-Type of the part (attacker-controlled!)
            "content_type": part.get("Content-Type", "").split(";")[0].strip().lower(),
            "data": part.get_payload(decode=True) or b"",
        }
    return out


def send_json(handler, obj, status=200):
    raw = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def send_raw(handler, data, content_type, status=200, extra_headers=None):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    for k, v in (extra_headers or []):
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(data)


class _ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True   # a browser's idle pre-connect can't freeze the challenge


def serve(challenge, handler_cls):
    """Run a challenge on its registered port, bound to 127.0.0.1 only."""
    _db().close()
    with _ThreadingServer(("127.0.0.1", challenge["port"]), handler_cls) as httpd:
        print(f"[{challenge['id']}] http://127.0.0.1:{challenge['port']}  "
              f"({challenge['difficulty']}, {challenge['points']} pts)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
