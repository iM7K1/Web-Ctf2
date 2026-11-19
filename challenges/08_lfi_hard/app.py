#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 08 — LFI / Traversal with a naive filter · Hard · 250 pts
===================================================================
Same portal, now "patched": the raw ?file= value has "../" removed ONE time, and only
THEN is it URL-decoded. Two classic bypasses (Ch7):
  nesting:   ....//....//secret/flag.txt        ("....//" minus "../" == "../")
  encoding:  ..%2f..%2fsecret%2fflag.txt        (filter sees no "../"; decode rebuilds it)

Lab safety guard: reads are confined to THIS challenge folder (not part of the challenge).

Run:  python3 app.py
"""
import os, sys, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "lfi_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "www", "files")
FLAG_FILE = os.path.join(HERE, "secret", "flag.txt")


def write_flag():
    os.makedirs(os.path.dirname(FLAG_FILE), exist_ok=True)
    with open(FLAG_FILE, "w") as f:
        f.write(f"TOP SECRET — not for the public portal\n{FLAG}\n")


def lab_guard(path):
    """LAB SAFETY ONLY (not the challenge): never read outside this challenge's folder."""
    real = os.path.realpath(path)
    return real == HERE or real.startswith(HERE + os.sep)


def raw_param(query, key):
    """Return a query parameter WITHOUT URL-decoding it (so the filter sees the raw bytes)."""
    for pair in query.split("&"):
        k, _, v = pair.partition("=")
        if k == key:
            return v
    return None


# ======= VULN HERE =======
# 1) "../" is stripped once (str.replace is not recursive over its own output), and
# 2) the check runs BEFORE URL-decoding, so %2f / %2e are never seen by the filter.
# Fix: decode fully first, normalise with os.path.realpath, then verify the result is inside
#      BASE (and reject, don't "clean", any input containing traversal).
def sanitize(raw):
    cleaned = raw.replace("../", "")        # naive, single pass, on the raw value
    cleaned = cleaned.lstrip("/")           # "no absolute paths"
    return urllib.parse.unquote_plus(cleaned)
# ==========================


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self.index(qs.get("result", [None])[0])
            return
        if u.path == "/download":
            self.download(raw_param(u.query, "file") or "")
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def download(self, raw):
        name = sanitize(raw)
        path = os.path.join(BASE, name)
        if not name or not lab_guard(path):
            common.send_raw(self, b"Not found (or outside the lab sandbox).\n", "text/plain", 404)
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            # Leaking the post-filter name is a deliberate learning aid (shows what the filter did)
            common.send_raw(self, f"File not found: {name}\n".encode(), "text/plain; charset=utf-8", 404)
            return
        common.send_raw(self, data, "text/plain; charset=utf-8")

    def index(self, result=None):
        files = sorted(os.listdir(BASE))
        links = "".join(
            f"<div class='row'><span>📄 {html.escape(f)}</span>"
            f"<a href='/download?file={urllib.parse.quote(f)}'>download</a></div>" for f in files)
        body = f"""
        <h2>Acme Docs v2 — Public downloads</h2>
        <p class="ok">🔒 Security patch applied: path traversal sequences are now removed.</p>
        {links}
        <p class="note">Files are served from the <code>files/</code> folder via
           <code>/download?file=&lt;name&gt;</code>.</p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    write_flag()
    common.serve(C, Handler)
