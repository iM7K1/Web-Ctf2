#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 07 — Path Traversal · Easy · 100 pts
==============================================
/download?file=report.txt reads from www/files/ with no containment check.
  /download?file=../../secret/flag.txt
climbs out of www/files/ (-> www/ -> challenge folder) and reads secret/flag.txt.

Lab safety guard: reads are confined to THIS challenge folder (so the bug can't be used to
read the real host's files). That guard is not part of the challenge.

Run:  python3 app.py
"""
import os, sys, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "lfi_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "www", "files")          # the "allowed" folder
FLAG_FILE = os.path.join(HERE, "secret", "flag.txt")


def write_flag():
    os.makedirs(os.path.dirname(FLAG_FILE), exist_ok=True)
    with open(FLAG_FILE, "w") as f:
        f.write(f"TOP SECRET — not for the public portal\n{FLAG}\n")


def lab_guard(path):
    """LAB SAFETY ONLY (not the challenge): never read outside this challenge's folder."""
    real = os.path.realpath(path)
    return real == HERE or real.startswith(HERE + os.sep)


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self.index(qs.get("result", [None])[0])
            return
        if u.path == "/download":
            self.download(qs.get("file", [""])[0])
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def download(self, name):
        # ======= VULN HERE =======
        # The user-supplied name is joined onto the base folder and opened as-is; "../" walks
        # out of it. Fix:  real = os.path.realpath(os.path.join(BASE, name))
        #                  if not real.startswith(os.path.realpath(BASE) + os.sep): return 403
        path = os.path.join(BASE, name)
        # ==========================
        if not name or not lab_guard(path):
            common.send_raw(self, b"Not found (or outside the lab sandbox).\n", "text/plain", 404)
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except (IsADirectoryError, FileNotFoundError, PermissionError, OSError):
            common.send_raw(self, f"File not found: {name}\n".encode(), "text/plain; charset=utf-8", 404)
            return
        common.send_raw(self, data, "text/plain; charset=utf-8")

    def index(self, result=None):
        files = sorted(os.listdir(BASE))
        links = "".join(
            f"<div class='row'><span>📄 {html.escape(f)}</span>"
            f"<a href='/download?file={urllib.parse.quote(f)}'>download</a></div>" for f in files)
        body = f"""
        <h2>Acme Docs — Public downloads</h2>
        {links}
        <p class="note">Files are served from the <code>files/</code> folder via
           <code>/download?file=&lt;name&gt;</code>.</p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    write_flag()
    common.serve(C, Handler)
