#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 05 — Reflected XSS · Easy · 100 pts
=============================================
?q= is echoed into the page with no encoding. The page defines a solve() helper;
running it FROM YOUR INJECTED PAYLOAD proves script execution and reveals the flag.
  /?q=<script>solve()</script>

How "proof" works: solve() sends the current page's query string to /solve. The server
re-checks that this q really is executable markup that calls solve() (i.e. the reflection
ran it), and only then returns the flag. Nothing leaves 127.0.0.1.

Run:  python3 app.py
"""
import os, sys, re, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "xss_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]

# markup that a browser would execute when reflected raw into HTML
EXEC_RE = re.compile(r"<script[\s>]|<[a-z][^>]*\son[a-z]+\s*=|javascript:", re.I)

SOLVE_JS = """
<script>
// CTF helper: call solve() from YOUR injected script to prove execution.
function solve() {
  fetch('/solve', {method: 'POST',
                   headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                   body: 'proof=' + encodeURIComponent(location.search)})
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var show = function () {
        var el = document.getElementById('flag');
        el.textContent = d.flag ? ('\\uD83D\\uDEA9 XSS executed! ' + d.flag) : ('\\u274C ' + d.error);
        el.style.display = 'block';
      };
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', show); else show();
    });
}
</script>"""


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self.search_page(qs.get("q", [None])[0], qs.get("result", [None])[0])
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/solve":
            proof = common.parse_form(self).get("proof", "")
            q = urllib.parse.parse_qs(proof.lstrip("?"), keep_blank_values=True).get("q", [""])[0]
            if EXEC_RE.search(q) and "solve(" in q:
                common.send_json(self, {"flag": FLAG})
            else:
                common.send_json(self, {"error": "Not proven: solve() must be called by a script "
                                                 "you injected through ?q=."}, 403)
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def search_page(self, q, result=None):
        results = ""
        if q is not None:
            # ======= VULN HERE =======
            # The search term is inserted into HTML without encoding, so <tags> in it are parsed
            # and run by the browser. Fix: html.escape(q) (context-aware output encoding) + a CSP
            # such as  Content-Security-Policy: script-src 'self'  to block inline scripts.
            results = f"<p>Showing results for: <b>{q}</b></p><p class='note'>0 articles found.</p>"
            # ==========================
        val = html.escape(q or "", quote=True)
        body = f"""
        {SOLVE_JS}
        <h2>NewsHub — Search articles</h2>
        <form method="GET" action="/">
          <input name="q" value="{val}" placeholder="search..." autocomplete="off">
          <button type="submit">Search</button>
        </form>
        {results}
        <div id="flag" class="flag" style="display:none"></div>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    common.serve(C, Handler)
