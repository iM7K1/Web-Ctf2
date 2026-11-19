#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 09 — Unrestricted File Upload · Easy · 100 pts
========================================================
The avatar uploader accepts ANY file and serves it back from the app's own origin with a
Content-Type guessed from the extension. Upload an .html (or .svg) that loads the site helper
and calls solve():
    <script src="/static/ctf.js"></script><script>solve()</script>
then open /uploads/<your file>. Your page runs AS the site -> flag.

Safe analogue of the DVWA shell-upload lab: the uploaded file is never executed on the host;
"execution" is your HTML/JS running in the browser in the app's origin.

Run:  python3 app.py
"""
import os, sys, re, mimetypes, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "upload_easy"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
HERE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(HERE, "uploads")
MAX_SIZE = 512 * 1024
ACTIVE_TYPES = {"text/html", "image/svg+xml", "application/xhtml+xml"}

CTF_JS = r"""// Site helper loaded by every page. solve() proves that code is running in this origin
// from an uploaded file, and reveals the flag.
function solve() {
  fetch('/solve', {method: 'POST',
                   headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                   body: 'page=' + encodeURIComponent(location.pathname)})
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var msg = d.flag ? ('🚩 Code executed from your upload: ' + d.flag) : ('❌ ' + d.error);
      document.title = msg;
      if (document.body && document.body.namespaceURI === 'http://www.w3.org/1999/xhtml') {
        var el = document.createElement('div');
        el.id = 'ctf-flag';
        el.textContent = msg;
        el.setAttribute('style', 'font:16px monospace;background:#052e16;color:#4ade80;' +
                        'border:1px solid #22c55e;padding:12px;margin:12px;border-radius:8px');
        document.body.appendChild(el);
      } else {
        alert(msg);   // e.g. inside an SVG document
      }
    });
}
"""


def safe_name(filename):
    name = os.path.basename((filename or "").replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")
    return name[:100] or "upload.bin"


def served_type(name):
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


class Handler(common.CTFHandler):
    CHALLENGE_ID = CID

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self.profile(qs.get("result", [None])[0], qs.get("msg", [""])[0], qs.get("f", [""])[0])
            return
        if u.path == "/static/ctf.js":
            common.send_raw(self, CTF_JS.encode(), "application/javascript; charset=utf-8")
            return
        if u.path.startswith("/uploads/"):
            name = safe_name(urllib.parse.unquote(u.path[len("/uploads/"):]))
            path = os.path.join(UPLOADS, name)
            if not os.path.isfile(path):
                self.send_html(common.render("<p>404 — no such upload</p>", C["title"], self.challenge), 404)
                return
            with open(path, "rb") as f:
                data = f.read()
            # ======= VULN HERE (serving) =======
            # Uploads are served from the SAME origin with a type guessed from the extension,
            # so an .html/.svg upload is rendered as an active page that runs as the site.
            # Fix: serve as application/octet-stream + Content-Disposition: attachment +
            #      X-Content-Type-Options: nosniff, ideally from a separate cookieless domain.
            common.send_raw(self, data, served_type(name))
            # ===================================
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def do_POST(self):
        if self.path == "/submit":
            self.handle_flag_submit()
            return
        if self.path == "/upload":
            form = common.parse_multipart(self)
            item = form.get("avatar")
            if not item or not item["filename"]:
                self.redirect("/?msg=nofile")
                return
            if len(item["data"]) > MAX_SIZE:
                self.redirect("/?msg=toolarge")
                return
            # ======= VULN HERE (upload) =======
            # No allow-list of extensions, no content validation: ANY file is accepted.
            # Fix: allow only .png/.jpg/.gif, verify magic bytes, re-encode images,
            #      and store under a random server-chosen name.
            name = safe_name(item["filename"])
            # ==================================
            os.makedirs(UPLOADS, exist_ok=True)
            with open(os.path.join(UPLOADS, name), "wb") as f:
                f.write(item["data"])
            self.redirect("/?msg=ok&f=" + urllib.parse.quote(name))
            return
        if self.path == "/solve":
            self.solve()
            return
        self.send_html(common.render("<p>404</p>", C["title"], self.challenge), 404)

    def solve(self):
        page = common.parse_form(self).get("page", "")
        referer = urllib.parse.urlparse(self.headers.get("Referer", "")).path
        name = safe_name(page[len("/uploads/"):]) if page.startswith("/uploads/") else ""
        path = os.path.join(UPLOADS, name) if name else ""
        ok = (name and os.path.isfile(path) and referer == page
              and served_type(name) in ACTIVE_TYPES)
        if ok:
            with open(path, "rb") as f:
                ok = b"solve(" in f.read()
        if ok:
            common.send_json(self, {"flag": FLAG})
        else:
            common.send_json(self, {"error": "solve() must be called by a page you uploaded, "
                                             "opened from /uploads/."}, 403)

    def profile(self, result=None, msg="", fname=""):
        note = ""
        if msg == "ok" and fname:
            n = html.escape(fname)
            note = (f"<p class='ok'>Uploaded! Served at <a href='/uploads/{n}'>/uploads/{n}</a> "
                    f"as <code>{html.escape(served_type(fname))}</code>.</p>")
        elif msg == "nofile":
            note = "<p class='bad'>Choose a file first.</p>"
        elif msg == "toolarge":
            note = "<p class='bad'>File too large (max 512 KB).</p>"
        avatar = (f"<img src='/uploads/{html.escape(fname)}' alt='' "
                  f"style='width:96px;height:96px;border-radius:50%;object-fit:cover;background:#0b1424'>"
                  if msg == "ok" and fname else "<div style='font-size:64px'>👤</div>")
        body = f"""
        <script src="/static/ctf.js"></script>
        <h2>PicShare — Your profile</h2>
        {avatar}
        {note}
        <form method="POST" action="/upload" enctype="multipart/form-data">
          <label>Upload a new avatar</label>
          <input type="file" name="avatar">
          <button type="submit">Upload</button>
        </form>
        <p class="note">Every page on this site loads the helper <a href="/static/ctf.js">/static/ctf.js</a>.</p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    common.serve(C, Handler)
