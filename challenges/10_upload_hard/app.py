#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 10 — File Upload: bypass the extension/type filter · Hard · 250 pts
=============================================================================
The uploader now (a) blocks dangerous extensions with a case-SENSITIVE check on the LAST
extension only, and (b) requires the client-declared Content-Type to start with image/.
The file server then picks the type like an old Apache "AddType" setup: if ANY extension in
the name is an active type (html/htm/svg/xhtml), the file is served as that type,
case-insensitively. Bypasses (any one works):
  double extension:  shell.html.png   (Content-Type image/png)      -> served as text/html
  case:              shell.HtMl       + spoofed Content-Type image/png -> served as text/html
Then open the uploaded file; it loads /static/ctf.js and calls solve() -> flag.

Nothing is ever executed on the host; "execution" is the browser rendering your page.

Run:  python3 app.py
"""
import os, sys, re, mimetypes, urllib.parse, html
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import common

CID = "upload_hard"
C = common.CHALLENGE_BY_ID[CID]
FLAG = C["flag"]
HERE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(HERE, "uploads")
MAX_SIZE = 512 * 1024

ACTIVE = {"html": "text/html", "htm": "text/html", "xhtml": "application/xhtml+xml",
          "svg": "image/svg+xml"}
BLOCKED_EXT = (".html", ".htm", ".xhtml", ".xht", ".svg", ".shtml", ".js", ".php", ".phtml")

CTF_JS = r"""// Site helper. solve() proves that code is running in this origin from an uploaded file.
function solve() {
  fetch('/solve', {method: 'POST',
                   headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                   body: 'page=' + encodeURIComponent(location.pathname)})
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var msg = d.flag ? ('🚩 Smuggled file executed: ' + d.flag) : ('❌ ' + d.error);
      document.title = msg;
      if (document.body && document.body.namespaceURI === 'http://www.w3.org/1999/xhtml') {
        var el = document.createElement('div');
        el.id = 'ctf-flag';
        el.textContent = msg;
        el.setAttribute('style', 'font:16px monospace;background:#052e16;color:#4ade80;' +
                        'border:1px solid #22c55e;padding:12px;margin:12px;border-radius:8px');
        document.body.appendChild(el);
      } else {
        alert(msg);
      }
    });
}
"""


def safe_name(filename):
    name = os.path.basename((filename or "").replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")
    return name[:100] or "upload.bin"


# ======= VULN HERE (validation) =======
# 1) blacklist instead of allow-list, 2) case-sensitive, 3) looks at the LAST extension only,
# 4) trusts the client's Content-Type header (attacker-controlled).
# Fix: allow-list (.png/.jpg/.gif) on the lower-cased final extension, verify magic bytes /
#      re-encode the image, ignore the client Content-Type, store under a random name.
def upload_rejected(filename, content_type):
    if filename.endswith(BLOCKED_EXT):
        return "Blocked: dangerous file extension."
    if not content_type.startswith("image/"):
        return f"Blocked: Content-Type '{content_type or 'none'}' is not an image."
    return None
# ======================================


# ======= VULN HERE (serving) =======
# Mimics a mis-configured web server (Apache AddType): any extension anywhere in the name can
# make the file active, matched case-insensitively — so the filter and the server disagree.
# Fix: serve uploads as application/octet-stream + Content-Disposition: attachment + nosniff.
def served_type(name):
    for ext in name.lower().split(".")[1:]:
        if ext in ACTIVE:
            return ACTIVE[ext]
    return mimetypes.guess_type(name.lower())[0] or "application/octet-stream"
# ===================================


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
                common.send_raw(self, f.read(), served_type(name))
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
            name = safe_name(item["filename"])
            why = upload_rejected(name, item["content_type"])
            if why:
                self.redirect("/?msg=" + urllib.parse.quote("err:" + why))
                return
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
              and served_type(name) in ACTIVE.values())
        if ok:
            with open(path, "rb") as f:
                ok = b"solve(" in f.read()
        if ok:
            common.send_json(self, {"flag": FLAG})
        else:
            common.send_json(self, {"error": "solve() must be called by a page you smuggled in, "
                                             "opened from /uploads/."}, 403)

    def profile(self, result=None, msg="", fname=""):
        note = ""
        if msg == "ok" and fname:
            n = html.escape(fname)
            note = (f"<p class='ok'>Uploaded! Served at <a href='/uploads/{n}'>/uploads/{n}</a> "
                    f"as <code>{html.escape(served_type(fname))}</code>.</p>")
        elif msg.startswith("err:"):
            note = f"<p class='bad'>🛑 {html.escape(msg[4:])}</p>"
        elif msg == "nofile":
            note = "<p class='bad'>Choose a file first.</p>"
        elif msg == "toolarge":
            note = "<p class='bad'>File too large (max 512 KB).</p>"
        avatar = (f"<img src='/uploads/{html.escape(fname)}' alt='' "
                  f"style='width:96px;height:96px;border-radius:50%;object-fit:cover;background:#0b1424'>"
                  if msg == "ok" and fname else "<div style='font-size:64px'>👤</div>")
        body = f"""
        <script src="/static/ctf.js"></script>
        <h2>PicShare v2 — Your profile</h2>
        <p class="ok">🔒 Hardened uploader: dangerous extensions are blocked and only images are accepted.</p>
        {avatar}
        {note}
        <form method="POST" action="/upload" enctype="multipart/form-data">
          <label>Upload a new avatar (images only)</label>
          <input type="file" name="avatar" accept="image/*">
          <button type="submit">Upload</button>
        </form>
        <p class="note">Every page on this site loads the helper <a href="/static/ctf.js">/static/ctf.js</a>.</p>"""
        self.send_html(common.render(body, C["title"], self.challenge, result))


if __name__ == "__main__":
    common.serve(C, Handler)
