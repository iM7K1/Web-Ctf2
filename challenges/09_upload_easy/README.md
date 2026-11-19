# 09 — File Upload: Unrestricted · Easy · 100 pts

**OWASP:** A05:2021 Security Misconfiguration / A04 Insecure Design · **Course ref:** Lab5 DVWA file upload.

## Scenario / Briefing (shown to students in-app)
A profile page lets you upload an avatar — and accepts *any* file, then serves it back from the site's own address.
A file served from the site runs *as* the site: upload a page with a script and it executes in the app's origin.
(This is the safe cousin of the DVWA shell-upload lab.)
**Your objective:** upload a file that runs your code and reveals the flag.

## Walkthrough
1. Upload any image → it is served at `/uploads/<name>`. The page tells you the Content-Type it uses.
2. View source: every page loads `/static/ctf.js`, which defines `solve()`.
3. Create `pwn.html`:
   ```html
   <script src="/static/ctf.js"></script><script>solve()</script>
   ```
   Upload it, then open `http://127.0.0.1:8009/uploads/pwn.html` → the flag is shown.
   An SVG works too: `<svg xmlns="http://www.w3.org/2000/svg"><script href="/static/ctf.js"/><script>solve()</script></svg>`

Flag: `FLAG{unrestricted_upload_served}`

> Safe analogue: in DVWA you upload a PHP web shell and the server executes it. Here nothing runs on the host —
> "execution" is your HTML/JS running in the browser *in the app's origin* (stored XSS via upload).
> `solve()` only pays out when called from a page under `/uploads/` that is served as an active type.

## The bug
`/upload` accepts any extension/content (`# ======= VULN HERE (upload) =======`) and `/uploads/` serves the file with
a type guessed from its extension, same-origin (`# ======= VULN HERE (serving) =======`).

## The fix
Allow-list `.png/.jpg/.gif`, verify magic bytes (and re-encode images), store under random names, and serve uploads as
`application/octet-stream` with `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`, ideally from a
separate cookieless domain.
