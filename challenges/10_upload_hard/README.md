# 10 — File Upload: Bypass the Extension Filter · Hard · 250 pts

**OWASP:** A05:2021 Security Misconfiguration / A04 Insecure Design · **Course ref:** Lab5 DVWA upload (medium/high),
Ch07 Filter Evasion.

## Scenario / Briefing (shown to students in-app)
Now the uploader tries to be careful: it blocks dangerous extensions *and* checks the file's declared type. But the
checks are shallow — double extensions, odd capitalization, and a spoofed `Content-Type` all slip through (Ch7).
**Your objective:** smuggle an executable file past the filter and trigger it to get the flag.

## How the filter (mis)behaves
- **Upload check:** rejects names whose *last* extension is in a blacklist (`.html .htm .svg .xhtml .js .php …`),
  **case-sensitive**; and requires the client-sent `Content-Type` to start with `image/`.
- **File server:** like a mis-configured Apache `AddType`, a file is served as HTML/SVG if *any* of its extensions is
  `html/htm/svg/xhtml`, **case-insensitively**. The filter and the server disagree → bypass.

## Walkthrough
Payload (same as challenge 09): `<script src="/static/ctf.js"></script><script>solve()</script>`

- Upload `pwn.html` → **Blocked: dangerous file extension.**
- **Double extension** — rename to `pwn.html.png`. The browser sends `image/png`, last extension `.png` passes, but the
  server serves it as `text/html`. Open `/uploads/pwn.html.png` → flag.
- **Case + spoofed Content-Type** — `pwn.HtMl` passes the case-sensitive blacklist, but the browser sends `text/html`,
  so intercept in Burp (or use curl) and change the part's `Content-Type` to `image/png`:
  ```bash
  curl -F 'avatar=@pwn.html;filename=pwn.HtMl;type=image/png' http://127.0.0.1:8010/upload
  ```
  Open `/uploads/pwn.HtMl` → flag.

Flag: `FLAG{upload_filter_bypass_exec}`

## The bug
`upload_rejected()` — blacklist, case-sensitive, last extension only, trusts client `Content-Type`
(`# ======= VULN HERE (validation) =======`); `served_type()` — any extension can make a file active
(`# ======= VULN HERE (serving) =======`).

## The fix
Strong allow-list on the lower-cased final extension, verify magic bytes / re-encode the image, ignore the client
`Content-Type`, store under a random server-chosen name, and serve uploads as non-executable
(`application/octet-stream`, `Content-Disposition: attachment`, `nosniff`) from a separate origin.
