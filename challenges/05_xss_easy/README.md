# 05 — Cross-Site Scripting: Reflected · Easy · 100 pts

**OWASP:** A03:2021 Injection (XSS) · **Course ref:** Ch04 Intro + XSS, Lab4 reflected XSS (xss-game level 1).

## Scenario / Briefing (shown to students in-app)
This site has a search box that echoes your term back onto the page. If it drops your text in without encoding it,
your text stops being text and becomes *code the browser runs*. The "hello world" of this bug is making the page run
a script you supplied.
**Your objective:** get your JavaScript to execute and trigger `solve()` to reveal the flag.

## Walkthrough
1. Search `<b>hi</b>` → "hi" shows in **bold** → HTML is not encoded.
2. View source: the page defines a helper `solve()`.
3. Payload:
   ```
   http://127.0.0.1:8005/?q=<script>solve()</script>
   ```
   (`<img src=x onerror=solve()>` works too.) The flag appears in the green box.

Flag: `FLAG{r3flected_xss_proven}`

> Why can't I just type `solve()` in the DevTools console? `solve()` sends the page's own query string to `/solve`,
> and the server checks that `q` is executable markup that calls `solve()` — i.e. that the reflection really ran your
> script. Calling it on a page without an injected payload is rejected.

## The bug
`search_page()` writes `q` into the HTML unescaped (`# ======= VULN HERE =======`).

## The fix
Context-aware output encoding — `html.escape(q)` for HTML body context — plus a Content-Security-Policy such as
`script-src 'self'` that blocks inline scripts as defense in depth.
