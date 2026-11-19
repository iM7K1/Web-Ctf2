# 🚩 Web App Pentesting CTF

A self-hosted CTF with **10 challenges** (5 vulnerability types × Easy + Hard), plus a shared scoreboard.
Python standard library only. Every server binds to `127.0.0.1`.

> ⚠️ **Deliberately vulnerable.** For authorized practice on your own machine only. Never deploy it to a network.

| # | Challenge | OWASP | Level | Port | Pts |
|---|-----------|-------|-------|------|-----|
| 1 | IDOR — Change the ID | A01 Broken Access Control | Easy | 8001 | 100 |
| 2 | Admin Panel (forced browsing + role) | A01 Broken Access Control | Hard | 8002 | 250 |
| 3 | SQLi — Login Bypass | A03 Injection | Easy | 8003 | 100 |
| 4 | SQLi — UNION Extraction | A03 Injection | Hard | 8004 | 250 |
| 5 | XSS — Reflected | A03 Injection (XSS) | Easy | 8005 | 100 |
| 6 | XSS — Stored + Filter Bypass | A03 Injection (XSS) | Hard | 8006 | 250 |
| 7 | Path Traversal | A01 / A05 | Easy | 8007 | 100 |
| 8 | LFI — Filter Bypass | A01 / A05 | Hard | 8008 | 250 |
| 9 | File Upload — Unrestricted | A05 / A04 | Easy | 8009 | 100 |
| 10 | File Upload — Filter Bypass | A05 / A04 | Hard | 8010 | 250 |

## Run

```bash
python3 run_all.py
```

Open the scoreboard at http://127.0.0.1:8000, pick a challenge, find the `FLAG{...}`, and submit it on the
challenge page. Each page shows a scenario, an OWASP tag, and hints. Stop everything with Ctrl+C.

Requires Python 3.8+ (tested on 3.13). No packages to install.

## Layout

```
common.py      shared engine: theme, scoreboard, hints, flag submission
index.py       scoreboard (port 8000)
run_all.py     starts the scoreboard and all challenges
challenges/    one folder per challenge: app.py + README.md (walkthrough and fix)
SOLUTIONS.md   all flags and exploits (spoilers!)
solve_all.sh   instructor self-test: solves all 10 and checks 1750/1750 (resets the scoreboard)
```

> 🔑 **Spoiler warning:** `SOLUTIONS.md` and the challenge READMEs contain the answers.
