# 07 — Path Traversal · Easy · 100 pts

**OWASP:** A01:2021 Broken Access Control / A05 Security Misconfiguration · **Course ref:** Lab4 LFI & Directory Traversal.

## Scenario / Briefing (shown to students in-app)
A document portal lets you download files by name: `?file=report.txt`, reading straight from a folder on the server.
But if it never checks that the name stays *inside* that folder, then `../` lets you climb out and read anything the
server can.
**Your objective:** escape the downloads folder and read the secret flag file elsewhere on disk.

## Walkthrough
1. Download links look like `/download?file=report.txt`.
2. Test whether `../` is honoured: `?file=../files/report.txt` still returns the report → traversal is processed.
   (`?file=../../app.py` even returns the portal's own source code.)
3. Files live in `www/files/`; climb two levels and read the secret:
   ```
   http://127.0.0.1:8007/download?file=../../secret/flag.txt
   ```

Flag: `FLAG{path_traversal_dotdot}`

(Lab safety: a guard confines reads to this challenge's folder so the bug can't read real host files like
`/etc/passwd`. That guard is not part of the challenge.)

## The bug
`download()` does `os.path.join(BASE, name)` and opens it without checking the result (`# ======= VULN HERE =======`).

## The fix
```python
real = os.path.realpath(os.path.join(BASE, name))
if not real.startswith(os.path.realpath(BASE) + os.sep):
    return 403
```
Even better: don't take paths from users at all — map an ID to a file server-side.
