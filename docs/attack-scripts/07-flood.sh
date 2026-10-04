#!/usr/bin/env bash
# Brute force and flooding against a running API. Requires curl. Watch the status codes and the Retry-After header.
API=${API:-https://localhost:5443}; C="curl -sk"

echo "== 1. password guessing against alice: 30 attempts in a row (want: a few 401, then 429 with Retry-After)"
for i in $(seq 1 30); do
  $C -o /dev/null -w '%{http_code} ' -X POST -H 'Content-Type: application/json' -d "{\"username\":\"alice\",\"password\":\"guess$i\"}" $API/api/auth/login
done; echo

echo "== 2. the same guessing, but rotating usernames to dodge a per-account limit (still 429: the limit is per client)"
for i in $(seq 1 30); do
  $C -o /dev/null -w '%{http_code} ' -X POST -H 'Content-Type: application/json' -d "{\"username\":\"victim$i\",\"password\":\"guess\"}" $API/api/auth/login
done; echo

echo "(waiting ${WAIT:-61}s so the previous requests leave the window)"; sleep ${WAIT:-61}
echo "== 3. pretending to be many clients with X-Forwarded-For (want: no extra allowance)"
for i in $(seq 1 60); do $C -o /dev/null -w '%{http_code} ' -H "X-Forwarded-For: 203.0.113.$i" $API/api/blogs; done; echo

echo "(section 3: with an anonymous limit of N you should see about N non-429 codes, then 429s - not 60 fresh allowances)"
echo "== 4. what a rejected request looks like"
$C -i $API/api/blogs | head -12
echo "(in Development the limits are relaxed on purpose; run with ASPNETCORE_ENVIRONMENT=Production or set RateLimiting__Anonymous=5 to see 429 quickly)"
