#!/usr/bin/env bash
# Security smoke test for a deployed SecLab API. Usage: smoke.sh https://host [expected-cors-origin]
# Copy to scripts/smoke.sh (the deploy workflow calls it). Read-only requests, no credentials, exit 1 on any failure.
# Not run against a real deployment by the author: adjust paths (/health, /api/v1/...) to your API.
set -u
BASE="${1:?usage: smoke.sh https://host}"
BASE="${BASE%/}"
HOST="${BASE#https://}"; HOST="${HOST%%/*}"
fail=0
check() { # name, actual, expected-regex
  if [[ "$2" =~ $3 ]]; then echo "PASS  $1"; else echo "FAIL  $1  (got: $2, wanted: $3)"; fail=1; fi
}
code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$@" 2>/dev/null || echo 000; }

[[ "$BASE" == https://* ]] || { echo "FAIL  base url must be https"; exit 1; }

check "http redirects to https or is refused" "$(code "http://$HOST/")" '^(301|302|307|308|000)$'
check "health endpoint is up"                 "$(code "$BASE/health")"  '^200$'
check "anonymous request to protected API is 401" "$(code "$BASE/api/v1/users/1")" '^401$'
check "old unversioned route is gone (step 08)"   "$(code "$BASE/api/users/1")"    '^(404|401)$'

hdrs="$(curl -sSI --max-time 15 "$BASE/health" 2>/dev/null | tr -d '\r')"
hsts="$(grep -i '^strict-transport-security:' <<<"$hdrs" | sed -E 's/.*max-age=([0-9]+).*/\1/I')"
[[ "${hsts:-0}" =~ ^[0-9]+$ && "${hsts:-0}" -ge 15552000 ]] && echo "PASS  HSTS max-age >= 180 days" || { echo "FAIL  HSTS missing or too short (${hsts:-none})"; fail=1; }
check "no server version leak"      "$(grep -ci '^\(server\|x-powered-by\):.*\(kestrel\|asp\.net\)' <<<"$hdrs")" '^0$'
check "X-Content-Type-Options set"  "$(grep -ci '^x-content-type-options: *nosniff' <<<"$hdrs")" '^1$'

# TLS floor: TLS 1.1 must fail, TLS 1.2 must work
check "TLS 1.1 is rejected" "$(code --tlsv1.1 --tls-max 1.1 "$BASE/health")" '^000$'
check "TLS 1.2 works"       "$(code --tlsv1.2 --tls-max 1.2 "$BASE/health")"  '^200$'

# No verbose errors (step 11): the deliberate crash route must be absent or generic
body="$(curl -sS --max-time 15 "$BASE/api/debug/crash" 2>/dev/null || true)"
check "no stack trace / connection string in error body" "$(grep -ciE 'stacktrace|at SecLab\.|Server=|Password=|Exception' <<<"$body")" '^0$'

# WAF: a classic injection probe must be blocked (403) or safely rejected, never 200/500
check "SQLi probe is not served" "$(code "$BASE/api/v1/blogs/search?q=%27%20OR%201%3D1--")" '^(400|401|403)$'

# CORS: a foreign origin must not be reflected
acao="$(curl -sSI --max-time 15 -H 'Origin: https://evil.example' "$BASE/health" 2>/dev/null | tr -d '\r' | grep -i '^access-control-allow-origin:' || true)"
check "foreign origin not allowed by CORS" "$(grep -ci 'evil.example\|: \*' <<<"$acao")" '^0$'

# Rate limiting (step 07): a burst should eventually see 429. Keep the burst small; WAF may answer 403/429.
seen429=0
for _ in $(seq 1 60); do c="$(code "$BASE/api/v1/blogs/search?q=a")"; [[ "$c" == 429 ]] && { seen429=1; break; }; done
[[ $seen429 == 1 ]] && echo "PASS  rate limiting engaged" || echo "WARN  no 429 within 60 requests (limit may be higher than the burst)"

# Origin lock: set ORIGIN_URL to the container app's default FQDN to assert it is not directly usable
if [[ -n "${ORIGIN_URL:-}" ]]; then
  check "origin is not reachable bypassing the edge" "$(code "${ORIGIN_URL%/}/api/v1/users/1")" '^(000|403|404)$'
fi

exit $fail
