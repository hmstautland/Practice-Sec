#!/usr/bin/env bash
# Probing the public entry point. Requires: API on 127.0.0.1:5100, gateway on https://localhost:5443, Keycloak, curl, jq, python3.
GW=${GW:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"
TOKEN=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=dave -d password=password123 | jq -r .access_token)
H="Authorization: Bearer $TOKEN"

echo "== 1. what is published? (want 404 for everything except /api/**)"
for p in / /swagger /health/live /health/ready /metrics /avatars/x.png /api2/blogs; do printf '%-18s ' $p; $C -o /dev/null -w '%{http_code}\n' -H "$H" $GW$p; done

echo "== 2. no credential at all on a protected route (want 401 from the EDGE - the API never sees it)"
$C -o /dev/null -w '%{http_code}\n' $GW/api/me

echo "== 3. methods the API does not use (want 404/405)"
for m in TRACE PATCH PROPFIND; do printf '%-10s ' $m; $C -o /dev/null -w '%{http_code}\n' -X $m -H "$H" $GW/api/blogs; done

echo "== 4. spoofing where you come from (the API must see the REAL address, so its per-IP limits and admin-network rule cannot be dodged)"
$C -o /dev/null -w 'status %{http_code}\n' -H "$H" -H 'X-Forwarded-For: 10.1.2.3' -H 'Forwarded: for=10.1.2.3' -H 'X-Real-IP: 10.1.2.3' -H 'X-Gateway-Auth: let-me-in' $GW/api/me
echo "   (check the API log/audit events: ClientIp must be ::1/127.0.0.1, never 10.1.2.3)"

echo "== 5. path tricks against the admin block (from loopback these are ALLOWED by design; from any other address they must be 404)"
for p in /api/admin/users /API/ADMIN/users '/api/%61dmin/users' '/api/x/../admin/users'; do printf '%-26s ' "$p"; $C --path-as-is -o /dev/null -w '%{http_code}\n' -H "$H" "$GW$p"; done

echo "== 6. 4 MB body (want 413 from the edge)"
head -c 4194304 /dev/zero | $C -o /dev/null -w '%{http_code}\n' -X POST -H "$H" -H 'Content-Type: application/json' --data-binary @- $GW/api/blogs

echo "== 7. flood one address (gateway limit 300/min by default; start it with Gateway__RateLimitPerMinute=20 to see 429 quickly)"
for i in $(seq 1 30); do $C -o /dev/null -w '%{http_code} ' -H "$H" $GW/api/me; done; echo

echo "== 8. bypass attempt: talk to the API directly (works on this machine only because it listens on loopback; from the network it must not be reachable)"
$C -o /dev/null -w '%{http_code}\n' -H "Host: localhost" http://127.0.0.1:5100/health/live
