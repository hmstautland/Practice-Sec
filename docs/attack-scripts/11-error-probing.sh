#!/usr/bin/env bash
# What does an attacker learn from your errors? Requires: API + Keycloak running, curl, jq.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"
TOKEN=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=alice -d password=password123 | jq -r .access_token)
H="Authorization: Bearer $TOKEN"

echo "== 1. make the server crash (alice is Admin, request comes from localhost). Want: generic body + trace id, NOT the message/stack/paths"
$C -i -H "$H" -H 'Accept: text/html' $API/api/debug/crash

echo; echo "== 2. response headers: does the server announce itself? (want: no 'server:' / 'x-powered-by:' line)"
$C -I -H "$H" $API/api/me | grep -iE '^(server|x-powered-by|x-aspnet)' || echo "(none - good)"

echo "== 3. every failure has the same shape (dave is an ordinary user)"
D=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=dave -d password=password123 | jq -r .access_token)
for path in /api/does-not-exist /api/users/2000000000 /api/admin/users; do printf '%-26s ' $path; $C -H "Authorization: Bearer $D" $API$path | jq -c '{status,title,traceId}'; done
printf '%-26s ' "no token"; $C $API/api/me | jq -c '{status,title,traceId}'
printf '%-26s ' "PATCH /api/blogs"; $C -X PATCH -H "$H" $API/api/blogs | jq -c '{status,title,traceId}'

echo "== 4. login failures: unknown user vs wrong password (want identical apart from traceId)"
for u in alice nobody-at-all; do $C -X POST -H 'Content-Type: application/json' -d "{\"username\":\"$u\",\"password\":\"wrong-password-1\"}" $API/api/auth/login | jq -c 'del(.traceId)'; done   # same status, same title, only the trace id differs
