#!/usr/bin/env bash
# Horizontal and vertical privilege escalation as an ordinary user (dave: not a friend of alice). Requires Keycloak + API, curl, jq.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}
tok() { curl -s -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=$1 -d password=password123 | jq -r .access_token; }
BOB=$(tok dave); ALICE_ID=$(curl -sk -H "Authorization: Bearer $(tok alice)" $API/api/me | jq .id)
H="Authorization: Bearer $BOB"; C="curl -sk"

echo "== 1. dave reads alice's profile (want: only public fields, no email/phone/address/password)"
$C -H "$H" $API/api/users/$ALICE_ID | jq 'keys'
echo "== 2. dave edits alice's profile (want 403)"
$C -o /dev/null -w '%{http_code}\n' -X PUT -H "$H" -H 'Content-Type: application/json' -d '{"displayName":"pwned"}' $API/api/users/$ALICE_ID
echo "== 3. dave makes himself Admin through his own profile (want: role unchanged)"
BOB_ID=$($C -H "$H" $API/api/me | jq .id)
$C -o /dev/null -X PUT -H "$H" -H 'Content-Type: application/json' -d '{"displayName":"dave","role":"Admin"}' $API/api/users/$BOB_ID
$C -H "$H" $API/api/me | jq .role
echo "== 4. dave reads alice's friends and likes (want 403 403)"
for p in friends likes; do $C -o /dev/null -w '%{http_code} ' -H "$H" $API/api/users/$ALICE_ID/$p; done; echo
echo "== 5. dave lists all users / calls an admin route (want 403 403)"
$C -o /dev/null -w '%{http_code} ' -H "$H" $API/api/admin/users; $C -o /dev/null -w '%{http_code}\n' -H "$H" $API/api/debug/crash
