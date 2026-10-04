#!/usr/bin/env bash
# Generates a small "incident" against a running API so you can practise detecting it.
#   terminal 1:  dotnet run --project backend/src/SecLab.Api 2>&1 | tee /tmp/seclab.log
#   terminal 2:  bash docs/attack-scripts/12-attack-and-detect.sh
#   then:        python3 docs/attack-scripts/12-detect.py /tmp/seclab.log
# In Development the limits are relaxed on purpose; start the API with RateLimiting__Login=1000 to keep the login flood from being
# stopped at the door and see the failed-login events instead of only rate-limit rejections.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"

echo "1. credential stuffing: 12 different usernames, one password"
for u in alice bob carol dave eve mallory trudy oscar peggy victor walter zed; do
  $C -o /dev/null -X POST -H 'Content-Type: application/json' -d "{\"username\":\"$u\",\"password\":\"Winter2026!\"}" $API/api/auth/login
done
echo "2. brute force one account until it locks"
for i in $(seq 1 7); do $C -o /dev/null -X POST -H 'Content-Type: application/json' -d "{\"username\":\"carol\",\"password\":\"guess$i\"}" $API/api/auth/login; done
echo "3. an authenticated user probing admin functions"
D=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=dave -d password=password123 | jq -r .access_token)
for p in /api/admin/users /api/debug/crash; do $C -o /dev/null -H "Authorization: Bearer $D" $API$p; done
$C -o /dev/null -X PUT -H "Authorization: Bearer $D" -H 'Content-Type: application/json' -d '{"role":"Admin"}' $API/api/admin/users/1/role   # try to promote alice/himself
echo "4. API key guessing"
for i in 1 2 3 4; do $C -o /dev/null -H "X-Api-Key: sl_AAAAAAAA_$(printf 'b%.0s' {1..40})" $API/api/partner/blogs; done
echo "5. a privileged change (should be audited, not alerted)"
A=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=alice -d password=password123 | jq -r .access_token)
$C -o /dev/null -X PUT -H "Authorization: Bearer $A" -H 'Content-Type: application/json' -d '{"role":"User"}' $API/api/admin/users/2/role
echo "done - now run the detector on the log"
