#!/usr/bin/env bash
# What can someone do with ONLY a stolen bearer token (XSS, malware, a leaked log line)?
# Requires: Keycloak + API running, curl, jq. Creates nothing; the destructive call is expected to be REFUSED after step 04.
API=${API:-https://localhost:5443}
KC=${KC:-http://localhost:8081}
TOKEN=$(curl -s -X POST $KC/realms/seclab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=seclab-dev-cli -d username=eve -d password=password123 | jq -r .access_token)

echo "== The attacker holds eve's access token (valid for minutes). Reading her data works by design:"
curl -sk -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" $API/api/me

echo "== ...but deleting the account with the token alone must now be refused (expect 403; 404/405 means step 04 is not done yet):"
curl -sk -o /dev/null -w '%{http_code}\n' -X DELETE -H "Authorization: Bearer $TOKEN" $API/api/me

echo "== ...and a made-up step-up token must not help either (expect 403):"
curl -sk -o /dev/null -w '%{http_code}\n' -X DELETE -H "Authorization: Bearer $TOKEN" -H 'X-StepUp: AAAA' $API/api/me
