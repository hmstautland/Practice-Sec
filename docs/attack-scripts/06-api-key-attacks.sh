#!/usr/bin/env bash
# Attacks on the API-key mechanism. Requires: API + Keycloak running, curl, jq.
# Creates one read key for alice, then abuses it. Expected results are printed after each line.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"
TOKEN=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=alice -d password=password123 | jq -r .access_token)
NEW=$($C -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"attack-demo","level":"read"}' $API/api/keys)
KEY=$(echo "$NEW" | jq -r .apiKey); ID=$(echo "$NEW" | jq -r .id)
[[ $KEY == sl_* ]] || { echo "could not create a key - is step 06 done?"; echo "$NEW"; exit 1; }
PREFIX=$(echo $KEY | cut -d_ -f2)

echo "== 1. read key reads (200)";                       $C -o /dev/null -w '%{http_code}\n' -H "X-Api-Key: $KEY" $API/api/partner/blogs
echo "== 2. read key tries to write (403)";              $C -o /dev/null -w '%{http_code}\n' -X POST -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' -d '{"title":"x","body":"y"}' $API/api/partner/blogs
echo "== 3. read key tries to delete (403)";             $C -o /dev/null -w '%{http_code}\n' -X DELETE -H "X-Api-Key: $KEY" $API/api/partner/blogs/1
echo "== 4. right prefix, guessed secret (401)";         $C -o /dev/null -w '%{http_code}\n' -H "X-Api-Key: sl_${PREFIX}_$(printf 'a%.0s' {1..40})" $API/api/partner/blogs
echo "== 5. key in the URL instead of the header (401)"; $C -o /dev/null -w '%{http_code}\n' "$API/api/partner/blogs?api_key=$KEY"
echo "== 6. key used on a user route (401)";             $C -o /dev/null -w '%{http_code}\n' -H "X-Api-Key: $KEY" $API/api/me
echo "== 7. key used to mint a more powerful key (401)"; $C -o /dev/null -w '%{http_code}\n' -X POST -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' -d '{"name":"x","level":"admin"}' $API/api/keys
echo "== 8. ordinary user asks for an admin key (403)";  $C -o /dev/null -w '%{http_code}\n' -X POST -H "Authorization: Bearer $($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=dave -d password=password123 | jq -r .access_token)" -H 'Content-Type: application/json' -d '{"name":"x","level":"admin"}' $API/api/keys
echo "== 9. revoke, then reuse (204 then 401)";          $C -o /dev/null -w '%{http_code} ' -X DELETE -H "Authorization: Bearer $TOKEN" $API/api/keys/$ID; $C -o /dev/null -w '%{http_code}\n' -H "X-Api-Key: $KEY" $API/api/partner/blogs
echo "== 10. what does the database hold? (secret must not appear)"
docker exec seclab-sql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P 'Passw0rd!Passw0rd' -d SecLab -h -1 -W \
  -Q "SET NOCOUNT ON; SELECT TOP 3 Prefix, CONVERT(varchar(80), KeyHash, 2) AS KeyHash, Level FROM ApiKeys ORDER BY Id DESC" 2>/dev/null
