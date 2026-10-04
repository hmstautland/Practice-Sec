#!/usr/bin/env bash
# Old versions are attack surface: they keep the bugs you already fixed elsewhere. Requires: API + Keycloak, curl, jq.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"
TOKEN=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=alice -d password=password123 | jq -r .access_token)
H="Authorization: Bearer $TOKEN"

echo "== 1. no version header at all: which contract do I get, and does the server tell me it is deprecated?"
$C -D - -o /dev/null -H "$H" $API/api/blogs | grep -iE '^(HTTP|api-|sunset|deprecation|link)'

echo "== 2. v1 dumps the whole table in one response (unbounded): number of items"
$C -H "$H" -H 'api-version: 1.0' $API/api/blogs | jq 'length'

echo "== 3. v2 is bounded (max page size 50; asking for 1000 must be refused)"
$C -o /dev/null -w '%{http_code}\n' -H "$H" -H 'api-version: 2.0' "$API/api/blogs?pageSize=1000"

echo "== 4. asking for a version that does not exist must fail, not fall back silently (400)"
$C -o /dev/null -w '%{http_code}\n' -H "$H" -H 'api-version: 9.9' $API/api/blogs

echo "== 5. two contradicting versions in one request (400)"
$C -o /dev/null -w '%{http_code}\n' -H "$H" -H 'api-version: 1.0' "$API/api/blogs?api-version=2.0"

echo "== 6. after the sunset date v1 is gone: restart the API with Api__V1SunsetDate=2000-01-01 and run step 1 again (410)"
