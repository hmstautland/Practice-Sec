#!/usr/bin/env bash
# Hostile input against the API. Requires: API + Keycloak running, curl, jq.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"
TOKEN=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=carol -d password=password123 | jq -r .access_token)
H="Authorization: Bearer $TOKEN"; J='Content-Type: application/json'

echo "== 1. stored XSS: publish a post with script, event handler, javascript: link and iframe, then read it back (want: only <p>/<a> left)"
BODY='<p>hello</p><script>alert(document.domain)</script><img src=x onerror=alert(1)><a href="javascript:alert(2)">click</a><iframe src="https://evil.example"></iframe>'
ID=$($C -X POST -H "$H" -H "$J" -d "$(jq -n --arg b "$BODY" '{title:"xss test",body:$b}')" $API/api/blogs | jq -r .id)
$C -H "$H" -H 'api-version: 2.0' "$API/api/blogs?pageSize=50" | jq -r --argjson id "${ID:-0}" '.items[] | select(.id==$id) | .body'

echo "== 2. markup in a title / display name (want 400)"
$C -o /dev/null -w '%{http_code} ' -X POST -H "$H" -H "$J" -d '{"title":"<img src=x onerror=alert(1)>","body":"x"}' $API/api/blogs
$C -o /dev/null -w '%{http_code}\n' -X PUT -H "$H" -H "$J" -d '{"displayName":"<script>x</script>"}' $API/api/users/$($C -H "$H" $API/api/me | jq .id)

echo "== 3. oversized and malformed input (want 400 400 415)"
$C -o /dev/null -w '%{http_code} ' -X POST -H "$H" -H "$J" -d "$(jq -n --arg b "$(head -c 20000 /dev/zero | tr '\0' a)" '{title:"t",body:$b}')" $API/api/blogs
$C -o /dev/null -w '%{http_code} ' -X POST -H "$H" -H "$J" -d '{"title": ' $API/api/blogs
$C -o /dev/null -w '%{http_code}\n' -X POST -H "$H" -H 'Content-Type: text/plain' -d 'title=x' $API/api/blogs

echo "== 4. registration abuse: homoglyph username, 10-char password, invalid e-mail (want 400 with field names, never echoing the input)"
$C -X POST -H "$J" -d '{"username":"аlice","password":"short","displayName":"x","email":"nope"}' $API/api/auth/register | jq -c '{status, errors}'

echo "== 5. references: like a post that does not exist (want 404)"
$C -o /dev/null -w '%{http_code}\n' -X POST -H "$H" $API/api/blogs/2000000000/like
echo "(SQL injection through /api/blogs/search is still open - that is step 15)"
