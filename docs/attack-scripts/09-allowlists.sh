#!/usr/bin/env bash
# Things an allow-list should stop. Requires: API + Keycloak running, curl, jq, python3.
API=${API:-https://localhost:5443}; KC=${KC:-http://localhost:8081}; C="curl -sk"
TOKEN=$($C -X POST $KC/realms/seclab/protocol/openid-connect/token -d grant_type=password -d client_id=seclab-dev-cli -d username=alice -d password=password123 | jq -r .access_token)
H="Authorization: Bearer $TOKEN"; ME=$($C -H "$H" $API/api/me | jq .id)

echo "== 1. CORS: preflight from an attacker's website (want: NO Access-Control-Allow-Origin header)"
$C -i -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' -H 'Access-Control-Request-Headers: authorization' $API/api/blogs | grep -iE '^(HTTP|access-control)' || echo "(no CORS headers - good)"
echo "== 1b. CORS: the real frontend (want: allow-origin = https://localhost:5173, methods limited, no *)"
$C -i -X OPTIONS -H 'Origin: https://localhost:5173' -H 'Access-Control-Request-Method: DELETE' -H 'Access-Control-Request-Headers: authorization,api-version' $API/api/blogs | grep -iE '^(HTTP|access-control|vary)'

echo "== 2. Host header attack: password-reset-poisoning style (want 400)"
$C -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' $API/api/blogs

echo "== 3. upload an HTML file as an 'avatar' (want 400) and a real PNG named ../../evil.html (want 200 + random name)"
printf '<html><script>alert(document.domain)</script></html>' > /tmp/evil-avatar.png
$C -o /dev/null -w '%{http_code}\n' -H "$H" -F "file=@/tmp/evil-avatar.png;type=image/png" $API/api/users/$ME/avatar
python3 - <<'PY'
import base64
open('/tmp/real.png','wb').write(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="))
PY
$C -H "$H" -F "file=@/tmp/real.png;filename=../../evil.html;type=text/html" $API/api/users/$ME/avatar

echo "== 4. SSRF through the link-preview feature (want 400 each, and nothing fetched)"
for u in "https://169.254.169.254/latest/meta-data/" "https://localhost/api/admin/users" "http://example.com/" "https://example.com@evil.example/" "https://[::1]/" "file:///etc/passwd"; do
  printf '%-45s -> ' "$u"; $C -o /dev/null -w '%{http_code}\n' -X POST -H "$H" -H 'Content-Type: application/json' -d "{\"url\":\"$u\"}" $API/api/tools/link-preview
done
echo "   allowed host (needs outbound internet):"; $C -X POST -H "$H" -H 'Content-Type: application/json' -d '{"url":"https://example.com/"}' $API/api/tools/link-preview; echo

echo "== 5. OAuth redirect-URI allow-list at the IdP (want an error page, not a redirect to evil.example)"
$C -o /dev/null -w '%{http_code} %{redirect_url}\n' "$KC/realms/seclab/protocol/openid-connect/auth?client_id=seclab-spa&response_type=code&scope=openid&redirect_uri=https://evil.example/cb"
