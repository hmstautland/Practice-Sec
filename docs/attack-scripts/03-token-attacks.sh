#!/usr/bin/env bash
# Identity attacks against the API. Requires: curl, jq, python3. API on API=https://localhost:5443 (use -k for the dev cert).
API=${API:-https://localhost:5443}
C="curl -sk"

echo "== 1. Impersonate alice by choosing the header yourself (starter: works; after step 03: 401)"
$C -o /dev/null -w '%{http_code}\n' -H 'X-User-Id: 1' "$API/api/timeline"

echo "== 2. Forge an unsigned 'alg: none' token claiming to be alice (must be 401)"
b64() { python3 -c "import sys,base64;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip('='))"; }
H=$(printf '{"alg":"none","typ":"JWT"}' | b64)
P=$(printf '{"iss":"http://localhost:8081/realms/seclab","aud":"seclab-api","exp":4102444800,"preferred_username":"alice"}' | b64)
$C -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $H.$P." "$API/api/me"

echo "== 3. Tamper with a real token's payload (signature no longer matches; must be 401)"
T=$($C -X POST http://localhost:8081/realms/seclab/protocol/openid-connect/token \
      -d grant_type=password -d client_id=seclab-dev-cli -d username=bob -d password=password123 | jq -r .access_token)
if [[ -n $T && $T != null ]]; then
  HDR=${T%%.*}; REST=${T#*.}; SIG=${REST#*.}
  FORGED=$(python3 - "$T" <<'PY'
import sys,json,base64
t=sys.argv[1].split('.')
pad=lambda s:s+'='*(-len(s)%4)
p=json.loads(base64.urlsafe_b64decode(pad(t[1]))); p['preferred_username']='alice'
t[1]=base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip('=')
print('.'.join(t))
PY
)
  $C -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $FORGED" "$API/api/me"
  echo "== 4. Control: the untouched token works (200 once step 03 is done)"
  $C -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $T" "$API/api/me"
else
  echo "(Keycloak not running: docker compose --profile oidc up -d keycloak)"
fi
