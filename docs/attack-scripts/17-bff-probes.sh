#!/usr/bin/env bash
# Step 17 – probing the BFF with a real login (no browser needed: curl plays the browser and fills in Keycloak's login form).
# Needs: SQL Server, Keycloak with the realm of step 17 + `bash docs/init-bff-secret.sh`, the API (127.0.0.1:5100) and the gateway.
# Start the gateway so that the IdP calls back to *it* (there is no SPA dev server in this script):
#     set -a; source .env; set +a;  Bff__PublicOrigin=https://localhost:5443 dotnet run --project backend/src/SecLab.Gateway
# Requires: curl, python3.   Optional: GW=https://localhost:5443 KC=http://localhost:8081
GW=${GW:-https://localhost:5443}; KC=${KC:-http://localhost:8081}
JAR=$(mktemp); KCJAR=$(mktemp); HDR=$(mktemp); trap 'rm -f "$JAR" "$KCJAR" "$HDR"' EXIT
code() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }

echo "== 1. is there a BFF at all?  GET /bff/user without a session (want 401; 404 = no BFF, the SPA keeps its own tokens)"
status=$(code "$GW/bff/user"); echo "   $status"
if [ "$status" != 401 ]; then
  echo "   -> no BFF yet. Today the browser holds the tokens - see what a script in the page can take:  bash docs/attack-scripts/17-spa-token-scan.sh"
  exit 1
fi

login() {   # $1 = user: the browser's part of Authorization Code + PKCE, done by hand. Leaves the session cookie in $JAR.
  : > "$JAR"; : > "$KCJAR"; : > "$HDR"
  local loc html action cb
  loc=$(curl -sk -c "$JAR" -o /dev/null -w '%{redirect_url}' "$GW/bff/login?returnUrl=/profile")
  [ -n "$loc" ] || { echo "   /bff/login did not redirect"; return 1; }
  html=$(curl -s -c "$KCJAR" -b "$KCJAR" "$loc")
  action=$(printf '%s' "$html" | python3 -c 'import sys,re,html
t=sys.stdin.read(); m=re.search(r"<form[^>]*kc-form-login[^>]*>", t, re.S); a=re.search(r"action=\"([^\"]+)\"", m.group(0)) if m else None
print(html.unescape(a.group(1)) if a else "")')
  [ -n "$action" ] || { echo "   no login form from the IdP (is the realm imported? $loc)"; return 1; }
  cb=$(curl -s -c "$KCJAR" -b "$KCJAR" -o /dev/null -w '%{redirect_url}' --data-urlencode "username=$1" --data-urlencode "password=password123" "$action")
  [ -n "$cb" ] || { echo "   the IdP did not redirect back (wrong password?)"; return 1; }
  curl -sk -b "$JAR" -c "$JAR" -D "$HDR" -o /dev/null "$cb"
}

echo "== 2. log in as carol; what does the browser end up with?"
login carol || exit 1
echo "   callback answered: $(head -1 "$HDR" | tr -d '\r')   Location: $(grep -i '^location:' "$HDR" | tr -d '\r' | cut -d' ' -f2)"
echo "   Set-Cookie headers of the last step (want: one cookie, __Host- prefix, HttpOnly, Secure, SameSite, no Domain):"
grep -i '^set-cookie:' "$HDR" | tr -d '\r' | sed -E 's/^set-cookie: ([^=]*)=[^;]*/\1=<value>/I; s/^([^=]{0,50})[^=]*=/\1...=/; s/^/     /'
echo "   cookie jar (value length only):"
awk '!/^# / && NF>=7 {sub(/^#HttpOnly_/,"HttpOnly "); print "     " $0}' "$JAR" | awk '{n=NF; v=$n; $n="<" length(v) " chars>"; print}'

echo "== 3. what can a script in the page learn? (it can call the API with the cookie, but cannot read the cookie or any token)"
echo "   /bff/user -> $(curl -sk -b "$JAR" -H 'X-CSRF: 1' "$GW/bff/user")"
echo "   mentions of 'token' anywhere in that answer: $(curl -sk -b "$JAR" "$GW/bff/user" | grep -ci token)  (want 0)"
echo "   /api/me -> $(code -b "$JAR" -H 'api-version: 2.0' "$GW/api/me")  (want 200: the gateway added the Bearer token)"

echo "== 4. CSRF: a request another site could trigger (cookie is sent, custom header is missing)"
echo "   POST like, cookie only           -> $(code -X POST -b "$JAR" -H 'api-version: 2.0' "$GW/api/blogs/1/like")   (want 403)"
echo "   POST like, forged cross-site     -> $(code -X POST -b "$JAR" -H 'X-CSRF: 1' -H 'Sec-Fetch-Site: cross-site' -H 'api-version: 2.0' "$GW/api/blogs/1/like")   (want 403)"
echo "   POST like, from our own page     -> $(code -X POST -b "$JAR" -H 'X-CSRF: 1' -H 'api-version: 2.0' "$GW/api/blogs/1/like")   (want 2xx)"
echo "   POST /bff/logout, cookie only    -> $(code -X POST -b "$JAR" "$GW/bff/logout")   (want 403: a link on another site must not log you out)"
echo "   GET /bff/logout                  -> $(code -b "$JAR" "$GW/bff/logout")   (want 404/405)"

echo "== 5. a forged / replayed cookie"
echo "   random cookie value              -> $(code -H 'Cookie: __Host-seclab-session=CfDJ8forged' "$GW/bff/user")   (want 401)"
echo "   a Bearer header next to a cookie must not win: the API sees the session's token, never 'attacker' (checked by the tests)"

echo "== 6. logout: the session must die on the SERVER, not only in the browser"
STOLEN=$(awk '!/^# / && NF>=7 && $6 ~ /__Host-seclab-session/ {print $7}' "$JAR")
out=$(curl -sk -X POST -b "$JAR" -c "$JAR" -H 'X-CSRF: 1' "$GW/bff/logout")
echo "   POST /bff/logout -> $(printf '%s' "$out" | cut -c1-200)"
end=$(printf '%s' "$out" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("endSessionUrl") or "")')
[ -n "$end" ] && echo "   IdP end-session (browser would follow it): $(curl -s -b "$KCJAR" -c "$KCJAR" -o /dev/null -w '%{http_code} -> %{redirect_url}' "$end")"
echo "   replaying the stolen cookie      -> /bff/user $(code -H "Cookie: __Host-seclab-session=$STOLEN" "$GW/bff/user"), /api/me $(code -H "Cookie: __Host-seclab-session=$STOLEN" -H 'api-version: 2.0' "$GW/api/me")   (want 401 401)"
echo "   silent SSO at the IdP afterwards -> $(curl -s -b "$KCJAR" -o /dev/null -w '%{redirect_url}' "$KC/realms/seclab/protocol/openid-connect/auth?client_id=seclab-bff&response_type=code&scope=openid&prompt=none&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=$GW/bff/callback" | grep -o 'error=[a-z_]*')   (want error=login_required: the IdP session ended too)"

echo "== 7. refresh happens on the server (start the gateway with Bff__RefreshSkew=00:04:55 to see it within seconds)"
login dave || exit 1
sleep 6
echo "   /api/me 6 s after login         -> $(code -b "$JAR" -H 'api-version: 2.0' "$GW/api/me")   (want 200; with the short skew the gateway log says 'Access token refreshed')"
echo "   /api/me again (token is fresh)  -> $(code -b "$JAR" -H 'api-version: 2.0' "$GW/api/me")"
