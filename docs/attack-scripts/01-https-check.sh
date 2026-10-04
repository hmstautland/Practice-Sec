#!/usr/bin/env bash
# Checks the HTTPS goals against a running API. Override with HTTP_URL / HTTPS_URL.
HTTP_URL=${HTTP_URL:-http://localhost:5080}
HTTPS_URL=${HTTPS_URL:-https://localhost:5443}
ok() { echo "PASS  $1"; }; bad() { echo "FAIL  $1"; }

code=$(curl -s -o /dev/null -w '%{http_code}' "$HTTP_URL/api/blogs")
[[ $code == 307 || $code == 308 ]] && ok "HTTP is redirected ($code)" || bad "HTTP answered $code instead of redirecting"

loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$HTTP_URL/api/blogs")
[[ $loc == https://* ]] && ok "redirect target is HTTPS ($loc)" || bad "redirect target is '$loc'"

code=$(curl -s -o /dev/null -w '%{http_code}' "$HTTPS_URL/api/blogs")
[[ $code == 200 ]] && ok "HTTPS endpoint answers 200 with a *trusted* cert" || bad "HTTPS endpoint answered '$code' (cert not trusted? not listening?)"

curl -sk --tls-max 1.1 -o /dev/null "$HTTPS_URL/api/blogs" && bad "TLS 1.1 was accepted" || ok "TLS 1.1 refused"
curl -sk --tlsv1.2 --tls-max 1.2 -o /dev/null "$HTTPS_URL/api/blogs" && ok "TLS 1.2 accepted" || bad "TLS 1.2 refused"
