#!/usr/bin/env bash
# Step 17: what could a script running in the page (an XSS payload, a compromised npm package) get its hands on?
# It scans the SPA sources and the PRODUCTION BUNDLE for everything that keeps or sends credentials from JavaScript.
# Exit code 0 = nothing found, 1 = findings (the starter finds a lot).  Needs node/npm; builds the SPA if there is no dist/.
cd "$(dirname "$0")/../../frontend" || exit 2
[ -d node_modules ] || npm ci >/dev/null 2>&1
[ -d dist ] || npm run build >/dev/null 2>&1 || { echo "the SPA does not build"; exit 2; }
bad=0
scan() {   # description, extended regex, paths...
  local what=$1 re=$2; shift 2
  local hits; hits=$(grep -rEno "$re" "$@" 2>/dev/null | sort | uniq -c | sort -rn | head -8)
  if [ -n "$hits" ]; then echo "FOUND  $what"; echo "$hits" | sed 's/^/         /'; bad=1; else echo "ok     $what"; fi
}

echo "== sources (src/)"
scan "browser storage (localStorage / sessionStorage / IndexedDB / document.cookie)" '(localStorage|sessionStorage|indexedDB|document\.cookie)' src
scan "token names (access_token / refresh_token / id_token)"                        '(access_token|refresh_token|id_token)' src
scan "Authorization / Bearer built in JavaScript"                                    "(Bearer |['\"]Authorization['\"])" src
scan "OIDC client library"                                                           '(oidc-client|userManager|signinRedirect)' src package.json
scan "direct calls to the identity provider or the gateway"                          '(localhost:8081|localhost:5443)' src

echo "== production bundle (dist/)"
scan "browser storage in the bundle"                  '(localStorage|sessionStorage|indexedDB)' dist
scan "token handling in the bundle"                   '(access_token|refresh_token|id_token|WebStorageStateStore|signinRedirect)' dist
scan "Bearer / Authorization in the bundle"           '(Bearer |Authorization)' dist
scan "client secret strings (a public SPA must not hold one)"'(client_secret|clientSecret)' dist src
echo
[ $bad = 0 ] && echo "RESULT: no credential can be found by script in this SPA" || echo "RESULT: scripts in the page can read credentials (see FOUND above)"
exit $bad
