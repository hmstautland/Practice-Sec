#!/usr/bin/env bash
# A quick external security review of a running API + the repository. Requires curl, jq; dotnet and npm on PATH.
API=${API:-https://localhost:5443}; C="curl -sk"
cd "$(dirname "$0")/../.."

echo "== 1. response headers (want: nosniff, CSP default-src 'none', X-Frame-Options, Referrer-Policy, Permissions-Policy, CORP, Cache-Control: no-store; NO Server/X-Powered-By/Set-Cookie)"
$C -i $API/api/me | sed -n '1,25p' | grep -iE '^(HTTP|x-content|content-security|x-frame|referrer|permissions|cross-origin|cache-control|server|x-powered|set-cookie)' 

echo "== 2. is anything exposed that should not be? (swagger, actuator-style, debug, source maps)"
for p in /swagger /swagger/index.html /openapi/v1.json /actuator /env /.env /appsettings.json /api/debug/crash /metrics; do printf '%-26s ' $p; $C -o /dev/null -w '%{http_code}\n' $API$p; done

echo "== 3. dependencies with known vulnerabilities"
dotnet list backend/SecLab.slnx package --vulnerable --include-transitive 2>&1 | grep -E "has no vulnerable|Severity|>" | head
(cd frontend && npm audit --omit=dev 2>&1 | tail -2)

echo "== 4. outdated packages (informational - patch releases are security work too)"
dotnet list backend/SecLab.slnx package --outdated 2>&1 | grep -E ">" | head -8

echo "== 5. secrets that should not be in the repository"
grep -rInE "(password|passwd|secret|apikey|api_key)\s*[:=]\s*['\"][^'\"$]{6,}" --include=*.json --include=*.yml --include=*.yaml --include=*.cs --include=*.ts --include=*.env . 2>/dev/null \
  | grep -vE "node_modules|/bin/|/obj/|/tests/|docs/|\.lock|package-lock|password123|Passw0rd" | head -10 || true
echo "(the SA password in docker-compose.yml/appsettings.json is a known starter weakness - step 15)"

echo "== 6. the mapping matrix"
grep -cE '^\| (A[0-9]{2}|API[0-9]+) ' docs/owasp-matrix.md | xargs echo "rows:"; grep -c '| ? |' docs/owasp-matrix.md | xargs echo "unfilled cells:"
