#!/usr/bin/env bash
# Step 17: the gateway (the BFF) is a *confidential* OIDC client. Keycloak generated its secret when the realm was imported;
# this script reads it through the admin API and stores it in .env as Bff__ClientSecret (git-ignored), so it is never committed.
#
#   bash docs/init-bff-secret.sh             # read the current secret
#   bash docs/init-bff-secret.sh --rotate    # make Keycloak generate a new one (then restart the gateway)
#
# Needs: Keycloak running (docker compose --profile oidc up -d keycloak), .env (bash docs/init-secrets.sh), curl, jq.
# If the client does not exist, the realm was imported before step 17: Keycloak imports a realm only once, so re-create the dev container:
#   docker compose --profile oidc rm -sf keycloak && docker compose --profile oidc up -d keycloak
set -euo pipefail
cd "$(dirname "$0")/.."
KC=${KC:-http://localhost:8081}
[ -f .env ] || { echo "no .env yet: run  bash docs/init-secrets.sh  first"; exit 1; }
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

for _ in $(seq 1 60); do curl -sf "$KC/realms/seclab/.well-known/openid-configuration" >/dev/null && break; sleep 2; done
ADMIN=$(curl -sf -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin "$KC/realms/master/protocol/openid-connect/token" | jq -r .access_token)
AUTH="Authorization: Bearer $ADMIN"
ID=$(curl -sf -H "$AUTH" "$KC/admin/realms/seclab/clients?clientId=seclab-bff" | jq -r '.[0].id // empty')
[ -n "$ID" ] || { echo "client 'seclab-bff' not found - see the comment at the top of this script"; exit 1; }
[ "${1:-}" = "--rotate" ] && curl -sf -X POST -H "$AUTH" "$KC/admin/realms/seclab/clients/$ID/client-secret" >/dev/null
SECRET=$(curl -sf -H "$AUTH" "$KC/admin/realms/seclab/clients/$ID/client-secret" | jq -r .value)

umask 077
{ grep -v '^Bff__ClientSecret=' .env || true; echo "Bff__ClientSecret='$SECRET'"; } > .env.tmp && mv .env.tmp .env
echo "Bff__ClientSecret written to .env (${#SECRET} characters). Load it:  set -a; source .env; set +a"
