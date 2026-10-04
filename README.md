# SecLab – learn .NET security by hardening an insecure app

> **Warning:** this app is intentionally insecure. Never deploy the starter.

React frontend, ASP.NET Core (.NET 10) API, SQL Server. Pages: **Profile** (avatar, contact info, friends), **Personal** (blogs you liked), **Timeline** (friends' blogs), **Experience** (all blogs).

## Prerequisites
- **.NET 10 SDK** (this repo's `global.json` requires it). If your system `dotnet` is older (e.g. 8.0), install 10 side by side without touching it:
  ```
  curl -sSL https://dot.net/v1/dotnet-install.sh -o dotnet-install.sh
  bash dotnet-install.sh --channel 10.0 --install-dir "$HOME/.dotnet"
  ```
  This works on any glibc Linux (including Arch/CachyOS) and needs no sudo. Then activate it **per terminal** before working on this repo:
  - fish: `set -x PATH $HOME/.dotnet $PATH; set -x DOTNET_ROOT $HOME/.dotnet`
  - bash/zsh: `export PATH="$HOME/.dotnet:$PATH" DOTNET_ROOT="$HOME/.dotnet"`

  Check with `dotnet --version` (should print 10.x). A new terminal goes back to your system version, so your other projects are unaffected. Don't run older-runtime apps from a terminal where this is active; `~/.dotnet` only contains .NET 10.
- **Docker** with the daemon running (`sudo systemctl start docker`; add yourself to the `docker` group to avoid sudo).
- **Node.js 20+** and npm.
- `curl` and `jq` for the attack scripts.

## Run it
```
docker compose up -d sqlserver
dotnet run --project backend/src/SecLab.Api        # http://localhost:5080
cd frontend && npm install && npm run dev          # http://localhost:5173
```
Log in as `alice` / `password123` (also bob, carol, dave, eve).

## Tutorial
Work through the steps **in order**: each step's tests assume the previous steps' fixes are in place (a step's `solutions/NN-*.patch` applies on top of all earlier patches, so you can also catch up with `patch -p1 < …`). Tests for each step are tagged: `dotnet test backend/SecLab.slnx --filter "Step=01"`. They start red on purpose and need the SQL Server container. If a step changes the schema, run `bash docs/reset-database.sh` and restart the API. **From step 15 on** the database needs secrets: `bash docs/init-secrets.sh` creates `.env`; load it in every shell that starts the API or the tests (`set -a; source .env; set +a`) and create the database with `bash docs/init-database.sh` (details in step 15). **From step 17 on** the gateway is an OIDC client with a secret: re-create the Keycloak container once (`docker compose --profile oidc rm -sf keycloak && docker compose --profile oidc up -d keycloak`, the realm is imported only once) and run `bash docs/init-bff-secret.sh`.

Start at [docs/00-overview-and-threat-model.md](docs/00-overview-and-threat-model.md). Steps are challenges: read the goal, try it yourself using the hints, check with the provided tests, and only then open the solution.

| # | Step | Status |
|---|------|--------|
| 00 | Overview & threat model | written |
| 01 | [HTTPS](docs/01-https.md) | written, solution verified |
| 02 | [Password storage & login hardening](docs/02-passwords.md) | written, solution verified |
| 03 | [OAuth2 / OpenID Connect](docs/03-oauth2-oidc.md) | written, solution verified (browser flow not click-tested) |
| 04 | [WebAuthn / passkeys (step-up)](docs/04-webauthn.md) | written, solution verified (browser ceremony not click-tested) |
| 05 | [Authorization](docs/05-authorization.md) | written, solution verified |
| 06 | [Leveled API keys](docs/06-api-keys.md) | written, solution verified |
| 07 | [Rate limiting](docs/07-rate-limiting.md) | written, solution verified |
| 08 | [API versioning](docs/08-api-versioning.md) | written, solution verified |
| 09 | [Allow-listing (CORS, hosts, admin network, uploads, SSRF)](docs/09-allow-listing.md) | written, solution verified |
| 10 | [Input validation & output encoding](docs/10-input-validation.md) | written, solution verified |
| 11 | [Error handling](docs/11-error-handling.md) | written, solution verified |
| 12 | [Logging, observability & monitoring](docs/12-logging-observability.md) | written, solution verified |
| 13 | [OWASP review: evidence matrix, headers, supply chain](docs/13-owasp-review.md) | written, solution verified |
| 14 | [API gateway (YARP)](docs/14-api-gateway.md) | written, solution verified |
| 15 | [Database & SQL security](docs/15-database-security.md) | written, solution verified |
| 16 | [Testing (unit, integration, contract) and testing your tests](docs/16-testing.md) | written, solution verified |
| 17 | [Extras: BFF and session hardening](docs/17-extras.md) | written, solution verified (browser flow not click-tested) |
| P2 | [Hosting in Azure, CI/CD with GitHub Actions](docs/part2-azure/README.md) | drafted, nothing run against Azure/GitHub |

Reference: https://learn.microsoft.com/en-us/dotnet/standard/security/
