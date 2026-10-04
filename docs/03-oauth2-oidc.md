# 03 – OAuth2 and OpenID Connect

> Prerequisites: steps 01–02 done (or apply `solutions/01-https.patch` and `02-passwords.patch`). Time: 2–3 hours.
> Infrastructure is provided: Keycloak with a ready-made realm (`infra/keycloak/seclab-realm.json`) – **you** write the API and SPA side.

## Goal
Stop trusting a header the client makes up. Users authenticate at an **identity provider (IdP)**; the SPA obtains an **access token** with the Authorization Code flow + PKCE; the API validates it on every request.

Acceptance criteria:

1. Start the IdP: `docker compose --profile oidc up -d keycloak` (admin console `http://localhost:8081`, admin/admin). Realm `seclab` has users alice…eve (`password123`), the public SPA client `seclab-spa`, and access tokens that carry `aud = seclab-api`.
2. The API is a **resource server** using the **standard JwtBearer handler with its default scheme**. It reads its settings from configuration keys **`Auth:Authority`** and **`Auth:Audience`**. Development points at Keycloak (plain HTTP is acceptable *only* there); any other environment must require an HTTPS authority.
3. **Every `/api` route requires a valid access token**, except the legacy local `/api/auth/login` and `/api/auth/register` (kept public for now so step 02 keeps passing). No token, or the old `X-User-Id` header alone → `401`.
4. A token is accepted only if: the signature verifies against the IdP's published keys, `iss` and `aud` match, it is not expired (**clock skew of at most 1 minute**), and it is not an unsigned (`alg: none`) token.
5. The caller's identity comes **from the token** (`preferred_username` → the local `Users.Username`). Anything that used `X-User-Id` (timeline, like/unlike) now uses that identity, and a client-sent `X-User-Id` is ignored.
6. New `GET /api/me` returns the current local user – **without** the password/hash or lockout fields.
7. The React app no longer has its own login form: "Log in" redirects to Keycloak (Authorization Code + **PKCE**, no client secret), a `/callback` route completes the flow, API calls send `Authorization: Bearer …`, and log-out ends the IdP session too.

Out of scope: who may *do* what (step 05), refresh-token rotation and BFF (step 17), removing the legacy local login (step 04/05).

## Threat / why
The starter's "session" is `X-User-Id: <number>`; anyone can be anyone. And handing every service your password (step 02's world) does not scale, cannot do MFA or passkeys, and spreads credentials over many databases.

```bash
bash docs/attack-scripts/03-token-attacks.sh        # API + Keycloak running
```
It tries: impersonation by header, an unsigned `alg:none` token, a real token with a tampered payload – and, as a control, a genuine token. On the starter the first attack succeeds; when you are done, 1–3 print `401` and 4 prints `200`.

## Concepts
- **OAuth 2.0 is delegated authorization, OpenID Connect (OIDC) adds authentication on top.** The *ID token* tells the **client** who logged in; the *access token* is what the **API** receives. Never accept an ID token at the API and don't put your API's trust decisions on something meant for the SPA.
- **Roles:** resource owner (user), client (SPA), authorization server/IdP (Keycloak), resource server (your API).
- **Authorization Code + PKCE** is the flow for browser apps. The implicit flow and the password grant (`seclab-dev-cli` exists only so scripts/tests can get tokens) are legacy. PKCE binds the code to the client instance that started the flow, so a stolen code is useless. A SPA is a **public client**: it can't keep a secret.
- **JWT access tokens:** header (alg, kid) . payload (claims) . signature. The API downloads the IdP's **discovery document** and **JWKS** (public keys) and verifies the signature *locally*. Validation is a checklist: signature + allowed algorithm, `iss`, `aud`, `exp`/`nbf` (+ clock skew), and only then trust claims. Every "we forgot to check X" is a well-known real-world CVE class (alg=none, algorithm confusion, missing audience → token for another API accepted).
- **Audience** = which API the token is for. **Scopes/roles** = what it may do (step 05).
- **Claim mapping:** ASP.NET Core's JWT handler by default renames incoming claims (`sub` → a long URI). Decide deliberately which name you rely on and look for the setting.
- **Clock skew:** the validator tolerates time differences; the default is generous. Trade-off: short skew needs NTP-synced servers.
- **Identity mapping / provisioning:** the token's subject must map to a row in *your* database. What happens for a valid token whose user doesn't exist locally (reject, or create on first login = JIT provisioning)? Decide and document.
- **Where does the SPA keep tokens?** `localStorage` (survives, readable by any XSS), `sessionStorage` (per tab, still XSS-readable), memory (lost on reload; needs silent re-auth), or not at all in JS – a **BFF** keeps tokens server-side and gives the browser only an HttpOnly cookie. There is no perfect answer; know the trade-off (revisited in step 17).
- **HTTPS everywhere:** bearer tokens are as good as cash – whoever holds one is the user (step 01). Metadata endpoints must be HTTPS outside dev; the JWT handler enforces that unless you switch it off.
- **Libraries, not hand-rolled:** `Microsoft.AspNetCore.Authentication.JwtBearer` on the API, `oidc-client-ts` in the SPA.

## Your turn
Tasks:
1. Start Keycloak, look at the discovery document (`/realms/seclab/.well-known/openid-configuration`) and at a token (paste one into a JWT decoder *locally*, or use the script's `jq`/python approach). Which claims will you rely on?
2. API: add authentication with the JwtBearer handler, configured from `Auth:*`; require authentication on the API surface; resolve the current user from the token; add `/api/me`.
3. Make sure a **Production** run cannot silently use an HTTP authority.
4. SPA: add `oidc-client-ts`, implement login redirect, callback, bearer header, and logout. Remove the old login form and `X-User-Id` usage.
5. Run the tests and the attack script.

<details><summary>Hint 1 – where to look</summary>

`Program.cs` (services + middleware order), `appsettings*.json` (per-environment configuration), `Endpoints/Api.cs` (the `CurrentUserId` helper and the route group), `frontend/src/api/client.ts`, `pages/Login.tsx`, `App.tsx`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(...)`: `Authority`, `Audience`, `MapInboundClaims`, `RequireHttpsMetadata`, `TokenValidationParameters.ClockSkew`; `UseAuthentication()` before `UseAuthorization()`; `RequireAuthorization()` / `AllowAnonymous()` on route groups; `HttpContext.User.FindFirst(...)`. SPA: `UserManager`, `signinRedirect`, `signinRedirectCallback`, `getUser`, `signoutRedirect`, `WebStorageStateStore`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One registration block reading two config keys; a `/api` group that requires auth with the `/auth` sub-group opting out; the helper that used to parse a header now reads a claim and looks the user up (async!); Development-only override file for the HTTP Keycloak URL and an HTTPS placeholder in the base settings. SPA: one small module that builds the `UserManager`, a callback page that finishes the flow and asks `/api/me` who you are, and the request wrapper attaching the bearer token.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=03"        # 10 tests; no Keycloak needed – the tests mint their own tokens
docker compose --profile oidc up -d keycloak
bash docs/attack-scripts/03-token-attacks.sh              # expects 401 401 401 200
```
How the tests work without Keycloak: `TestIdp` owns a signing key and tells the API's JwtBearer handler to trust it (`StaticConfigurationManager`), while **your** issuer/audience/lifetime rules stay in charge. That is why the config keys and the default scheme are part of the goal.

Browser check: `npm run dev`, open `https://localhost:5173`, log in as `carol`, see her profile, timeline and friends; DevTools → Network shows `Authorization: Bearer …` and no `X-User-Id`. Log out and check Keycloak's session ended.

Checklist:
- [ ] `Step=03` tests green (10), steps 01–02 still green
- [ ] Attack script prints `401 401 401 200`
- [ ] Production start-up refuses an `http://` authority (try `ASPNETCORE_ENVIRONMENT=Production`) and a request with a valid token works against an https IdP
- [ ] No client secret in the SPA; no token in the URL after the callback
- [ ] `git grep X-User-Id` finds nothing in code

## Pitfalls
- **`ClockSkew` default is 5 minutes** – tokens expired 2 minutes ago are still accepted (a test catches it).
- Forgetting `Audience`: a token minted for *another* API of the same IdP would be accepted.
- Setting `RequireHttpsMetadata = false` globally "to make it work". Scope it to Development.
- Middleware order: `UseAuthentication` must come before `UseAuthorization` and before endpoints; CORS before both.
- Using the **ID token** as the bearer token, or reading claims from a token *before* it is validated.
- `MapInboundClaims` left on, then looking for `preferred_username` and finding nothing.
- Trusting `sub`/username mapping blindly: two IdP users with the same `preferred_username` in different realms are different people.
- Access token lifetime: short (minutes). Long-lived bearer tokens in browser storage are the real risk; think about refresh tokens before turning them on.
- Logging tokens (URL, headers) – tokens are credentials (step 12).
- Redirect URIs: register exact URIs at the IdP, never wildcards on real deployments (step 09).

## Further reading
- JWT bearer authentication in ASP.NET Core – https://learn.microsoft.com/aspnet/core/security/authentication/
- Microsoft identity platform – OAuth 2.0 auth code flow – https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 9700 (OAuth 2.0 Security BCP), RFC 8725 (JWT BCP), OpenID Connect Core
- OWASP JWT, OAuth2 and Authentication Cheat Sheets

Stuck or done? Compare with the solution: [`docs/solutions/03-oauth2-oidc.md`](solutions/03-oauth2-oidc.md) and `solutions/03-oauth2-oidc.patch` (applies on top of 01 and 02).
