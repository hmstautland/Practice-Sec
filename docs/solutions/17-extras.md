# Solution – 17 Extras: BFF and session hardening

> Spoiler. Try the step yourself first: [`../17-extras.md`](../17-extras.md). Reference patch: `solutions/17-extras.patch` – apply `01`…`16`, then this one (`patch -p1 < …`). It adds `backend/src/SecLab.Gateway/Bff/` (four files), changes the gateway's `Program.cs` and `appsettings.json`, adds `appsettings.Development.json`, replaces the SPA's OIDC code, and updates `docs/00` (W15) and the OWASP matrix. One new package: `Microsoft.AspNetCore.Authentication.OpenIdConnect` 10.0.12 in the gateway (both lock files regenerated; locked restore with `CI=true` works; NuGet audit is clean). The npm package `oidc-client-ts` is gone (`npm audit`: 0 vulnerabilities). The API is **not** changed.

## What was verified
- **Red → green.** Starter + patches 01–16: `Step=17` gateway tests **38 of 40 red** (the 2 green ones are guards: no client secret in a committed file, and a bearer-only client does not need the CSRF header); the 8 new front-end tests are 8 of 8 red (the 10 older ones stay green); `17-spa-token-scan.sh` exits 1 and lists `sessionStorage`, `access_token`, `refresh_token`, `Bearer`, `signinRedirect`, … in sources and in the built bundle. With the patch: **`Step=17` 40 of 40 green** (five consecutive runs together with step 14's 30, about 2 s each, no flakiness seen), front end 18 of 18 green, `npm run build` ok, scan exits 0.
- **Whole suite on the solution** (fresh SQL Server container, `.env` and database from the scripts): 649 API tests and 70 gateway tests (30 + 40), all green. Steps 01–16 are unchanged except for the deliberate change of `frontend/tests/headers.test.ts` (below).
- **Mutation checks** on the gateway tests (a mutant is a one-line change to the solution; each was reverted; **32 mutants: 30 killed, 2 survived as equivalent**, all run against the final tests):
  | Mutant | Killed by |
  |---|---|
  | session cookie `SameSite=None` / `HttpOnly=false` / `Secure` off / no `__Host-` prefix | the cookie-flags test (each) |
  | no `SessionStore` (tokens inside the cookie) | 19 cases (cookie size, single cookie, expiry, logout …) |
  | refresh without the per-session lock (`Wait` removed – this one also throws `SemaphoreFullException` on release, so it dies for several reasons) / lock that is not exclusive (1000 permits) | 4 refresh tests / **only** the concurrency test |
  | rotated refresh token not kept | the rotation test |
  | refresh never happens | 4 refresh tests |
  | CSRF header not required / `Sec-Fetch-Site` ignored | 2 + 2 cases |
  | idle timeout ignored / clock ignored (`DateTimeOffset.UtcNow`) | 2 cases each |
  | `returnUrl` not checked | 4 cases |
  | PKCE off | 21 cases (the IdP records the violation) |
  | `Cookie` forwarded to the API / API may `Set-Cookie` | 1 case each |
  | ID-token issuer / audience / signature not validated | the ID-token theory (each) |
  | HTTP authority allowed outside Development | the production test |
  | `redirect_uri` taken from the `Host` header | the Host-header test |
  | a refused refresh keeps the session | the refusal test – **but only after I rewrote it**: the first version looked at the same browser, whose cookie the middleware had already cleared; it now replays a copy of the cookie |
  | browser `Authorization` header wins over the session's | 1 case |
  | expired cookie not cleared / `/bff/user` cacheable | 1 case each |
  | sliding cookie re-issued | the absolute-lifetime test – **after I added the assertion "no new Set-Cookie while active"** |
  | `GET /bff/logout` allowed | the logout test |
  | **absolute lifetime ignored in the store only; logout without removing the session from the store only** | **survived – equivalent mutants.** The cookie handler enforces its own `ExpireTimeSpan` (with the same `TimeProvider`) and `SignOutAsync` calls `RemoveAsync` itself: two layers do the same job. Removing **both** layers is killed (1 case each) |
- **Live against real Keycloak 26.0** (my own containers `seclab-sql-t17` and `seclab-kc-t17`, realm imported from the repository, secret read by `docs/init-bff-secret.sh`; API on 127.0.0.1:5100, gateway on https://localhost:5443 with `Bff__PublicOrigin=https://localhost:5443`): `17-bff-probes.sh` meets every "want": `/bff/user` 401; callback `302 → /profile` with `__Host-seclab-session; path=/; secure; samesite=strict; httponly` (correlation and nonce cookies: `secure; samesite=lax; httponly`, the first one deleted again), a 326-character cookie value, `/bff/user` shows three claims and no "token", `/api/me` 200; CSRF `403 403 204 403 405`; forged cookie 401; logout returns the Keycloak end-session URL with `id_token_hint`, following it ends the SSO session (`prompt=none` → `error=login_required`), the replayed cookie gives `401 401`; refresh with `Bff__RefreshSkew=00:04:55` works (`Access token refreshed (refresh token rotated: True)` in the log). Ten parallel requests with an expiring token caused **exactly one** refresh and no `invalid_grant`. With the lock removed (a mutant, live) the same ten requests made Keycloak refuse the replayed refresh token (`The identity provider refused a refresh (400)`), the gateway ended the session, and `/api/me` and `/bff/user` answered 401 – reuse detection working as described in the step (the ten `500`s of that run are an artefact of how the mutant was written: `Release` without `Wait`). The handler used **PAR** against Keycloak (the authorize URL carried only `client_id` and a `request_uri`) and worked unchanged. `init-bff-secret.sh --rotate` produced a new secret and kept one line in `.env` (mode 600).
- **Vite proxy** (dev server on a spare port, checked with `curl` and a `Host: localhost:5174` header): `/bff/user` → 401, `/api/me` → 401, `/bff/login` → 302 to Keycloak – i.e. the forwarding to the gateway works. (The gateway's `AllowedHosts` refuses `127.0.0.1`; use `localhost`.)
- **Patch applies:** on a fresh copy of the repository with 01–16 applied, `patch -p1` reproduces the verified tree exactly (`diff -r` identical, ignoring build output).
- **Supply chain:** `dotnet list package --vulnerable --include-transitive` clean for all five projects, `16-supply-chain.sh` ("nothing to act on"), `npm audit` 0.
- **Not verified here:** the interactive browser flow (redirect → Keycloak login → callback → profile, with the Strict cookie in a real redirect chain; DevTools checks of the *Verify* section); the Vite **dev server over HTTPS** with `certs/dev.pem` and the `secure: false` proxy to the dev certificate; Firefox and Safari behaviour of `__Host-` / `SameSite`; the SPA pages after login (profile edit, avatar upload through the proxy, passkeys of step 04 – the origin the browser sees is unchanged, but nothing was clicked); `docker compose --profile oidc rm -sf keycloak` as written in the step (I created my own containers with `docker run` and removed them, to leave the machine's compose containers alone); Part 2 pipelines (the gateway now needs `Bff__*` settings in a deployment); behaviour with more than one gateway instance; memory growth under many logins. Existing behaviour I noticed, not caused: a request for a **missing** avatar file answers `401` from the API (the fallback policy), also without the BFF.

## Gateway (`backend/src/SecLab.Gateway`)
**`Bff/BffSettings.cs`** – the `Bff` section as a record (`Authority`, `ClientId`, `ClientSecret`, `PublicOrigin`, `IdleTimeout` 30 min, `SessionLifetime` 8 h, `RefreshSkew` 1 min) and the constants (`__Host-seclab-session`, `/bff/callback`, `X-CSRF`). The secret is only read from configuration; `appsettings.json` has no `ClientSecret` key at all.

**`Bff/SessionStore.cs`** – an `ITicketStore` over a `ConcurrentDictionary<string, BffSession>`.
```csharp
var key = Base64Url(RandomNumberGenerator.GetBytes(32));       // 256 random bits at every login: no fixation
_sessions[key] = new BffSession(ticket, tokens, clock.GetUtcNow());
```
`StoreAsync` moves the access and refresh token out of the freshly signed-in ticket into an immutable `TokenSet` (and keeps only the `id_token`, which logout needs) – so nothing but the key is ever in the cookie. `Touch(key)` is the one lookup: unknown → null; `now − CreatedAt ≥ SessionLifetime` or `now − LastSeen ≥ IdleTimeout` → remove and null; otherwise update `LastSeen` (activity). Everything uses the injected `TimeProvider`. A `BffSession` also owns a `SemaphoreSlim(1,1)`. `Sweep()` runs on every login.

**`Bff/SessionTokens.cs`** – `GetAccessTokenAsync(ctx)`: authenticate the cookie scheme (data protection → key), `Touch`, return the access token when it is more than `RefreshSkew` from expiry; otherwise **enter the session's lock, look again** (another request may have refreshed while we waited), and POST `grant_type=refresh_token` to the discovered token endpoint with the handler's own back-channel `HttpClient`. Outcomes: success → swap in a new `TokenSet` with the **rotated** refresh token (`expires_at` from `expires_in`, with the injected clock); `4xx` → the IdP refuses (session over, reuse detected) → remove the session; network/`5xx` → keep the session, and if the old token has not expired yet keep using it, otherwise `503` + `Retry-After`. The log line says "refreshed" and whether the token rotated, never a token.

**`Bff/BffExtensions.cs`**
- `AddBff`: cookie scheme `bff-cookie` (`__Host-seclab-session`, `HttpOnly`, `Always` secure, `SameSite=Strict`, `ExpireTimeSpan` = session lifetime, `SlidingExpiration` off, `SessionStore` and `TimeProvider` injected through `Configure<…>`; the login/denied redirects become 401/403) and OIDC scheme `bff-oidc` (code flow, `ResponseMode=query`, PKCE, secret, scopes `openid profile email`, `SaveTokens`, `MapInboundClaims=false`, `RequireHttpsMetadata = !IsDevelopment()`, name claim `preferred_username`, 30 s skew, **`Lax`** correlation and nonce cookies). Events: `OnRedirectToIdentityProvider` sets `RedirectUri = PublicOrigin + /bff/callback` (after the handler built it from the request – changing it here also changes what is sent at the token endpoint, because the handler remembers the value *after* the event); `OnRedirectToIdentityProviderForSignOut` sets the post-logout URI, stores the end-session URL in the properties and calls `HandleResponse()` (no redirect inside an XHR); `OnRemoteFailure` logs and redirects to `/login?error=signin_failed`. `Program.cs` needs no `DefaultScheme`: every use names its scheme.
- `UseBffSession`: only for `/api/**` **with** the session cookie. CSRF first (`BffCsrf.Allows`: safe methods pass; otherwise `X-CSRF: 1` *and* `Sec-Fetch-Site` empty/`same-origin`/`none`; else 403), then the token service: `Ok` → `Authorization = Bearer …` (**assignment**, so a browser-supplied header is overwritten), `Unavailable` → 503, no session → clear the cookie (only when the request had one, so visitors never get a `Set-Cookie`), `WWW-Authenticate: Bearer`, 401. Requests without the cookie are untouched and fall through to step 14's credential check.
- `MapBff`: `GET /bff/login` (a `Challenge` with a **local** `returnUrl`: starts with `/`, not `//`, no `\`, no control characters; else `/`), `GET /bff/user` (three claims, `no-store`), `POST /bff/logout` (CSRF; `SignOutAsync(oidc)` first – it reads the ID token from the session – then remove from the store, `SignOutAsync(cookie)`, answer `{ endSessionUrl }`).

**`Program.cs`** – `builder.AddBff()`; the old edge middleware is split in two around `app.UseAuthentication(); app.UseBffSession();`: path/size/admin checks → authentication (handles `/bff/callback`) → BFF → coarse credential check → `MapBff()` → `MapReverseProxy()`.

**`appsettings.json`** – the `Bff` defaults (HTTPS placeholder authority) and, on both routes, `RequestHeaderRemove: Cookie` and `ResponseHeaderRemove: Set-Cookie` (plus `X-CSRF` removed on `/api`). `appsettings.Development.json` points the authority at `http://localhost:8081/realms/seclab`.

## SPA (`frontend`)
- `src/api/auth.ts` and `pages/Callback.tsx` are deleted; `oidc-client-ts` is removed from `package.json` and the lock file.
- `client.ts`: `API_BASE = ''` (same origin); the signed-in user is a module variable (reload → `loadSession()` asks the server); `loadSession()` (`GET /bff/user`, then `/api/me`), `logout()` (`POST /bff/logout` with the CSRF header, then `location.assign(endSessionUrl)`); every request carries `X-CSRF: 1` and `credentials: 'same-origin'`; a `401` clears the user and goes to `/login`. No `Authorization`, no storage.
- `main.tsx` awaits `loadSession()` before rendering; `Login.tsx` navigates to `/bff/login?returnUrl=%2Fprofile`; `App.tsx`/`Profile.tsx` call `logout()`.
- `vite.config.ts`: `proxy` for `/bff`, `/api`, `/avatars` in `server` **and** `preview` (target `https://localhost:5443`, `secure: false` for the dev certificate; Host is forwarded, so the OIDC redirect URI could also be derived from the request – the gateway uses configuration anyway), CSP `connect-src 'self'` and `img-src 'self' https://i.pravatar.cc data:`, plus `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` (`same-origin`). The built bundle contains none of `localStorage`, `sessionStorage`, `access_token`, `refresh_token`, `id_token`, `Bearer`, `Authorization`, `oidc`.

## Changes outside the new files (found while building)
- **Step 13's `frontend/tests/headers.test.ts`** asserted `connect-src` = self + API + IdP. That requirement is what this step removes, so the assertion became `['self']`. The patch changes it; it is the deliberate, reviewed kind of test change the pitfalls of step 16 ask for.
- **Shipped harness** (not part of the patch): `GatewayHarness.cs` – `Gw.ConfigureServices` (to replace `TimeProvider`) and `HandleCookies = false` on the test client (otherwise the client's own cookie container shared one session between "different" browsers: the first run of the tests let an anonymous browser through); `AssemblyInfo.cs` – gateway tests run sequentially because settings are environment variables; `FakeIdp` sets `AllowedHosts=*` for itself because the gateway's `appsettings.json` (copied next to the tests by the project reference) otherwise made it answer `400 Invalid Hostname`.
- `docs/00`: W15 is "fixed in 03, 17"; `docs/owasp-matrix.md`: A07, API2, API8 extended. Their evidence is a **file path**, not `Step=17`: the matrix test (step 13) only knows `Step=NN` traits of the *API* test project.
- The realm change (`seclab-bff`, refresh-token rotation, SSO timeouts 30 min / 8 h), `docs/init-bff-secret.sh`, `.env.example` and the scripts are shipped infrastructure, not part of the patch.

## Run it
```bash
docker compose --profile oidc rm -sf keycloak && docker compose --profile oidc up -d keycloak     # re-import the realm once
bash docs/init-bff-secret.sh                                                                        # Bff__ClientSecret into .env
set -a; source .env; set +a
dotnet run --project backend/src/SecLab.Api                    # terminal 1
dotnet run --project backend/src/SecLab.Gateway                # terminal 2 (needs Bff__ClientSecret from .env)
cd frontend && npm run dev                                     # terminal 3: https://localhost:5173 -> proxies /bff /api /avatars to the gateway
dotnet test backend/SecLab.slnx --filter "Step=17"
```

## Deliberately left open
- **Sessions live in memory.** A restart signs everybody out; two gateway instances do not share sessions. Production: a distributed store behind the same `ITicketStore` (Redis/SQL), a shared and protected Data Protection key ring (the lab uses the default per-user key folder), and a per-user limit on concurrent sessions. The store sweeps expired sessions only when somebody logs in (and a lookup removes the one it touches).
- **No back-channel logout.** A logout at the IdP (or an admin ending the SSO session) is noticed only at the next refresh (`invalid_grant`) – at most one access-token lifetime later – or when the idle timeout fires. OIDC Back-Channel Logout would end the session at once.
- **Secret-based client authentication.** `client_secret_post`; `private_key_jwt` (a signed assertion, rotated key) is the stronger option. The secret lives in `.env`; production: a vault / managed identity (Part 2).
- **A session can still be ridden by a script in the open page** (XSS): it can call the API with the session's rights while the page is open. What it can no longer do is take a credential away. Output encoding (step 10) and the CSP (step 13) remain the controls against the injection itself. `X-CSRF` is a static value: its protection is the browser's refusal to let other origins add a custom header, not its secrecy; a synchronizer token would be the stricter variant.
- **No DPoP / token binding**: the access token the gateway sends to the API is a plain bearer token.
- **The API still accepts the legacy local `/api/auth/login`** and the public client `seclab-spa` is still in the realm (kept so step 03's scripts and tests keep working); in a real system both would be removed.
- **Cookies are not port-isolated.** On `localhost` every other program sees the `__Host-` cookie (a dev-only concern; a real deployment has its own host name).
- **Lifetimes are configuration, not policy**: 30 min idle / 8 h absolute are the Keycloak realm values; nothing checks that the two sides stay aligned.
- **Trusted Types, Subresource Integrity, `report-to` for the CSP**: not added.
- **Gateway ↔ API** is still plain HTTP on loopback (step 14's note): the Bearer token the BFF adds travels there unprotected on a real network.
- The dev server's proxy trusts the gateway's self-signed certificate by switching verification off (`secure: false`) – fine for loopback, wrong anywhere else.
