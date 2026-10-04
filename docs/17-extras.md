# 17 – Extras: a backend-for-frontend (BFF) and session hardening

> Prerequisites: steps 01–16 done (or apply patches `01`–`16`), SQL Server running, `.env` loaded (`set -a; source .env; set +a`), Keycloak running. Time: 3–4 hours. No schema change. **New:** one NuGet package in the gateway (`Microsoft.AspNetCore.Authentication.OpenIdConnect`), a confidential client in the Keycloak realm, and one more secret (`Bff__ClientSecret`).
> **One-time setup (shipped infrastructure).** Keycloak imports a realm only once, so re-create the dev container to get the new client, then let a script read the secret Keycloak generated for it:
> ```
> docker compose --profile oidc rm -sf keycloak && docker compose --profile oidc up -d keycloak
> bash docs/init-bff-secret.sh          # writes Bff__ClientSecret into .env (git-ignored); `--rotate` makes Keycloak generate a new one
> set -a; source .env; set +a           # in every shell that starts the gateway
> ```
> The tests of this step are in `backend/tests/SecLab.Gateway.Tests/Step17BffTests.cs` (they need neither Keycloak nor SQL Server – they bring their own identity provider) and `frontend/tests/step17-bff.test.ts`.

## Goal
Step 03 ended with an honest limitation: the SPA obtains its tokens itself and keeps them in `sessionStorage`, where **any script that runs in the page can read them** (W15). Take the tokens out of the browser. The browser gets exactly one thing – an opaque, `HttpOnly` session cookie – and a server component, the **BFF** (backend-for-frontend), holds the tokens, talks to the identity provider and to the API on the user's behalf.

**Decision record – what already exists, and where the BFF goes**

| Concern | Already there | This step |
|---|---|---|
| Authorization Code + PKCE, token validation | Step 03: public SPA client `seclab-spa`; the API validates JWTs (issuer, audience, lifetime, signature) | The **gateway** becomes a *confidential* client (`seclab-bff`, with a secret). The API is **not touched**: it still receives a bearer token and validates it exactly as before |
| Response headers, SPA CSP | Step 13: strict CSP (`script-src 'self'`, …) in the Vite preview config, `nosniff`, `Referrer-Policy`, `Permissions-Policy`; the API never sets a cookie | Not repeated. The CSP is only **tightened** (the page no longer needs the API or the IdP in `connect-src`) and gets COOP/CORP. Step 13's `headers.test.ts` changes on purpose |
| Coarse authentication, header hygiene, limits | Step 14: gateway edge | Reused. The BFF logic sits *inside* the gateway's pipeline, in front of the existing credential check |
| CORS allow-list | Step 09 | The SPA and the BFF now share one origin, so the SPA needs no CORS at all. The API's policy stays as defence in depth |

*Why the gateway and not the API?* The gateway is the only public process, already the trust boundary (TLS, limits, header hygiene), and the one place that must be allowed to hold a client secret. The API stays a plain resource server with no notion of cookies, sessions or CSRF – its tests (and the step-13 rule "the API never sets a cookie") keep their meaning. The price: the gateway becomes **stateful** (sessions), which matters when you run more than one copy.

Acceptance criteria (the 40 gateway tests and 8 front-end tests encode them):

**Login (Authorization Code + PKCE, confidential client)**
1. Configuration (section **`Bff`**): `Authority`, `ClientId` (`seclab-bff`), `ClientSecret` (**only** from the environment – `Bff__ClientSecret` – never in `appsettings*.json`, the realm file, or the SPA), `PublicOrigin` (default `https://localhost:5173`), `IdleTimeout` (30 min), `SessionLifetime` (8 h), `RefreshSkew` (1 min). Development points at Keycloak over HTTP (`appsettings.Development.json`); every other environment requires an HTTPS authority.
2. `GET /bff/login?returnUrl=/path` redirects to the IdP with response type `code`, **PKCE (S256)**, `state`, `nonce` and the scopes `openid profile email`. The `redirect_uri` is built from **`Bff:PublicOrigin`**, not from the `Host` header. The secret never appears in a URL; it is sent only server-to-server, to the token endpoint.
3. The callback is handled by the standard OpenID Connect handler. An ID token with a wrong signature, issuer, audience or nonce, a forged `state`, or a replayed callback creates **no session**. Failures end in a redirect to `/login?error=signin_failed` with no protocol details.
4. `returnUrl` must be a local path (`/…`); anything else (`https://…`, `//host`, `/\host`, `javascript:`) is replaced by `/`.

**The cookie and the session**
5. After login the browser holds **exactly one cookie** (the short-lived OIDC correlation cookies are gone again): `__Host-seclab-session`, `HttpOnly`, `Secure`, `SameSite` Strict (or Lax), `Path=/`, no `Domain`, no `Expires`. *Every* cookie of the flow – also the correlation and nonce cookies – is `HttpOnly`, `Secure` and not `SameSite=None`.
6. The cookie is **a reference**, not a container: under 512 characters, no tokens in it, no chunked cookies. Tokens and claims live **server-side**. Every login creates a new, unpredictable session identifier.
7. **Idle timeout** (`Bff:IdleTimeout`) and **absolute lifetime** (`Bff:SessionLifetime`) are enforced on the server; activity extends only the idle timer; the cookie is never re-issued. An expired or unknown session is `401` and the browser's cookie is cleared. All time decisions use the registered **`TimeProvider`** (the tests move it).
8. `GET /bff/user` answers `401` without a session and, with one, a small allow-list of claims (`username`, `name`, `sub`) with `Cache-Control: no-store` – never a token.

**Calls to the API**
9. A request to `/api/**` that carries the session cookie gets the session's access token as `Authorization: Bearer …`. Whatever `Authorization` the browser sent is **replaced**. The API never sees the `Cookie` header, and it **cannot set cookies** on the application's origin (`Set-Cookie` from the API is dropped). Requests without the cookie behave as in step 14 (Bearer or API key required, passed through unchanged).
10. **CSRF:** a request authenticated by the cookie that is not `GET`/`HEAD`/`OPTIONS` must carry the header **`X-CSRF: 1`** and must not claim to come from another site (`Sec-Fetch-Site` absent, `same-origin` or `none`); otherwise `403` from the gateway, before the API sees it.
11. **Refresh on the server:** when the access token expires within `Bff:RefreshSkew`, the gateway uses the refresh token – once, even for ten simultaneous requests – stores the **rotated** refresh token, and carries on; the browser notices nothing. If the IdP refuses (session ended, token reuse detected), the session ends (`401`) and nothing expired reaches the API. If the IdP is merely unreachable and the old token is still valid, keep using it; otherwise `503`.

**Logout**
12. `POST /bff/logout` (with the CSRF header; `GET` does nothing) destroys the session **on the server**, clears the cookie and answers `{ "endSessionUrl": … }` – the IdP's end-session URL with `id_token_hint` and `post_logout_redirect_uri` (= `PublicOrigin` + `/`) – for the page to navigate to, so the IdP session ends too. A copy of the old cookie is worthless afterwards.

**SPA**
13. The SPA has **no OIDC library, no token handling, no `localStorage`/`sessionStorage`/IndexedDB/`document.cookie`**, and talks only to its own origin. Log-in is a navigation to `/bff/login`, "who am I" is `/bff/user` (before the first render), every API call carries the CSRF header, log-out is the POST above. The Vite dev server **and** preview server forward `/bff`, `/api` and `/avatars` to the gateway.
14. The CSP of step 13 is tightened to `connect-src 'self'` (no API or IdP origin), the `img-src` loses the API origin, and the headers gain `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`. Update step 13's own test in the same change.

Out of scope (see *Concepts* and the solution notes): back-channel logout, DPoP/token binding, several gateway instances (a shared session store), per-user session limits, `private_key_jwt` client authentication, Trusted Types.

## Threat / why
A token in the browser is a credential in a place that runs other people's code: your own components, every npm package you bundle, ad or analytics scripts, and – when an injection bug slips through (W8 was fixed in step 10, but assume the next one exists) – the attacker's script. Such a script can read `sessionStorage` and `localStorage`, and send what it finds anywhere the CSP allows. The stolen **access token** works for minutes, the stolen **refresh token** for as long as the IdP session lasts, from the attacker's own machine, after the victim has closed the tab. Two things reduce that damage:

1. **The token never reaches JavaScript** (this step's BFF). A script can still *use* the page's session while the page is open (session riding) – the BFF does not fix XSS – but it can no longer **take anything away**: no durable credential, nothing that outlives the tab, nothing that works from another machine.
2. **Cookies bring their own problems**, which you must now solve: the browser attaches them to requests another site triggers (**CSRF**), they can be stolen with the wrong flags, they can be fixated or outlive their purpose (**session lifetime, logout**), and a server-side session must survive a hostile network (**refresh-token rotation and races**).

```bash
bash docs/attack-scripts/17-spa-token-scan.sh     # what can a script in the page read?  (exit 1 until the tokens are gone)
bash docs/attack-scripts/17-bff-probes.sh         # a real login with curl, then cookie flags, CSRF, replayed cookies, logout, refresh
```
The first script scans the sources and the **production bundle**: on the starter it finds `sessionStorage`, `access_token`, `refresh_token`, `Bearer`, the OIDC library. The second needs the whole stack and the gateway started with `Bff__PublicOrigin=https://localhost:5443` (there is no SPA dev server in it; see the header of the script). On the starter it stops at section 1 (`/bff/user` is `404`); when you are done every line says what it wanted.

## Concepts
- **Where can a SPA keep a token?** `localStorage` (survives, readable by any script), `sessionStorage` (per tab, still readable), JavaScript memory (gone on reload, still readable by any script in the page and needs a silent re-login), a Web Worker or service worker (smaller surface, still the same page's code), or **not at all**: the BFF pattern. The IETF's *OAuth 2.0 for Browser-Based Applications* recommends the BFF for anything that matters, because it is the only option where a successful XSS cannot leave with the credential.
- **The BFF pattern.** The SPA is a *UI*, the BFF is the *OAuth client*. The browser authenticates to the BFF with a cookie; the BFF holds access and refresh tokens, adds `Authorization` when it forwards a request, and refreshes. A **confidential client** can authenticate to the IdP with a secret (or, better, a signed assertion – `private_key_jwt`): a stolen authorization code is useless without it, and PKCE still protects the code in the browser. A proxy BFF (as here) forwards the API calls; a "token-mediating" backend only hands out tokens and is much weaker.
- **Same origin.** The page and the BFF should look like one origin to the browser (a reverse proxy in front of both; Vite's `server.proxy` in development). Then the cookie is first-party, there is no CORS, and `fetch` needs no `credentials: 'include'`. *Site* vs *origin*: `https://localhost:5173` and `https://localhost:5443` are different origins but the **same site** (ports are not part of a site) – which is why SameSite alone says nothing about them. **Lab caveat:** cookies are not isolated by port, so every program on `localhost` sees the cookies of every other port.
- **Cookie attributes** (RFC 6265bis): `HttpOnly` (scripts cannot read it), `Secure` (HTTPS only), `SameSite=Strict|Lax|None` (when the browser attaches it to cross-site requests – `Strict` also withholds it from the navigation that arrives from another site), `Path`/`Domain` (scope; no `Domain` = this host only), `Max-Age`/`Expires` (absent = browser session), and the **`__Host-` prefix**, which makes the browser *refuse* the cookie unless it is `Secure`, `Path=/` and has no `Domain` – a sibling subdomain cannot overwrite it. The OIDC correlation/nonce cookies must survive the redirect *back from the IdP* (a cross-site top-level navigation): they need `Lax`, not `None` and not `Strict`.
- **CSRF.** Whenever the browser attaches a credential by itself, another site can make the user's browser send requests. Defences, layered: `SameSite`; a **custom request header** (a form or `<img>` cannot add one, and a cross-origin `fetch` with one needs a CORS preflight that you never grant); **Fetch Metadata** (`Sec-Fetch-Site` tells you where a request came from); an `Origin` check; classic **anti-forgery tokens** (synchronizer or double-submit). Requests that carry no cookie (bearer tokens, API keys) are not CSRF-able. *Login CSRF* (forcing the victim into the attacker's account) is what `state`/the correlation cookie prevent; *logout CSRF* is why logout is a `POST`.
- **Server-side sessions.** A cookie that *contains* the session (an encrypted ticket) cannot be revoked, grows with what you put in it (tokens are 1–2 KB each; browsers cap a cookie at ~4 KB and ASP.NET chunks it) and ships its contents with every request. A cookie that is only a **key** into a server-side store can be revoked at once, stays tiny, and keeps the tokens on the server. In ASP.NET Core: `CookieAuthenticationOptions.SessionStore` (`ITicketStore`). **Idle timeout** (no activity) and **absolute lifetime** (since login) are different controls: the first limits an unattended session, the second limits a stolen-but-active one. **Session fixation**: a new identifier at every login. The lab store is in memory (restart = everybody signs in again; two gateway instances = two stores): production uses a shared store (Redis, SQL) and a shared Data Protection key ring.
- **The OpenID Connect handler** (`AddOpenIdConnect`) does a lot you must not rewrite: discovery and key download, `state` and `nonce` with the correlation cookie, PKCE, code exchange, ID-token validation (signature, issuer, audience, lifetime, nonce). Since .NET 9 it also uses **Pushed Authorization Requests** (RFC 9126) when the IdP advertises them – Keycloak does, and the authorize URL then carries only a `request_uri`. What stays yours: the redirect URI (configuration, never the `Host` header), the return URL (a local path), what happens on failure (no details to the user), where tokens go, and logout.
- **Refresh tokens.** In a browser a refresh token is the most dangerous string you can hold (it outlives the access token by hours). At a BFF it is just a server-side secret. **Rotation:** every refresh returns a *new* refresh token and invalidates the old one. **Reuse detection:** if an already used refresh token is presented again – a thief and the owner both holding it – the IdP revokes the whole family and both are logged out. Consequences for *your* code: (1) store the new refresh token **before** you need it again; (2) never refresh the same session **in parallel** – two requests that both see an expired token would both present the same refresh token, and your own race looks exactly like theft; (3) `invalid_grant` means the session is over, not "try again"; (4) refresh a little early (`RefreshSkew`) so a request does not arrive with a token that expires in flight.
- **Logout.** There are two sessions – yours and the IdP's. Deleting your cookie leaves the IdP session, so the next "login" silently succeeds. **RP-initiated logout** sends the browser to the IdP's `end_session_endpoint` with `id_token_hint` (which session) and an allow-listed `post_logout_redirect_uri`. **Back-channel logout** (the IdP calls *you* when the user logs out elsewhere) closes the remaining gap and is not built here. Align lifetimes: Keycloak's SSO idle/max (realm: 30 min / 8 h) and the BFF's timeouts should agree, or the shorter one silently wins.
- **Proxy transforms.** What the browser sends is not what the API should get: the cookie stays at the gateway, the `Authorization` header is the gateway's, `Set-Cookie` from upstream is dropped. YARP's header transforms (or a small middleware) do it, and the tests check it at the API's end.
- **SPA hardening that belongs with this.** No credentials in script-reachable storage (a test greps sources *and* the built bundle); the page talks to one origin, so the CSP can say `connect-src 'self'` – a successful XSS can then no longer *send* data to another origin through `fetch`; COOP/CORP isolate the browsing context. What is still in JavaScript, and why that is acceptable: the user's own profile in memory (display), the short-lived step-up token of step 04 (one purpose, one use), a freshly created API key shown once. Not done: **Trusted Types** (`require-trusted-types-for 'script'`) – worth trying once you have no `dangerouslySetInnerHTML` left outside a sanitizer policy.
- **Testing a stateful, time-dependent control.** The shipped harness runs a *real* identity provider on a loopback socket (discovery, JWKS, authorization, token endpoint with client authentication, PKCE verification, rotation, reuse detection) and moves the gateway's clock through the `TimeProvider` service – no `Thread.Sleep`, no five-minute test. The IdP records every protocol violation (`Problems`), so a missing PKCE challenge fails a test even if the login "worked".

## Your turn
Tasks:
1. **Infrastructure.** Do the one-time setup above. Open `infra/keycloak/seclab-realm.json`: find the `seclab-bff` client (confidential, standard flow only, PKCE required, exact redirect URIs) and the realm settings that make refresh tokens rotate. Read `BffHarness.cs` – `FakeIdp` is the executable specification of what your gateway talks to.
2. **Gateway: configuration and secrets.** Add the OpenID Connect package, a `Bff` section with the defaults of the goal (HTTPS placeholder authority in `appsettings.json`, HTTP Keycloak in a Development override), and read the secret from the environment only.
3. **Sessions.** Cookie authentication with the flags of the goal, backed by a **server-side session store** that holds the claims and the tokens and enforces the idle timeout and the absolute lifetime with `TimeProvider`.
4. **Login.** Configure the OpenID Connect handler (code flow, PKCE, secret, scopes, callback path, validation, `Lax` correlation cookies, redirect URI from configuration, failure handling), then the `/bff/login` and `/bff/user` endpoints with a safe `returnUrl`.
5. **Calls to the API.** In the gateway's pipeline, after the existing edge checks and before the credential check: for `/api/**` requests with the session cookie apply the CSRF rules, obtain a valid access token (refresh when needed, **one refresh at a time per session**, keep the rotated refresh token, end the session when the IdP refuses) and set `Authorization`. Add the YARP transforms that keep cookies away from the API and drop `Set-Cookie` from it.
6. **Logout.** `POST /bff/logout`: build the IdP end-session URL, destroy the server-side session, clear the cookie, hand the URL to the caller.
7. **SPA.** Remove the OIDC library and its pages; make the client same-origin with the CSRF header; ask `/bff/user` before the first render; log in and out through the BFF; proxy `/bff`, `/api`, `/avatars` in the Vite dev **and** preview servers; tighten the CSP and update `headers.test.ts`.
8. **Run** the tests and scripts below, then **update the documents**: W15 in `docs/00` (fixed in 17) and the evidence of the OWASP matrix rows this step strengthens (A07, API2, API8 – evidence by file path, since the matrix test only knows `Step=NN` filters of the API test project).
9. **Prove your tests can fail.** Break your own solution on purpose in five ways (`SameSite=None`, no refresh lock, forget the rotated refresh token, no CSRF check, logout that only deletes the cookie) and see the right tests go red – the habit from step 16.

<details><summary>Hint 1 – where to look</summary>

`backend/src/SecLab.Gateway/Program.cs` (the order of the middleware: where does the OIDC callback have to be handled, and where does the credential check happen?), `appsettings.json` (the `ReverseProxy` transforms), `frontend/src/api/client.ts`, `App.tsx`, `pages/Login.tsx`, `main.tsx`, `vite.config.ts`. In the tests: `BffRig.Start` shows the configuration keys and the `TimeProvider` replacement; `Browser.SignIn` shows exactly what a browser does during a login.
</details>

<details><summary>Hint 2 – which APIs</summary>

`AddAuthentication().AddCookie(…).AddOpenIdConnect(…)` with explicit scheme names (no default scheme needed; pick the schemes explicitly where you use them). Cookie: `Cookie.Name/HttpOnly/SecurePolicy/SameSite`, `SessionStore` (`ITicketStore`: `StoreAsync`, `RenewAsync`, `RetrieveAsync`, `RemoveAsync`), `ExpireTimeSpan`, `SlidingExpiration`, `Events.OnRedirectToLogin`; `AuthenticationSchemeOptions.TimeProvider`. OpenID Connect: `Authority`, `ClientId`, `ClientSecret`, `ResponseType`, `UsePkce`, `CallbackPath`, `Scope`, `SaveTokens`, `MapInboundClaims`, `RequireHttpsMetadata`, `TokenValidationParameters`, `CorrelationCookie`/`NonceCookie`, `Backchannel`, `ConfigurationManager`, and the events `OnRedirectToIdentityProvider`, `OnRedirectToIdentityProviderForSignOut` (`HandleResponse()`), `OnRemoteFailure`. Endpoints: `Results.Challenge`, `HttpContext.AuthenticateAsync/SignOutAsync`, `AuthenticationProperties.GetTokenValue/StoreTokens/Items`. Refresh: a form POST with `grant_type=refresh_token` to the token endpoint, `SemaphoreSlim` per session, `TimeProvider.GetUtcNow()`. Transforms: `RequestHeaderRemove`, `ResponseHeaderRemove`. SPA: `fetch` with a custom header, `window.location.assign`, Vite `server.proxy`/`preview.proxy`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Three small units behind a few extension methods: a **session store** (random key → ticket + immutable token set + last-seen time + a lock; every lookup checks both lifetimes), a **token service** (`get access token for this request`: look up → fresh enough? → otherwise lock, look again, refresh, replace the token set, or end the session), and a **middleware** that applies CSRF and swaps cookie for `Authorization` for `/api` requests that carry the session cookie. The OIDC handler writes into the cookie scheme; moving the tokens from the freshly signed-in ticket into the store happens in `StoreAsync`. Logout asks the OIDC handler for the end-session URL *before* removing the session (it needs the ID token), but must not let it redirect: capture the URL in the sign-out event. Order in `Program.cs`: existing hygiene checks → `UseAuthentication` → BFF middleware → existing credential check → endpoints → proxy.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=17"                 # 40 gateway cases; each starts its own IdP and gateway, no Keycloak needed
dotnet test backend/SecLab.slnx                                    # everything: step 14's gateway tests and all earlier steps stay green
cd frontend && npm test && npm run build                           # 8 new + earlier front-end tests; type-check and build
bash docs/attack-scripts/17-spa-token-scan.sh                      # exit 0, nine "ok"

# the live stack (Keycloak with the new realm, `init-bff-secret.sh` done, .env loaded in the shell that starts the gateway)
dotnet run --project backend/src/SecLab.Api                        # 127.0.0.1:5100
Bff__PublicOrigin=https://localhost:5443 Bff__RefreshSkew=00:04:55 dotnet run --project backend/src/SecLab.Gateway   # for the probe script only
bash docs/attack-scripts/17-bff-probes.sh
```
For the browser, start the gateway **without** those two overrides and run `cd frontend && npm run dev` (https://localhost:5173 – the redirect URI registered at Keycloak; `npm run preview` on :4173 serves the production build with the CSP, but is not a registered redirect URI).

How the tests work: `FakeIdp` speaks real HTTP on `127.0.0.1:<random>`; `Gw` hosts the real gateway pipeline with a fake API behind it; `Browser` keeps cookies and a transcript of every byte it received; `TestClock` replaces the `TimeProvider` service. Nothing in them knows how you implemented the gateway – only configuration keys, URLs, cookies and headers.

Browser check (cannot be automated here): log in as `carol` → DevTools → *Application* → Cookies: one cookie, `HttpOnly`, `Secure`, `SameSite=Strict`, name starts with `__Host-`; *Storage* has nothing; the console says `document.cookie` → `""`; *Network*: calls to `/api/...` carry `X-CSRF: 1`, no `Authorization`, and no token appears in any response. Log out → Keycloak's own session is gone (opening the app asks for the password again); reload after a restart of the gateway → you are asked to log in again (in-memory sessions).

Checklist:
- [ ] `Step=17` gateway tests green (40), steps 01–16 and the 30 step-14 tests still green
- [ ] `npm test` and `npm run build` green; `17-spa-token-scan.sh` exits 0
- [ ] `17-bff-probes.sh`: every "want" is met (`403 403 2xx 403 405`, `401 401` after logout, `error=login_required`)
- [ ] No client secret in the repository (`grep -rni secret infra backend/src/SecLab.Gateway --include=*.json` shows no value); `.env` is git-ignored
- [ ] You broke it on purpose (task 9) and the tests noticed
- [ ] W15 and the matrix rows updated

## Pitfalls
- **A cookie that is "set but never sent".** `SameSite=Strict` is fine for the session, but the OIDC correlation cookie must be `Lax`, or the callback (a cross-site navigation) arrives without it. A `Secure` cookie on plain HTTP is dropped; `__Host-` additionally needs `Path=/` and no `Domain`. Page and gateway on different origins force `credentials: 'include'`, CORS with `Allow-Credentials` and a named origin – the proxy avoids all of it.
- **Tokens in the cookie.** `SaveTokens = true` with the default cookie handler puts access, refresh and ID token into the (encrypted) cookie: 4+ KB, chunked, sent with every request, impossible to revoke. A session store is the point of this step.
- **Parallel refresh.** The classic BFF bug: ten requests, one expired token, ten refreshes with the same refresh token; the IdP sees reuse, revokes the family, the user is logged out "randomly". One lock per session, and look again inside the lock.
- **Forgetting the rotated refresh token** (or storing it after the next request already used the old one).
- **Reading time from the wall clock** (`DateTime.UtcNow`) in a place the tests cannot move – and then sleeping in tests, or not testing expiry at all.
- **Open redirect** through `returnUrl`; **redirect URI taken from the `Host` header**; both are one-line mistakes that look like convenience.
- **Logout that only deletes the cookie** (the server session lives on, and a copied cookie still works), **logout by `GET`** (any page can log you out; `<img src=/logout>`), **no IdP end-session** (the next click logs you in again silently), `id_token_hint` missing.
- **CSRF defended on `POST` only** (PUT and DELETE are state-changing too), a header check that accepts any value, or a check the proxy never sees because the middleware order is wrong.
- **Letting the browser's `Authorization` header win** over the session's token, or forwarding the `Cookie` header to the API, or letting the API `Set-Cookie` on your origin.
- **Sweeping up errors**: showing the OIDC handler's exception text to the user; disabling `RequireHttpsMetadata` globally "to make Keycloak work" (scope it to Development).
- **The secret in the wrong place**: `appsettings.json`, the realm JSON, the SPA bundle, a test file that is also used in CI, the log. A confidential client whose secret is public is a public client with extra steps.
- **Believing the BFF fixes XSS.** It removes the *theft* of credentials, not the use of the session while the page is open. Output encoding (step 10) and the CSP (step 13) are still what stops the injection.
- **In-memory sessions at scale.** Two instances behind a load balancer: half of the requests land on the one that has never heard of the session. Sticky sessions hide it; a shared store fixes it (and the Data Protection key ring must be shared too).
- **Idle/absolute timeouts that disagree with the IdP's**: the BFF session outlives the SSO session (every refresh then fails) or the other way round (users are logged out at the IdP and still "logged in" here).

## Further reading
- IETF OAuth Working Group: *OAuth 2.0 for Browser-Based Applications* (BCP draft – the BFF section), RFC 9700 (OAuth 2.0 Security BCP), RFC 6749/7636, RFC 9126 (Pushed Authorization Requests), OpenID Connect Core, *RP-Initiated Logout 1.0*, *Back-Channel Logout 1.0*
- RFC 6265bis (cookies: `SameSite`, prefixes) and MDN: *Set-Cookie*, *Fetch metadata (`Sec-Fetch-Site`)*, *Cross-Origin-Opener-Policy*
- ASP.NET Core: *Use cookie authentication without ASP.NET Core Identity*, *`ITicketStore`*, *Configure OpenID Connect authentication*, *Prevent Cross-Site Request Forgery attacks*, *TimeProvider* – https://learn.microsoft.com/aspnet/core/security/authentication/
- YARP: *Transforms* (header removal) – https://microsoft.github.io/reverse-proxy/
- Keycloak: *Securing applications – OIDC*, *Server Administration: refresh token rotation / "Revoke Refresh Token"*, *session and token timeouts*
- OWASP Cheat Sheet Series: *Session Management*, *Cross-Site Request Forgery Prevention*, *HTML5 Security* (storage), *OAuth 2.0 / JWT*; OWASP ASVS V3 (Session Management)
- Duende BFF documentation – a commercial product implementing the same pattern; useful to compare designs
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/

Stuck or done? Compare with the solution: [`docs/solutions/17-extras.md`](solutions/17-extras.md) and `solutions/17-extras.patch` (applies on top of 01–16).
