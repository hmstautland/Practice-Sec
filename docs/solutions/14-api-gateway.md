# Solution – 14 API gateway

> Spoiler. Try the step yourself first: [`../14-api-gateway.md`](../14-api-gateway.md). Patch: `solutions/14-api-gateway.patch` (after 01–13; includes `packages.lock.json` for the new projects). Package: `Yarp.ReverseProxy` 2.3.0.

## What was verified
- **30 gateway test cases** and the **168 API tests** pass. **Mutation checks** on the gateway tests: switching `X-Forwarded` `For` to `Append` broke the spoofing test; disabling the admin-network check broke 5 admin-path cases. A third mutation (removing the explicit `RequestHeaderRemove: Forwarded`) did **not** fail: YARP does not forward `Forwarded` by default, so that line is belt-and-braces.
- **Whole stack live** (SQL Server + Keycloak + API on :5100 + gateway on :5443): `05-idor.sh` and `11-error-probing.sh` ran **unchanged** through the gateway with the same results; `14-edge-probes.sh`: unpublished paths `404`, credential-less `401` from the edge, `TRACE/PATCH/PROPFIND` → `405`, 4 MB body → `413`, spoofed forwarding headers accepted as a normal request (the API sees the real address), path tricks against admin routes answer `403` from the API for a non-admin from loopback (i.e. they reach the API only because loopback is inside `AdminNetworks`).
- Found by that live run and fixed: **avatars were not published** (`/avatars/**` returned 404, so profile images would have broken); a GET/HEAD-only route was added together with tests.
- **Not verified:** the SPA in a browser through the gateway; the flood section with a low limit (the limiter is covered by the automated test); an admin request from a *non-loopback* address end to end (only with the fake client IP in tests).

## Gateway project (`backend/src/SecLab.Gateway`)
**`appsettings.json`**
- `Gateway`: `RateLimitPerMinute` 300, `MaxBodyBytes` 3 MB, `AdminNetworks` loopback.
- Routes `api` (`/api/{**catch-all}`, `GET POST PUT DELETE OPTIONS`) and `avatars` (`/avatars/{**catch-all}`, `GET HEAD`), both `Timeout: 00:00:30`, cluster `api` → `http://127.0.0.1:5100/`.
- Transforms: `RequestHeaderOriginalHost: true` (API host filtering keeps working), `X-Forwarded` with **`Set`** for For/Proto/Host and `Prefix: Off`, removal of `Forwarded`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`; responses lose `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`. A code transform removes any inbound `X-Gateway-*`/`X-Internal-*` header.

**`Program.cs`**
- Kestrel: `AddServerHeader=false`, `MaxRequestBodySize`, 32 KB header budget, 15 s header timeout, TLS 1.2/1.3.
- Services: HSTS (1 year), problem details, request timeouts, rate limiter (global fixed window per `RemoteIpAddress`, `OnRejected` writes `Retry-After`), reverse proxy from configuration.
- Pipeline order: `UseHsts` (non-Development) → `UseHttpsRedirection` → exception handler → `UseStatusCodePages` → add-if-absent security headers → `UseRateLimiter` → `UseRequestTimeouts` → **edge middleware** → `MapReverseProxy`. The gateway has no forwarded-headers middleware: it *is* the edge, so the socket address is the truth (behind Front Door in Part 2 it would list that as a known proxy).
- Edge middleware, in order: reject `\`, `..`, `//` in the decoded path (`400`); `Content-Length` over the limit (`413`); `/api/admin` and `/api/debug` (case-insensitive `StartsWithSegments`) unless the client is inside `AdminNetworks` (`404`, "does not exist"); coarse authentication for `/api/**` except `/api/auth/**` and `OPTIONS` (Bearer with a value, or non-empty `X-Api-Key`, else `401` + `WWW-Authenticate: Bearer`).
- Errors set only a status code; `UseStatusCodePages` turns them into problem-details JSON. YARP's own `502` for an unreachable API goes through the same path, so nothing about the destination is written.

## API changes
- `Properties/launchSettings.json`: profile `internal` on `http://127.0.0.1:5100` with environment variables `Proxy__KnownProxies__0=127.0.0.1` and `__1=::1`. Using the **launch profile** (not `appsettings.json`) is deliberate: the API test host has client address 127.0.0.1, and trusting loopback there would break step 07's spoofing test.
- The API's `UseHttpsRedirection` sees `X-Forwarded-Proto: https` through the forwarded-headers middleware (step 07), so the plain-HTTP hop from the gateway is not redirected – TLS termination at the edge, exactly the scenario mentioned in step 01.

## Solution layout
`SecLab.slnx` now lists the Gateway and Gateway.Tests projects. The test project lives outside the API test project on purpose: it needs its own `Program` type and its own fake-API harness.

## Deliberately left open
- Gateway ↔ API is plain HTTP on loopback. On a network: TLS with mutual authentication (or a service mesh/private endpoints), and an origin lock so the API accepts only the gateway (Part 2).
- No token validation at the gateway (presence check only) and no per-user limits there.
- Single destination, no health checks/load balancing; no request/response body inspection (WAF).
- Access logging at the gateway and correlation into the API's audit stream (step 12) are not wired; the `traceparent` header is forwarded by YARP.
- Admin-network rule assumes the gateway sees real client addresses; behind another proxy, configure known proxies first.
