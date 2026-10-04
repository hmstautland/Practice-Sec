# 14 – API gateway

> Prerequisites: steps 01–13 done (or apply patches `01`–`13`). Time: 3–4 hours. No schema change. **New:** a second service. From now on the app is two processes (gateway on the public port, API on an internal one) – see the "Run it" note at the end of *Verify*.
> The tests are in `backend/tests/SecLab.Gateway.Tests`. That project is **not** in `SecLab.slnx` yet: create `backend/src/SecLab.Gateway` first, then add both projects to the solution.

## Goal
Put **one hardened front door** in front of the API: everything from the internet arrives at the gateway; the API listens only on an internal address. The gateway decides what is published at all, and rejects or normalises what it can before the API spends a cycle on it.

Build `backend/src/SecLab.Gateway` (ASP.NET Core + **YARP** reverse proxy) so that:

**Publishing**
1. The gateway listens on `https://localhost:5443` (the address the SPA already uses) and `http://localhost:5080` (redirects to HTTPS). The API moves to **`http://127.0.0.1:5100`** – loopback only – and trusts `X-Forwarded-*` headers **only from the gateway** (step 07's `Proxy:KnownProxies`; set it in the API's launch profile, not in `appsettings.json`, so tests do not trust loopback).
2. Two routes, configured in `appsettings.json` (`ReverseProxy` section): `/api/**` with methods `GET POST PUT DELETE OPTIONS`, and `/avatars/**` with `GET HEAD` (images are loaded by `<img>` tags that cannot send tokens). Each route has an explicit method list (no wildcard, no `TRACE`/`CONNECT`) and a **`Timeout` ≤ 60 s**. Everything else – `/`, `/swagger`, `/health/*`, `/metrics`, `/api2/…` – is a `404` **from the gateway**; the API never sees it.
3. `/api/admin/**` and `/api/debug/**` do not exist for the internet: unless the client address is inside **`Gateway:AdminNetworks`** (CIDR list, default loopback) the gateway answers `404`. Path tricks (`/API/Admin/…`, `%61dmin`, `.`/`..`, backslashes, `//`) must not get around it.

**Hygiene**
4. Client-supplied `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL` and any `X-Gateway-*`/`X-Internal-*` header are **dropped**. The API receives `X-Forwarded-For` = exactly the address the gateway saw, `X-Forwarded-Proto: https`, and the original `Host` (the API's `AllowedHosts` still applies).
5. `Server`, `X-Powered-By`, `X-AspNet*` headers from the API never reach the client; the gateway adds `nosniff`, `Referrer-Policy`, `X-Frame-Options`, a default-deny CSP (add-if-absent); HSTS outside Development; HTTP → HTTPS redirect; host filtering (`AllowedHosts`).
6. Gateway-produced errors (404, 401, 405, 413, 429, 502) are **problem-details JSON**; a dead API gives a generic `502` – **no internal address, port or exception text**.

**Protection**
7. **Coarse authentication at the edge:** a request to `/api/**` (except `/api/auth/**` and `OPTIONS` preflights) must carry *some* credential – `Authorization: Bearer <token>` or `X-Api-Key` – else `401` from the gateway. The API still validates properly; this only removes anonymous noise.
8. **Body limit:** > `Gateway:MaxBodyBytes` (3 MB) → `413` from the edge, also via Kestrel for chunked bodies.
9. **Rate limit per client address:** `Gateway:RateLimitPerMinute` (default 300) → `429` + `Retry-After`. Refused requests count too. (The API's finer per-user/per-key limits stay.)
10. TLS 1.2/1.3 only; short header timeout; no server banner.

Out of scope: JWT validation at the gateway (possible with YARP + JwtBearer, discussed below), WAF rules and DDoS protection (Part 2: Front Door), mTLS between gateway and API (Part 2), load balancing.

## Threat / why
A single service that faces the internet and also holds business logic means every parser bug, verbose error and forgotten endpoint is directly exposed. A gateway gives you: a **smaller, simpler, hardened attack surface**; **one** place for TLS, limits and header hygiene; the ability to hide internal-only routes; and **defence in depth** – what one layer misses (an unauthenticated flood, a forged `X-Forwarded-For`, a path trick) the next layer still stops. It also creates new risks you must design against: header trust between layers, *bypass* of the gateway, and the gateway as a single point of failure.

```bash
bash docs/attack-scripts/14-edge-probes.sh      # gateway :5443 + API :5100 + Keycloak running
```

## Concepts
- **Reverse proxy vs. API gateway vs. WAF.** A reverse proxy forwards. A gateway adds API-level policy (routing, authn/z hints, quotas, transformation). A WAF inspects for attack patterns. YARP is a *library* for building a proxy/gateway in .NET; managed products (Azure API Management, Front Door + WAF, Kong, Envoy) do the same at scale.
- **YARP building blocks:** *routes* (match on path/host/method/headers) → *clusters* (destinations, health checks, load balancing) → *transforms* (request/response header and path manipulation). Configuration comes from `appsettings.json` and can be reloaded; code-based transforms cover the rest. You can replace the forwarder's HTTP client (that is how the tests put a fake API behind the gateway).
- **Trust boundaries and forwarded headers.** Each hop should overwrite, not append to, the "who is the client" headers, and the next hop should trust them **only** from the previous hop. If the API trusts `X-Forwarded-For` from anyone, an attacker forges their address; if the gateway passes the client's header through, the same. (Recall step 07: an empty trusted-proxy list means "trust everyone" for the forwarded-headers middleware.)
- **Bypass.** A gateway is worthless if the API is reachable another way. Bind the API to loopback/private network, firewall it, and in the cloud use private endpoints or an *origin lock* (the API only accepts traffic carrying a secret/identity that only the gateway/Front Door has). Test the bypass, don't assume.
- **What belongs at the edge:** TLS termination, HTTP hygiene, size/time limits, coarse rate limits, published-route allow-list, network allow-lists for admin routes, response header hygiene, request logging/correlation. **What does not:** business authorization (ownership, roles) – that needs data only the API has.
- **Authentication at the edge:** either *pass-through* (as here: presence check only), or *validate* (JwtBearer at the gateway: signature, issuer, audience, expiry; then forward). Validation at both layers is defence in depth but doubles configuration; never let the API *skip* validation because "the gateway did it" unless the hop is cryptographically authenticated.
- **Path normalisation.** Attackers use case changes, percent-encoding, dot-segments, double slashes and backslashes to slip past string checks. Match after the framework has normalised the path, use case-insensitive comparisons, and reject the odd ones outright.
- **Failure behaviour:** timeouts, no retries for non-idempotent methods, generic 502/504, do not leak upstream addresses. Health checks for clusters (active/passive) matter once you have more than one instance.
- **Correlation:** forward `traceparent` (YARP does) so a request can be followed gateway → API in logs (step 12).

## Your turn
Tasks:
1. Create the gateway project and add it and its test project to the solution.
2. Describe routes, cluster, timeouts and header transforms in `appsettings.json`.
3. Write the edge middleware: path sanity, size limit, admin-network rule, coarse authentication.
4. Add rate limiting, HTTPS redirect/HSTS, problem-details errors, defensive headers, Kestrel limits.
5. Move the API to the internal address and trust the gateway as forwarding proxy.
6. Run the tests, then the whole stack, then the probes.

<details><summary>Hint 1 – where to look</summary>

New `backend/src/SecLab.Gateway` (`dotnet new web`), `backend/SecLab.slnx`, `backend/src/SecLab.Api/Properties/launchSettings.json`, the test project's `GatewayHarness.cs` (it shows exactly which YARP type the tests replace and which config keys they set).
</details>

<details><summary>Hint 2 – which APIs</summary>

NuGet `Yarp.ReverseProxy`: `AddReverseProxy().LoadFromConfig(...)`, `.AddTransforms(ctx => ctx.AddRequestTransform(...))` (namespace `Yarp.ReverseProxy.Transforms`), `MapReverseProxy()`. Config transforms: `RequestHeaderOriginalHost`, `X-Forwarded` (`For`/`Proto`/`Host`/`Prefix` with `Set`/`Append`/`Off`), `RequestHeaderRemove`, `ResponseHeaderRemove`; route `Timeout` + `AddRequestTimeouts()`/`UseRequestTimeouts()`; `Match.Methods`, `Match.Path`. ASP.NET: `AddRateLimiter` (global partitioned), `UseStatusCodePages`, `UseHttpsRedirection`, `UseHsts`, Kestrel `Limits`, `IPNetwork`, `PathString.StartsWithSegments(…, OrdinalIgnoreCase)`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Program.cs: Kestrel limits → services (HSTS, problem details, timeouts, rate limiter, reverse proxy + one code transform) → pipeline: HTTPS redirect/HSTS → exception handler → status-code pages → header hardening → rate limiter → timeouts → one inline middleware doing the four edge checks → `MapReverseProxy`. Config: two routes sharing one cluster, each with the transforms. Be careful with the default behaviour of the X-Forwarded transforms (append vs set) and with the `Host` header the API sees.
</details>

## Verify
```bash
# tests (gateway project uses a fake API behind the real gateway pipeline)
dotnet test backend/tests/SecLab.Gateway.Tests        # 30 test cases
dotnet test backend/SecLab.slnx                        # everything, incl. 168 API tests

# run the stack (three terminals; Keycloak and SQL Server as before)
dotnet run --project backend/src/SecLab.Api            # http://127.0.0.1:5100 (launch profile sets the trusted proxy)
dotnet run --project backend/src/SecLab.Gateway        # https://localhost:5443  <- the only public port
bash docs/attack-scripts/14-edge-probes.sh
# earlier scripts still work, unchanged, because they already talk to :5443
```
Checklist:
- [ ] Gateway tests (30) and the complete backend suite green
- [ ] Script section 1: only `/api/**` (and avatars) answer; section 2: `401`; 3: `405/404`; 6: `413`; 7 with `Gateway__RateLimitPerMinute=20`: `429`s
- [ ] API audit log (step 12) shows the **real** client address, never the spoofed one from section 4
- [ ] `05-idor.sh`, `09-allowlists.sh` (except the direct-host cases), `11-error-probing.sh` still behave as before through the gateway
- [ ] `curl -H 'Host: localhost' http://<your LAN IP>:5100/…` from another machine does not connect (loopback binding) – bypass closed
- [ ] The SPA works end to end through `https://localhost:5443` (login, pages, avatars)

## Pitfalls
- **`X-Forwarded-For` "Append"** at the gateway keeps the attacker's fake value in front. Use *Set*. (The reference solution's tests fail if you switch it.)
- API trusts forwarded headers from everyone (empty proxy list = trust all), or trusts the whole private network instead of the one gateway.
- Forgetting the API's `Host` filtering: YARP does not forward the original `Host` unless told to; the API then sees the internal address and answers `400`.
- Blocking `/api/admin` with a case-sensitive or pre-normalisation check.
- Leaving the API reachable on `0.0.0.0` or in the same public network segment.
- Gateway passes internal error text upstream errors (`Connection refused (10.0.0.5:8080)`).
- Rate limiting only the successful path, or only the API: refused and unauthenticated requests are exactly the ones you want to count.
- Timeouts missing or higher than clients' patience; retries of non-idempotent requests.
- Publishing avatars/static content through an authenticated route and then "fixing" the images by weakening authentication.
- Treating the gateway as *the* security: every API rule must hold if the gateway is bypassed or misconfigured.
- Not testing the failure modes (API down, slow, oversized) – you only find out in production.

## Further reading
- YARP documentation – https://microsoft.github.io/reverse-proxy/ (Getting started, Configuration, Transforms, Request timeouts)
- Configure ASP.NET Core to work with proxy servers and load balancers – https://learn.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer
- Rate limiting middleware – https://learn.microsoft.com/aspnet/core/performance/rate-limit
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- Azure API Management and Azure Front Door WAF (Part 2, step P2-04)
- OWASP API Security Top 10 (API8 Security Misconfiguration, API4, API9); OWASP REST Security Cheat Sheet

Stuck or done? Compare with the solution: [`docs/solutions/14-api-gateway.md`](solutions/14-api-gateway.md) and `solutions/14-api-gateway.patch` (applies on top of 01–13).
