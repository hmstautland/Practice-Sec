# 07 – Rate limiting

> Prerequisites: steps 01–06 done (or apply patches `01`–`06`). Time: 2 hours. No schema change.

## Goal
Bound how much any one caller can ask of the API, so that guessing, scraping and accidental loops cannot exhaust it – and make the limits fair, explainable and hard to dodge.

Configuration contract (the tests set these through environment variables, e.g. `RateLimiting__Anonymous=5`; all values are *requests per window*):

| Key | Default (production) | Applies to |
|---|---|---|
| `RateLimiting:WindowSeconds` | 60 | window length for all limits |
| `RateLimiting:Anonymous` | 20 | unauthenticated callers, **per client IP** (also requests with bad/unknown API keys) |
| `RateLimiting:User` | 120 | each signed-in user (per user, not per IP) |
| `RateLimiting:Login` | 5 | `/api/auth/login` and `/register`, **per client IP**, whatever username is tried – *in addition to* the general limits |
| `RateLimiting:ApiKeyRead` / `ApiKeyWrite` / `ApiKeyAdmin` | 60 / 300 / 1000 | each API key, by its level |

Requirements:

1. **Every** request is counted in exactly one general bucket: API key (if a valid key is presented) → signed-in user → client IP.
2. A rejected request gets **`429 Too Many Requests`**, a **`Retry-After`** header (whole seconds, ≥ 1, ≤ the window) and a JSON body with `status: 429`. Allowance returns when the window is over.
3. Buckets are **independent**: one user or one key using up its allowance doesn't affect another; authenticated users don't consume the anonymous bucket.
4. The client address is **not attacker-controlled**: `X-Forwarded-For` / `X-Real-IP` from an arbitrary client change nothing. Forwarded headers are honoured only from proxies listed in `Proxy:KnownProxies` (default: none).
5. Sensible for development: `appsettings.Development.json` relaxes the limits so normal work and the earlier steps' tests aren't throttled; the base `appsettings.json` holds production-like values.
6. The React client shows a friendly message on `429` using `Retry-After`.

Out of scope: distributed limiting across several instances (needs a shared store or the gateway – step 14), WAF-level limits (Part 2), logging/alerting on rejections (step 12).

## Threat / why
Without limits: password/credential-stuffing and API-key guessing run at network speed (step 02's lockout only protects accounts that exist and is itself a DoS lever), scrapers copy all data, a buggy client loop or a single heavy user starves everyone, and every request that reaches the database costs you money.

```bash
bash docs/attack-scripts/07-flood.sh       # start the API with RateLimiting__Anonymous=20 RateLimiting__Login=5 to see it quickly
```
It hammers the login endpoint (fixed username, then rotating usernames), tries to fake many clients with `X-Forwarded-For`, and shows what a rejection looks like.

## Concepts
- **What to limit and by what key.** The *key* (partition) defines fairness: IP for anonymous traffic, user id after login, API-key id for machines. Wrong keys either punish shared IPs (offices, mobile carriers) or let attackers rotate identities. Limit **credential endpoints** by IP *and* by account, because attackers rotate whichever you don't limit.
- **Algorithms.** *Fixed window* (simple, allows bursts at window edges), *sliding window* (smoother), *token bucket* (bursts up to a bucket size, refills steadily), *concurrency limiter* (bounds in-flight requests – protects slow endpoints). ASP.NET Core's `Microsoft.AspNetCore.RateLimiting` provides all four, plus **partitioned** limiters and named **policies** you attach to endpoints.
- **Global vs. endpoint limiters.** A global limiter sees every request; endpoint policies (`RequireRateLimiting`/`[EnableRateLimiting]`) add stricter rules to sensitive routes. Both must allow the request.
- **Pipeline order.** The limiter needs to know *who* is calling, so it sits after authentication – but before authorization and the endpoint, so rejected requests are cheap. API-key authentication in this app happens inside an authorization policy (too late); think about how to make the key's identity available earlier.
- **The 429 contract:** `429` + `Retry-After` (+ optionally `RateLimit-*` headers, IETF draft) tells well-behaved clients how to back off; don't leak internal keys or partition names in the body.
- **Client IP behind proxies.** Behind a load balancer/gateway, `RemoteIpAddress` is the proxy. `X-Forwarded-For` fixes that – *and* is trivially forged. The Forwarded Headers middleware must only trust configured proxies. Read what happens when the known-proxy lists are **empty**.
- **Memory & eviction.** Partitioned limiters keep state per key; idle partitions are evicted. Unbounded, attacker-chosen keys are a memory-exhaustion vector – choose keys you control (ip/user/key-id), not raw header values.
- **Multi-instance reality.** In-memory limits are per process. Two replicas double the allowance; use a shared limiter (Redis), a gateway (step 14) or the platform's WAF (Part 2).
- **Limits are a UX and a security control:** publish them, return the right headers, make them configurable per environment.

## Your turn
Tasks:
1. Bind the settings above from configuration (with the defaults).
2. Add a global partitioned limiter that picks the bucket as described; add the stricter login policy and attach it to the credential endpoints.
3. Produce the `429` response.
4. Make the API-key identity available to the limiter, and place the limiter correctly in the pipeline.
5. Handle forwarded headers safely and relax Development.
6. Update the client's error handling. Run the tests and the attack script.

<details><summary>Hint 1 – where to look</summary>

`Program.cs` (services + middleware order), a new `RateLimiting/` file, the `/auth` route group in `Endpoints/Api.cs`, both `appsettings*.json`, `frontend/src/api/client.ts`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`AddRateLimiter`, `RateLimiterOptions.GlobalLimiter` with `PartitionedRateLimiter.Create<HttpContext, string>`, `RateLimitPartition.GetFixedWindowLimiter`, `AddPolicy`, `RequireRateLimiting`, `OnRejected` with `MetadataName.RetryAfter`, `ProblemDetails` + `WriteAsJsonAsync`; `HttpContext.AuthenticateAsync(scheme)`; `ForwardedHeadersOptions.KnownProxies/KnownNetworks`, `UseForwardedHeaders`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One function `Classify(HttpContext) → (partitionKey, limit)` with three branches (key, user, ip). A tiny middleware before the limiter that authenticates the API-key scheme when the header is present and stashes the principal in `HttpContext.Items` (the authentication result is cached per request). Order: forwarded headers → … → authentication → key pre-authentication → limiter → authorization. Forwarded-header middleware only added when at least one proxy is configured.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=07"      # 6 tests; each starts a host with tiny limits via environment variables
RateLimiting__Anonymous=20 RateLimiting__Login=5 dotnet run --project backend/src/SecLab.Api   # then:
bash docs/attack-scripts/07-flood.sh
```
Checklist:
- [ ] `Step=07` (6) green; all earlier steps still green (the Development relaxation matters)
- [ ] Attack script: login guessing turns into `429` after the 5th try, also with rotating usernames; `X-Forwarded-For` gives no extra allowance
- [ ] A `429` carries `Retry-After` and `application/problem+json`
- [ ] `RateLimiting__Anonymous=5` makes a normal browser session hit the limit → the UI shows the friendly message
- [ ] Nothing in the code reads `X-Forwarded-For` directly

## Pitfalls
- **Empty `KnownProxies` *and* `KnownNetworks` means "trust everyone"** in the forwarded-headers middleware – clearing both lists is *not* "trust nobody". (This bit the reference solution during authoring; a test caught it.)
- Partitioning by a header value, username or any other client-chosen string without bounds.
- Placing the limiter before authentication (everyone becomes "anonymous") or after authorization/endpoint execution (rejections are expensive).
- One shared bucket for login *and* everything else, or per-account only: attackers rotate usernames (credential stuffing); per-IP only: attackers rotate IPs. Use both (step 02 lockout + this step).
- Forgetting that requests rejected as `401` still cost you – count them.
- Fixed-window edge effect: 2× the limit across a window boundary. Use sliding/token bucket when that matters.
- Very short windows in tests → flaky; big windows and tiny limits → deterministic.
- Returning `503` or closing the connection instead of `429` + `Retry-After`; clients then retry immediately.
- Limits in dev that hide problems in prod (or the other way round): keep a documented set for each environment.

## Further reading
- Rate limiting middleware in ASP.NET Core – https://learn.microsoft.com/aspnet/core/performance/rate-limit
- Configure ASP.NET Core to work with proxy servers and load balancers – https://learn.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer
- .NET rate-limiting primitives (`System.Threading.RateLimiting`) – https://learn.microsoft.com/dotnet/api/system.threading.ratelimiting
- OWASP API Security Top 10 (API4 Unrestricted Resource Consumption, API6 Sensitive Business Flows); OWASP Denial of Service and Credential Stuffing Prevention Cheat Sheets; RFC 6585 (429)

Stuck or done? Compare with the solution: [`docs/solutions/07-rate-limiting.md`](solutions/07-rate-limiting.md) and `solutions/07-rate-limiting.patch` (applies on top of 01–06).
