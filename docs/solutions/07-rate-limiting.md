# Solution – 07 Rate limiting

> Spoiler. Try the step yourself first: [`../07-rate-limiting.md`](../07-rate-limiting.md). Patch: `solutions/07-rate-limiting.patch` (after 01–06).

## What was verified
- **69 tests** (steps 01–07) pass on a fresh database.
- The forwarded-header test **failed on the first attempt** (see below) – it found a real bug in the first draft of this solution.
- Live: with `RateLimiting__Anonymous=20 RateLimiting__Login=5`, `07-flood.sh` produced `401 ×5` then `429 …` for guessing, `429` for rotating usernames, and a `429` with `Retry-After: 60` and `application/problem+json`. (Section 3 needs the window to reset first; the script now waits.)
- **Not verified:** behaviour with `Proxy:KnownProxies` configured (no proxy in this setup – exercised in step 14 with the gateway); multi-instance behaviour.

## Structure (`RateLimiting/RateLimiting.cs`)
`RateLimitSettings` is bound from `RateLimiting` (defaults in the class, production-like values in `appsettings.json`, relaxed ones in `appsettings.Development.json`).

**Global limiter** – one function decides the bucket:
```csharp
if (ctx.Items[ApiKeyItem] is ClaimsPrincipal key)   → "key:<id>",  limit by level (read/write/admin)
if (ctx.User.Identity?.IsAuthenticated == true)     → "user:<local id>", limit s.User
else                                                → "ip:<RemoteIpAddress or 'unknown'>", limit s.Anonymous
```
Keys are things the server controls (ids, IPs), never raw client strings. Fixed window, `QueueLimit = 0`, auto-replenish.

**Login policy** – `AddPolicy("login", ctx => fixed window per IP, limit s.Login)`, attached to the whole `/auth` group with `.RequireRateLimiting("login")`. It runs *in addition to* the global limiter.

**Rejection** – `OnRejected` writes `429`, `Retry-After` (from the lease metadata, min 1) and an `application/problem+json` body.

**API key identity before the limiter** – the API-key scheme is normally authenticated by the authorization policy, which runs after the limiter. `UseApiKeyPreAuthentication` calls `HttpContext.AuthenticateAsync("ApiKey")` early when the header is present and stores the principal in `Items`. `AuthenticateAsync` results are cached per request by the handler, so the later policy check does not repeat the database lookup.

**Pipeline order**
```
UseSecLabForwardedHeaders → DeveloperExceptionPage → HSTS → HttpsRedirection → CORS
→ UseAuthentication → UseApiKeyPreAuthentication → UseRateLimiter → UseAuthorization → endpoints
```

## The bug the test found
First draft: `KnownNetworks.Clear(); KnownProxies.Clear();` and `app.UseForwardedHeaders()` always. In `ForwardedHeadersMiddleware` the known-proxy check is applied **only if at least one of the lists is non-empty**; with both empty every sender is trusted. Rotating `X-Forwarded-For` therefore produced a fresh "IP" (and a fresh bucket) per request. Fix: enable the middleware only when `Proxy:KnownProxies` contains at least one address; otherwise forwarded headers are ignored and the connection's remote address is used.

## Test-infrastructure notes
- `TestIdp.CreateClient` now caches **one host per `TestIdp`** (i.e. per test), so several clients in a test share limiter state – required to test "user A doesn't affect user B".
- `EnvScope` sets `RateLimiting__*` environment variables before the host is built; big windows (600 s) and tiny limits make the tests deterministic, except `The_allowance_returns_when_the_window_is_over` which uses a 2-second window and waits 2.5 s.
- `TestServer` has no remote IP, so all anonymous test traffic falls into the `ip:unknown` bucket – which is exactly what the anonymous tests need.

## Deliberately left open
- In-process state: N replicas ⇒ N× the allowance. Step 14 (gateway) and Part 2 (Front Door WAF) add shared layers.
- Fixed windows allow a 2× burst at a boundary; switch the partition factory to `GetSlidingWindowLimiter`/`GetTokenBucketLimiter` if that matters.
- No `RateLimit-*` informational headers, no metrics/logs for rejections (step 12).
- Per-account login limiting is provided by step 02's lockout; a combined per-IP+per-account policy could replace both.
