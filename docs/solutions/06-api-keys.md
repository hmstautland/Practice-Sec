# Solution – 06 Leveled API keys

> Spoiler. Try the step yourself first: [`../06-api-keys.md`](../06-api-keys.md). Patch: `solutions/06-api-keys.patch` (after 01–05). New table → `bash docs/reset-database.sh`.

## What was verified
- **63 tests** (steps 01–06) pass on a fresh database.
- **Mutation check:** replacing the digest comparison with `true` made the "wrong secret" test fail (the tests do catch that mistake).
- Live `06-api-key-attacks.sh` against real Keycloak tokens printed exactly the expected `200 403 403 401 401 401 401 403 204→401`; the database rows contain only prefix, a 32-byte digest and the level.
- Frontend builds; UI not click-tested.

## Data
`ApiKey { Id, OwnerId, Name, Prefix (unique), KeyHash (32 bytes), Level, CreatedAt, ExpiresAt?, RevokedAt?, LastUsedAt? }`.

## Key format and generation
```csharp
var prefix = RandomNumberGenerator.GetString(Alphabet, 8);    // public
var secret = RandomNumberGenerator.GetString(Alphabet, 40);   // 62^40 ≈ 2^238
var hash   = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
// returned once: $"sl_{prefix}_{secret}"
```
A single unsalted SHA-256 is appropriate *because* the secret is 238 random bits: there is nothing to brute-force and no rainbow table can exist. (For human passwords it would be wrong – see step 02.) An HMAC with a pepper from Key Vault would be an extra layer (Part 2).

## Authentication handler (`Authorization/ApiKeyAuthentication.cs`)
1. No header (or several) → `NoResult()` → the challenge yields `401`.
2. Strict regex `^sl_[A-Za-z0-9]{8}_[A-Za-z0-9]{32,128}$` → anything else is `Fail` (same `401`).
3. Lookup by prefix (`AsNoTracking`), then `FixedTimeEquals(hash(presented), stored ?? new byte[32])` – comparison happens even when the prefix is unknown.
4. Reject revoked and expired keys.
5. Throttled `lastUsedAt` update (`ExecuteUpdateAsync`, at most once a minute per key).
6. Principal: `local_user_id` (the owner), `api_level`, `api_key_id`. Because it carries `local_user_id`, the same resource-based code from step 05 can be reused.

All failures return the same empty `401`, so nothing tells an attacker whether a prefix exists (the small timing difference of a DB miss is accepted: the prefix is not secret).

## Levels as policies
```csharp
foreach (var level in ["read", "write", "admin"])
    builder.AddPolicy("ApiKey:" + level, p => p
        .AddAuthenticationSchemes("ApiKey")             // ONLY this scheme authenticates these routes
        .RequireAuthenticatedUser()
        .RequireAssertion(ctx => Rank(ctx.User.FindFirst("api_level")?.Value) >= Rank(level)));
```
`Rank` is the index in the ordered list, so the comparison is numeric, never alphabetical. Routes: `GET /partner/blogs` → `ApiKey:read`, `POST` → `ApiKey:write`, `DELETE` → `ApiKey:admin`.

**Credential separation comes from schemes:** the default scheme is JWT bearer (so keys are unknown to every user route and hit the fallback policy → `401`), and partner routes name only the API-key scheme (so a bearer token finds no key → `401`).

## Management endpoints
`POST /api/keys` validates name/level/expiry (`ValidationProblem` → 400), refuses `admin` unless the caller `IsInRole("Admin")`, generates the key, stores the digest. `GET` filters by owner. `DELETE` sets `RevokedAt` (idempotent) for owner or Admin, so history is kept.

## Deliberately left open
- No per-key rate limits or quotas (step 07); no key rotation helper or "rotate" endpoint.
- `lastUsedAt` is the only usage record; per-request audit events come in step 12.
- Levels are coarse; move to named scopes when needed.
- The partner routes are unversioned (step 08 moves them under `/api/v1`).
- Secret scanning, pepper in Key Vault, key expiry policy → Part 2.
