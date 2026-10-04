# 06 – Leveled API keys

> Prerequisites: steps 01–05 done (or apply patches `01`–`05`). Time: 2–3 hours. New table → `bash docs/reset-database.sh` after adding the model.

## Goal
Give **machines** (partner integrations, scripts, the "external" service) their own, revocable, least-privilege credential – separate from user logins.

Contract (the tests encode it):

**Key management – for signed-in users only (bearer token; a key can never mint or list keys)**

| Route | Behaviour |
|---|---|
| `POST /api/keys` `{ name, level, expiresInSeconds? }` | `level` ∈ `read`, `write`, `admin`. Unknown level or bad name → `400`. **`admin` keys only for Admin users** (`403` otherwise). Response `201`: `{ id, apiKey, prefix, level, expiresAt }` – **the only time the full key is ever shown.** |
| `GET /api/keys` | The caller's own keys: `id, name, prefix, level, createdAt, expiresAt, revokedAt, lastUsedAt`. Never the secret. |
| `DELETE /api/keys/{id}` | Revoke. Owner or Admin (`403`/`404` for others) → `204`. Takes effect immediately. |

**Partner API – for API keys only (header `X-Api-Key`)**

| Route | Minimum level |
|---|---|
| `GET /api/partner/blogs` | `read` |
| `POST /api/partner/blogs` `{ title, body }` | `write` – the blog's author is the **key's owner**, whatever the body says |
| `DELETE /api/partner/blogs/{id}` | `admin` |

Requirements:

1. **Format:** `sl_<prefix>_<secret>` – prefix = 8 alphanumerics (public, used to find the row), secret = **≥ 32 alphanumerics from a CSPRNG**.
2. **The secret is never stored** – no plaintext, no reversible encryption; only a one-way digest, and the tests scan *every text and binary column of every table* for it.
3. **Levels are ordered:** `admin` ⊃ `write` ⊃ `read`. A key that is authenticated but too weak gets `403`; a missing/invalid/revoked/expired key gets `401`.
4. Missing, malformed, unknown-prefix and wrong-secret keys are **indistinguishable** (same status, same body).
5. Keys are accepted **in the header only**, never in the URL.
6. **Credential types don't mix:** user bearer tokens are `401` on partner routes; API keys are `401` on every user route (including `/api/me`, `/api/keys`).
7. Keys can **expire** and be **revoked**; `lastUsedAt` is updated when a key is used.
8. A user cannot create a key more powerful than themselves.
9. Frontend: a small "API keys" panel on the profile page (create, list, revoke, one-time display of the new key).

Out of scope: rate limits per key (step 07), versioned URLs (08), audit logging (12).

## Threat / why
Sharing a user's password or long-lived token with a script gives it *everything the user can do*, forever, and you can't cut it off without locking the user out. Keys that are stored in plaintext leak wholesale with the database; keys accepted in URLs end up in logs, browser history and `Referer` headers; a `read` key that can quietly `DELETE` defeats its purpose.

```bash
bash docs/attack-scripts/06-api-key-attacks.sh      # API + Keycloak running; expects 200 403 403 401 401 401 401 403 204→401
```
The script also prints what the database holds for a key (a prefix and a digest – not the key).

## Concepts
- **API key vs. OAuth token.** Tokens (step 03) represent *a user's delegated authority*, are short-lived and issued by the IdP. API keys identify a *client application/integration*, are long-lived, and are issued and revoked by you. Use keys for simple server-to-server integrations; use OAuth client-credentials when you can afford an IdP for machines. **Never embed a key in a browser or mobile app** – anything shipped to a client is public.
- **Anatomy of a good key:** long random secret (entropy, not cleverness), an identifiable **prefix** (lets you look the row up without hashing every key, lets users tell keys apart, and lets secret-scanners such as GitHub's recognise leaks), no meaning encoded inside.
- **Storing keys.** Treat them like passwords, *but* they are high-entropy random strings, so a fast one-way hash (SHA-256/HMAC) is appropriate – slow password hashes exist to protect low-entropy human choices. Optional hardening: HMAC with a server-side secret ("pepper") kept outside the database. Show the key once; if it is lost, rotate.
- **Comparing secrets:** constant-time comparison (`CryptographicOperations.FixedTimeEquals`), and do comparable work whether or not the prefix exists.
- **Levels / scopes.** Encode *what a key may do*, not who it is. Keep the model small and ordered, or use named scopes (`blogs:read`, `blogs:write`) as soon as levels stop fitting. Check them in the **authorization layer** (policies), not inside handlers.
- **Least privilege & lifecycle:** minimal level, expiry, revocation, rotation (two keys valid during a switch-over), owner attribution, `lastUsedAt` to find dead keys.
- **Custom authentication in ASP.NET Core:** an `AuthenticationHandler<TOptions>` turns a request into a `ClaimsPrincipal` (or fails). Authorization policies can name the **authentication scheme(s)** they accept – that is how you keep credential types apart (a route that only accepts API keys, a default that only accepts JWT).
- **Transport:** headers only (URLs are logged everywhere), always over HTTPS (step 01).
- **401 vs 403:** "I don't know who you are / your credential is bad" vs "I know you and you may not".
- **Ties to later steps:** rate limits partitioned per key/level (07), keys carried through a gateway (14), secret-scanning and rotation runbooks (Part 2), key usage in the audit trail (12).

## Your turn
Tasks:
1. Model + table for keys (owner, prefix, digest, level, created, expires, revoked, last used).
2. Key generation and one-time display; management endpoints with the rules above.
3. An authentication handler for `X-Api-Key`, and one policy per level that uses *only* that scheme.
4. The partner endpoints, protected by level.
5. Frontend panel. Run the tests and the attack script.

<details><summary>Hint 1 – where to look</summary>

`Models/Models.cs` + `Data/AppDbContext.cs` (unique index on the prefix), a new `Authorization/` file for the handler and policies, `Program.cs` (authentication + authorization builders), a new endpoints file, `frontend/src/pages/Profile.tsx`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`RandomNumberGenerator.GetString(...)`, `SHA256.HashData`, `CryptographicOperations.FixedTimeEquals`; `AuthenticationHandler<AuthenticationSchemeOptions>` registered with `AddScheme<,>`; `AuthorizationPolicyBuilder.AddAuthenticationSchemes(...)` + `RequireAssertion(...)`; `AuthenticateResult.NoResult()` vs `Fail(...)`; `ExecuteUpdateAsync` for `lastUsedAt`; a regex source generator for strict key parsing.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Parse strictly first (regex) → look up by prefix → hash the presented secret and compare to the stored digest in constant time (against a dummy digest when nothing was found) → reject revoked/expired → build a principal with the owner's local user id and the key's level as claims. Levels are ranked; each policy says "authenticate with the API-key scheme, then require rank ≥ N". Routes carry the policy that matches their action; the default (JWT) policy never sees API keys.
</details>

## Verify
```bash
bash docs/reset-database.sh
dotnet test backend/SecLab.slnx --filter "Step=06"     # 11 tests
bash docs/attack-scripts/06-api-key-attacks.sh
```
Checklist:
- [ ] `Step=06` (11) green, steps 01–05 still green
- [ ] Attack script prints `200 403 403 401 401 401 401 403 204 401`, and the DB shows only prefix + digest
- [ ] `grep -rn "api_key\|apikey" backend/src` finds no query-string handling
- [ ] The key is not written to any log (check the console while creating and using one)
- [ ] The UI shows the full key once, then only `sl_<prefix>_…`

## Pitfalls
- Storing the key "encrypted" or "just in case" in plaintext for support. If you can read it, so can an attacker who gets the database.
- Looking the key up by comparing the whole string in SQL (timing and plaintext storage) instead of prefix lookup + constant-time digest comparison.
- Distinguishing "unknown prefix" from "wrong secret" in status or body.
- Reading the key from the query string "for convenience" – it lands in access logs and `Referer`.
- Accepting API keys on the same default scheme as user tokens, or letting a key call the key-management API (privilege escalation).
- Levels checked by string equality (`== "write"`) so `admin` keys fail write routes, or by string comparison so `"write" > "admin"` alphabetically.
- No expiry or revocation path; keys that outlive employees and projects.
- Returning the full key from list endpoints, or logging request headers.
- Updating `lastUsedAt` on every request (write amplification) – throttle it.
- Giving a key its owner's *full* rights: a key acts *as* the owner but is limited *by its level*.

## Further reading
- Custom authentication handlers – https://learn.microsoft.com/aspnet/core/security/authentication/
- Policy-based authorization (authentication schemes in policies) – https://learn.microsoft.com/aspnet/core/security/authorization/limitingidentitybyscheme
- .NET cryptography: hashing and random numbers – https://learn.microsoft.com/dotnet/standard/security/cryptography-model
- OWASP API Security Top 10 (API2 Broken Authentication, API5 BFLA); OWASP REST Security Cheat Sheet (API keys); GitHub secret scanning docs (why prefixes help)

Stuck or done? Compare with the solution: [`docs/solutions/06-api-keys.md`](solutions/06-api-keys.md) and `solutions/06-api-keys.patch` (applies on top of 01–05).
