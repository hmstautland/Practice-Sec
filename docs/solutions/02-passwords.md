# Solution – 02 Password storage and login hardening

> Spoiler. Try the step yourself first: [`../02-passwords.md`](../02-passwords.md). Reference patch: `solutions/02-passwords.patch`, cumulative – apply `01-https.patch` first, then `patch -p1 < solutions/02-passwords.patch`. Verified on a fresh database: `dotnet test` → all 10 tests (steps 01 + 02) green.

## Design decisions
- **Hasher:** `PasswordHasher<User>` from `Microsoft.Extensions.Identity.Core` (add the package). It emits Identity's v3 format (PBKDF2-HMAC-SHA512, random salt, iteration count embedded) and reports `SuccessRehashNeeded` when defaults change. Registered as a singleton.
- **Telling hashed from legacy:** an explicit `PasswordIsHashed` boolean. Guessing from the value's shape is fragile (a legacy plaintext could look like a hash). A row inserted by old code defaults to `false`, which is exactly what the legacy-upgrade test relies on.
- **Lockout:** `FailedLoginCount` + `LockoutEnd` on `User`; 5 failures → 5 minutes. Locked accounts answer with the *same* 401 as everything else.

## Code map
| File | Change |
|------|--------|
| `SecLab.Api.csproj` | `Microsoft.Extensions.Identity.Core` |
| `Models/Models.cs` | `PasswordIsHashed`, `FailedLoginCount`, `LockoutEnd` |
| `Program.cs` | `AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>()`; pass the hasher to `Seed.Run` |
| `Data/Seed.cs` | startup sweep hashes any row where `!PasswordIsHashed`; seed users are created hashed |
| `Endpoints/Api.cs` | new `register`; rewritten `login` |

## Login, step by step
```csharp
IResult Fail() => Results.Json(new { error = "Invalid username or password" }, statusCode: 401);

var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username);
if (user is null) { hasher.HashPassword(new User(), req.Password ?? ""); return Fail(); }  // equalise timing
if (user.LockoutEnd > DateTime.UtcNow) return Fail();

var ok = user.PasswordIsHashed
    ? hasher.VerifyHashedPassword(user, user.Password, supplied) != PasswordVerificationResult.Failed   // Success or SuccessRehashNeeded
    : CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(user.Password), Encoding.UTF8.GetBytes(supplied));

if (!ok) { if (++user.FailedLoginCount >= 5) { user.LockoutEnd = UtcNow.AddMinutes(5); user.FailedLoginCount = 0; }
           await db.SaveChangesAsync(); return Fail(); }

// success: upgrade legacy / re-hash if needed, reset counters, return a projection WITHOUT Password
```
The response is an anonymous object listing safe fields instead of the entity – "allow-list what you return" (this idea returns in step 10 as DTOs).

## Registration
Validation is hand-written and small on purpose; step 10 replaces it with a proper validation library. `Results.ValidationProblem` produces RFC 9457 `application/problem+json`, `Results.Conflict` the 409.

## Things this solution knowingly leaves open
- Lockout state is per account, in the database, single-node friendly; it is DoS-able (attacker can lock a victim) → step 07 rate limiting and step 04 passkeys.
- `GET /api/users/{id}` still serialises the whole entity including the hash and lockout fields → steps 05 and 10.
- The registration endpoint reveals whether a username exists (409) – a common, accepted trade-off; rate limit it.
- Tokens are still the user id → step 03.

## Operating note
Changing the schema requires `bash docs/reset-database.sh` (starter has no migrations; the database step introduces them).
