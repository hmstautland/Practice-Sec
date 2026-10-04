# 02 – Password storage and login hardening

> Prerequisites: step 01 done (or apply `solutions/01-https.patch`). Time: ~1 hour.
> **Schema change ahead:** the starter has no migrations (`EnsureCreated` never alters an existing database). After you add columns, run `bash docs/reset-database.sh` and restart the API – it re-creates and re-seeds the database.

## Goal
Make a stolen database, a curious admin, or a brute-force script much less useful to an attacker.

Acceptance criteria:

1. **No plaintext passwords at rest.** The `Users.Password` column (keep this name) only ever holds a salted, deliberately slow hash produced by a vetted library – never your own crypto. This includes the seed data and rows that already exist.
2. **Existing users keep working.** `alice` / `password123` still logs in. Rows that are still plaintext (e.g. created by an older version of the app) are upgraded after a successful login, and none remain after startup.
3. **`POST /api/auth/register`** accepts `{ username, password, displayName, email }`.
   - Success → `201`. Invalid input → `400` with a problem-details style body (username 3–32 chars of letters/digits/underscore, password **≥ 12 characters**, e-mail contains `@`). Duplicate username → `409`.
4. **Login never reveals more than necessary:** an unknown user and a wrong password produce the **same status and same body**, take roughly the same time, and the response never contains the password or its hash.
5. **Lockout:** after **5 consecutive failures** an account rejects logins – even with the right password – for a cool-down period (your choice, minutes).
6. Sessions/tokens are **out of scope** here (step 03); the "token" may stay the user id for now. Also out of scope: `GET /api/users/{id}` still returns the whole entity (fixed in steps 05/10).

## Threat / why
Databases leak (SQL injection – step 15, backups, misconfigured storage, insider access). With the starter, one leak equals every user's password – and people reuse passwords elsewhere.

```bash
# needs the API running
curl -s http://localhost:5080/api/users/2 | jq .password        # "password123"

# and nothing slows a guessing attack down:
for p in 123456 password qwerty password123; do
  curl -s -o /dev/null -w "$p -> %{http_code}\n" -X POST http://localhost:5080/api/auth/login \
    -H 'Content-Type: application/json' -d "{\"username\":\"alice\",\"password\":\"$p\"}"
done
```
(Also run `bash docs/attack-scripts/00-baseline.sh` and look at the W2/W12 lines.)

## Concepts
- **Hashing is not encryption and not "fast hashing".** SHA-256 can be computed billions of times per second on a GPU. Password hashing functions (PBKDF2, bcrypt, scrypt, **Argon2**) are *intentionally* expensive and take a per-password random **salt**, so identical passwords hash differently and rainbow tables are useless. Compare with OWASP's current recommended parameters.
- **Don't write your own.** .NET ships PBKDF2 (`Rfc2898DeriveBytes`) and ASP.NET Core Identity ships a well-reviewed `IPasswordHasher<TUser>` that embeds algorithm, iteration count, salt and hash in one string and can tell you when a stored hash should be **re-hashed** because parameters have moved on. It is available without adopting the whole Identity UI/schema – look for the smallest NuGet package that contains it.
- **Migrating legacy data.** You can't reverse a hash, so plaintext rows can only be converted when you know the plaintext (at login) or by hashing the stored value itself (a startup sweep). You need a reliable way to tell "hashed" from "not yet hashed" – guessing from the string's shape is fragile.
- **Enumeration & timing.** Different messages/status codes/response times for "no such user" vs "wrong password" let an attacker harvest valid usernames. Equalise all three.
- **Constant-time comparison** (`CryptographicOperations.FixedTimeEquals`) whenever you compare secrets yourself.
- **Throttling vs lockout.** Lockout stops online guessing against one account but lets an attacker lock *victims* out (denial of service) and can itself leak which accounts exist if it answers differently. Step 07 adds IP/user rate limiting; step 04 removes passwords for the strongest accounts.
- **Password policy (NIST SP 800-63B):** length over composition rules, allow long passphrases, check against breached-password lists, don't force periodic rotation.
- **Logs and errors** must never contain passwords (step 11).

## Your turn
Tasks:
1. Decide how the app tells hashed rows from legacy rows, and add whatever columns lockout needs.
2. Introduce a password hasher via dependency injection; hash in seed data and registration.
3. Implement `register`, then rework `login` (verification, upgrade path, uniform failures, lockout, safe response).
4. Add the startup sweep for remaining legacy rows.
5. Run the tests; then repeat the guessing loop above and watch it stop working.

<details><summary>Hint 1 – where to look</summary>

`Endpoints/Api.cs` (auth section), `Models/Models.cs` (`User`), `Data/Seed.cs`, `Program.cs` (service registration).
</details>

<details><summary>Hint 2 – which APIs</summary>

`Microsoft.AspNetCore.Identity.IPasswordHasher<TUser>` / `PasswordHasher<TUser>` from the `Microsoft.Extensions.Identity.Core` package: `HashPassword`, `VerifyHashedPassword` and its `PasswordVerificationResult` (three outcomes!). `Results.ValidationProblem` for 400s, `Results.Conflict` for 409, `CryptographicOperations.FixedTimeEquals` for the legacy comparison.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Three new columns on `User` (a "is hashed" flag, a failure counter, a lockout end time). Login: load user → if none, do throw-away hashing work and fail → if locked, fail the same way → verify (hashed or legacy path) → on failure count/lock and fail the same way → on success upgrade/re-hash, reset counters, return a projection of the user that omits the password. One private `Fail()` helper keeps every failure identical.
</details>

## Verify
```bash
bash docs/reset-database.sh                    # after the schema change
dotnet test backend/SecLab.slnx --filter "Step=02"
```
7 tests: hash at rest, weak password rejected, login works and leaks nothing, seeded users still work, legacy upgrade, indistinguishable failures, lockout. (On the starter 6 of them are red; the seeded-login test is a regression guard and is already green.)

Manual: run the guessing loop from the Threat section – after 5 wrong attempts even the right password fails. Look at the table: `docker exec -it seclab-sql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P 'Passw0rd!Passw0rd' -d SecLab -Q "select Username, Password from Users"`.

Checklist:
- [ ] `Step=02` tests green, and `Step=01` still green
- [ ] No plaintext in `Users.Password` (including seeded users)
- [ ] Login response contains no password/hash
- [ ] The frontend login (`alice` / `password123`) still works

## Pitfalls
- Hashing inside `Where(...)` / on the DB side: hash *in memory*, then store.
- Treating `SuccessRehashNeeded` as a failure (it means "correct, but re-hash now").
- Returning `423 Locked` / a different message only for real accounts turns lockout into a username oracle.
- Skipping the dummy hash for unknown users leaves a measurable timing difference.
- Locking on IP alone punishes shared networks; locking on username alone enables lock-out attacks – real systems combine both plus captcha/backoff.
- A plaintext-to-hash upgrade that only happens on login leaves dormant users exposed; sweep at startup.
- Don't log the request body of `/auth/*`.
- The hash itself is still readable by anyone who can call `GET /api/users/{id}` today – that hole is closed in steps 05 and 10.

## Further reading
- ASP.NET Core Identity password hashing – https://learn.microsoft.com/aspnet/core/security/authentication/identity
- Cryptography model in .NET – https://learn.microsoft.com/dotnet/standard/security/cryptography-model
- OWASP Password Storage Cheat Sheet, Authentication Cheat Sheet
- NIST SP 800-63B (Digital Identity Guidelines)

Stuck or done? Compare with the solution: [`docs/solutions/02-passwords.md`](solutions/02-passwords.md) and `solutions/02-passwords.patch` (applies on top of step 01).
