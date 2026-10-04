# Solution – 15 Database & SQL security

> Spoiler. Try the step yourself first: [`../15-database-security.md`](../15-database-security.md). Patch: `solutions/15-database-security.patch` (after 01–14; it includes the regenerated `packages.lock.json` for the API and the generated EF migration). New package: `Microsoft.EntityFrameworkCore.Design` 10.0.12 (design time only); local tool `dotnet-ef` 10.0.12 (`dotnet-tools.json`).

## What was verified
- **Red → green.** Starter + patches 01–14 (SQL Server 2022 container with the weak `sa` password, no `.env`): `Step=15` **14 of 17 red** (the 3 green cases are payloads that happen to match nothing even against the vulnerable query: `' OR '1'='1`, `" OR ""="` and the `COUNT(*)` one). With the patch, a fresh container started from the new compose file, `.env` from `init-secrets.sh`, `init-database.sh`: **17 of 17 green**.
- **Whole suite on the solution:** 185 API tests (168 earlier + 17) and 30 gateway tests, all green, with `.env` loaded, after the database had been created by the scripts (not by the tests).
- **Mutation checks** (each reverted afterwards):
  - concatenated `FromSqlRaw` written inline → **build error EF1003**; interpolated `FromSqlRaw($"…")` → **build error EF1002**; the same concatenation assigned to a local variable first → **no diagnostic at all** (the analyzers do not track the string) – hence the pitfall in the step;
  - `EF.Functions.Like(col, "%" + q + "%")` instead of `Contains` → the wildcard test goes red (`%` and `_` act as wildcards);
  - converters removed → the two data-at-rest tests go red;
  - `seclab_app` added to `db_owner` → the least-privilege tests go red (2);
  - `TrustServerCertificate=True` appended to the app connection string → the encryption test goes red.
- **Live:** API + gateway + Keycloak against the new container. `15-sql-attacks.sh`: sections 1–3 print `(nothing)`, `(nothing)`, `0`/`0`; 4 and 5 `Login failed for user 'sa'`; 6 shows `CfDJ8…` ciphertext for `Phone`/`Address` read with the app's own login. The same script on the starter showed all users' phone/address, `sa | 1`, the `sa` login, 20 vs 0 rows, a table dump as `sa`, and `/etc/passwd` read through `OPENROWSET`.
- `docs/reset-database.sh` (drop → logins/rights → migrations) verified, including recovery after a mutation run that had written plaintext rows.
- **Not verified:** the frontend in a browser (nothing changed there; the API contract is unchanged, covered by the tests); a restore of the Data Protection key ring from backup / key rotation; the pipeline in Part 2 (its CI example still uses `sa` with `TrustServerCertificate=True` and must be adapted: create the logins, run the migrations as the migrator, set both connection strings); behaviour on macOS/Windows Docker (bind-mounted key permissions); `dotnet ef migrations bundle`.

## Changes to the step's test contract (found while building the solution)
Five assertions in the shipped test could never pass on SQL Server 2022 and were corrected (the test was never run green before):
1. `CONNECTIONPROPERTY('encrypt_option')` is not a property SQL Server knows (it returns `NULL`); `sys.dm_exec_connections.encrypt_option` needs `VIEW SERVER PERFORMANCE STATE`, which the app must not have. The test now relies on the connection *opening* with `Encrypt=True` and certificate validation on, and checks the connection-string flags.
2. `SELECT … FROM master.sys.sql_logins` and `sys.dm_exec_sessions` **succeed** for any login (guest in `master`; sessions are filtered to your own). Replaced by `msdb.dbo.sysjobs` (denied) and `sys.dm_exec_connections` (denied).
3. `EXEC ('SELECT 1') AT [nowhere]` fails with 7202 for *everyone* (even `sa`); replaced by `sp_addlinkedserver` (denied).
4. `GRANT CONTROL … TO seclab_app` (to yourself) is a severity-10 no-op, not an error; replaced by `ALTER ROLE db_owner ADD MEMBER seclab_app`.
5. Error numbers 3701 (`DROP TABLE` without permission) and 300 (`VIEW SERVER … STATE denied`) were added to the allowed list.
Plus one strengthening: the `.editorconfig` test now also requires **EF1003** (concatenation – the form the starter used); EF1002 alone does not catch it.

## Infrastructure
- **`docs/init-secrets.sh`** (shipped with the step, not part of the patch): three 32-character CSPRNG passwords (all character classes), a self-signed certificate for `localhost`/`127.0.0.1` in `certs/sql/`, and `.env` with `MSSQL_SA_PASSWORD`, `SECLAB_APP_PASSWORD`, `SECLAB_MIGRATOR_PASSWORD` and the two connection strings. The strings contain `Encrypt=True;TrustServerCertificate=False;ServerCertificate=<path to server.crt>`: the client accepts exactly that certificate (pinning). Values are single-quoted so the file works for both `source` and docker compose.
- **`docker-compose.yml`**: `MSSQL_SA_PASSWORD: ${MSSQL_SA_PASSWORD}`, port published on `127.0.0.1` only, bind mounts for `infra/sql/mssql.conf` and the certificate/key (read-only), a health check.
- **`infra/sql/mssql.conf`**: `tlscert`, `tlskey`, `tlsprotocols = 1.2`, `forceencryption = 1` (the container log shows "successfully loaded for encryption"; `sys.dm_exec_connections.encrypt_option` is `TRUE` for an `sa` session; the "client that does not ask for encryption" case was not tested separately).
- **`infra/sql/init.sql`** (idempotent, `sqlcmd -v APP_PASSWORD=… MIGRATOR_PASSWORD=…`): creates `SecLab`, the logins (`CHECK_POLICY = ON`; re-running does `ALTER LOGIN … PASSWORD` = rotation), the users, `seclab_migrator` ∈ `db_ddladmin`, `db_datareader`, `db_datawriter` (DDL and the history table; not `db_owner`, no server role), and `GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::dbo TO seclab_app` – nothing else. Schema-level grant: tables added by later migrations are covered automatically.
- **`docs/init-database.sh`**: wait for the server → `init.sql` as `sa` → `dotnet tool restore` → `dotnet ef database update --connection "$ConnectionStrings__Migrator"`. **`docs/reset-database.sh`**: drop the database (as `sa`, password from `.env`), then run the setup script. Both accept `SQL_CONTAINER` (default `seclab-sql`).
- **`.editorconfig`**: `EF1002` and `EF1003` = `error`.
- Older material updated: step 06's attack script and step 02's manual SQL hint now use `seclab_app` from `.env`; the OWASP matrix rows A02/A04/A05 (A05 became *Mitigated*, evidence `Step=15`).

## API changes
- **`appsettings.json`**: the `ConnectionStrings` section is gone. `Program.cs` reads `ConnectionStrings:Default` from configuration only and throws a clear message when it is missing (the check is inside the `AddDbContext` callback so `dotnet ef` can still build the host).
- **Search**: `db.Blogs.Where(b => b.Title.Contains(q) || b.Body.Contains(q))`. EF translates it to a parameterised, case-insensitive `CHARINDEX`, so quotes, `%` and `_` are literal characters.
- **Migrations**: `Migrations/…_InitialCreate` (generated from the model as it is after steps 01–14) and the model snapshot. `Seed.Run` no longer calls `EnsureCreated`; it throws "apply the migrations" when `GetPendingMigrations()` is not empty and then seeds as before (with the app login: inserts only).
- **Encryption**: `Data/ColumnEncryption.cs` has an `EncryptedStringConverter` (`ValueConverter<string,string>`: `Protect` / `Unprotect`). `AppDbContext` takes `IDataProtectionProvider`, creates one protector for the versioned purpose `SecLab.Users.PersonalData.v1` and applies the converter to `User.Phone` and `User.Address`. `Program.cs`: `AddDataProtection().SetApplicationName("SecLab").PersistKeysToFileSystem(DataProtection:KeysPath ?? <LocalApplicationData>/SecLab/keys)`. Data Protection output is an authenticated, versioned payload with a random IV (AES-256-CBC + HMAC-SHA256 by default), so equal plaintexts give different ciphertexts and the stored value is much longer than the input. Every code path (`/api/me`, profile, seed, tests' `NewPerson`) goes through the entity and therefore through the converter; no endpoint code changed.
- The model (and therefore the converter's protector) is cached per `DbContext` type; fine here because every instance uses the same key ring. If you ever want different keys per tenant, do not capture a protector in the model.

## Run it
```bash
bash docs/init-secrets.sh
docker compose down -v            # once: the old volume holds the old sa password
docker compose up -d sqlserver
bash docs/init-database.sh
set -a; source .env; set +a       # in every shell that runs the API or the tests
dotnet test backend/SecLab.slnx
```

## Deliberately left open
- **Key ring unprotected at rest.** Data Protection keys are XML files in a local folder (readable by anyone with that account, and a lost folder means lost data). Production: a shared store plus `ProtectKeysWith…` (Key Vault key, certificate) – Part 2.
- **Lab TLS.** Self-signed certificate pinned by file, key file world-readable so the container user can read it (documented in the script), TLS 1.2 only. Production: a CA-issued certificate, rotation, key in a vault.
- **Secrets in a file.** `.env` is better than git, not as good as a vault or a managed identity (Part 2: Entra-only authentication, no passwords).
- **No re-encryption job** for existing plaintext rows (the lab resets the database). A real migration needs a restartable batch job and a dual-read period.
- **Phone/address cannot be searched or indexed** any more (intended). `Email`, `Bio` and blog content stay plaintext; `Email` would be the next candidate.
- **Migration identity runs on the developer's machine** with a password in `.env`; in production it belongs to the pipeline with its own secret (or a bundle run by the deployment identity).
- **App login can still read and change every row of every table in `dbo`** – an injection or bug in the API can therefore still read all personal data (the encryption here protects the *table*, not an API that decrypts for a bug). Narrower options: per-table grants, row-level security, separate schemas per trust zone, Always Encrypted.
- Server-level visibility is the SQL Server default: any login sees the login named `sa` in `master.sys.sql_logins` (no hash). Dev-mode Keycloak with `admin/admin` is untouched.
- No auditing of database access (SQL Server Audit, Defender for SQL – Part 2).
