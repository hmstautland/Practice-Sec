# 15 – Database & SQL security

> Prerequisites: steps 01–14 done (or apply patches `01`–`14`). Time: 4–5 hours. **Schema/infrastructure change:** the container is re-created, the database is re-created (`reset-database.sh`), and from now on the tests and the API need the secrets in `.env` (see *Verify*). Docker and the .NET 10 SDK as before; no Keycloak needed for the tests (they use an in-process IdP).

## Goal
Make the data layer survive two kinds of bad day: **a bug lets an attacker run SQL** (injection), and **someone gets read access to the database** (a leaked backup, a stolen credential, a curious colleague). Limit what the first can do, make the second useless, and stop the whole thing from sitting on a committed password.

Acceptance criteria (the tests in `backend/tests/SecLab.Api.Tests/Step15DatabaseTests.cs` encode them):

**1. No SQL injection**
1. `GET /api/blogs/search?q=…` treats `q` purely as data. Classic payloads (`' OR 1=1 --`, `UNION SELECT …`, stacked statements, comment tricks, `WAITFOR`) match nothing, return `200`, take no time, change nothing.
2. Ordinary searches keep working, including titles with `'`, and **`%` and `_` in the search term are literal characters**, not wildcards (searching for `%` finds only posts that contain a percent sign).
3. Raw SQL built from strings is a **build error** from now on: `.editorconfig` at the repository root makes the EF Core analyzer rules for *interpolated* (`EF1002`) and *concatenated* (`EF1003`) strings in `FromSqlRaw`/`ExecuteSqlRaw` errors.

**2. Who the application connects as**
4. The API connects with a dedicated SQL login **`seclab_app`** (never `sa`, never Windows/integrated auth): it can read, insert, update and delete rows in the application schema – and **cannot** create/alter/drop/truncate tables, create logins or users, change roles, read other databases or server state, run `sp_configure`/`xp_cmdshell`, or take backups.
5. Schema changes belong to a second login **`seclab_migrator`** (can change the schema, is not a server administrator). The running API does not use it. Schema is created by **EF Core migrations** applied with that login – `EnsureCreated()` is gone.

**3. Transport and secrets**
6. Both connection strings use **`Encrypt=True`** and **do not** set `TrustServerCertificate=True`: the server presents a certificate that the client really validates (the lab uses a self-signed certificate that the client is told to expect), and the server insists on encryption.
7. **No database password is committed**: not in `appsettings*.json`, not in `docker-compose.yml`, not in `docs/reset-database.sh`. Secrets come from a git-ignored `.env` (the repository ships `.env.example` and `docs/init-secrets.sh`, which generates strong random values).

**4. Data at rest**
8. `Users.Phone` and `Users.Address` are **encrypted in the database**: a plain `SELECT` returns an opaque value that is longer than the plaintext, nobody can find the plaintext anywhere in the database, and **equal plaintexts give different ciphertexts**. The API (owner view) still shows the plaintext – the encryption is transparent to the rest of the code. The key is **not** stored in the database.

Out of scope here (see *Further reading*): schemas per trust zone, row-level security, ledger tables, Always Encrypted, Entra-only authentication in Azure (Part 2), encrypting backups, searching in encrypted columns.

## Threat / why
The starter has three separate problems that multiply each other: the search endpoint **concatenates** user input into SQL; the app logs in as **`sa`** (the server administrator) with a **password that is committed to git**; and personal data sits in the table as **plaintext**. One injection string therefore reads every user's contact data, lists server logins, and with a different payload could drop tables or – as `sa` – read files from the server's operating system. Nothing in the path was encrypted or verified either.

```bash
bash docs/attack-scripts/15-sql-attacks.sh      # API + gateway + Keycloak + SQL Server running
```
On the starter you will see: (1) every user's phone and address through a `UNION` in the search box, (2) the app identity `sa` with `sysadmin = 1`, and the server's logins, (3) a yes/no oracle (20 rows vs 0), (4) a login as `sa` with the committed password that dumps the table, (5) a file read from the server's operating system. After your fixes: nothing, nothing, `0` and `0`, `Login failed`, `Login failed`, and (6) ciphertext when the table is read with the app's own credentials.

## Concepts
- **Injection is a *parsing* bug, not a *filtering* bug.** The fix is to keep code and data in separate channels: *parameters*. The database receives the statement text and the values separately, so a value can never change the statement. Escaping and blocklists try to repair the mixture afterwards and fail at the edges (encodings, comments, second-order cases). Input validation (step 10) is defence in depth, not the fix.
- **EF Core and parameters.** LINQ always parameterises. `FromSql`/`ExecuteSql` (and the `…Interpolated` forms) turn C# interpolation holes into parameters; the `…Raw` forms take your string as-is. Use raw SQL only for what LINQ cannot say, never with string-building. Dynamic *identifiers* (column names, `ORDER BY`) cannot be parameters: map them from an allow-list.
- **Analyzers as guard rails.** Roslyn analyzers ship with EF Core. Severity is configured in `.editorconfig` (`dotnet_diagnostic.<ID>.severity`). A rule that is only a warning gets ignored; as an error it is a build break. Know what a rule does **not** see: the analyzers look at the expression passed to the method; a string assembled in a variable beforehand is invisible to them. (Try it.)
- **`LIKE` has a mini-language.** `%`, `_` and `[` are special *inside* the parameter value. Parameterising stops injection but not "my search for `%` returns everything". Either use a translation that escapes for you or escape explicitly and tell the database the escape character.
- **Least privilege, twice.** SQL Server separates *server-level* principals (logins, roles like `sysadmin`) from *database-level* principals (users, roles like `db_owner`, `db_datareader`, `db_ddladmin`) and lets you grant on object, schema or database. A web app needs row operations on its tables – not DDL, not server state, not other databases. Granting at **schema** level keeps new tables covered without ever handing out ownership. A separate **migration identity** with DDL rights is used only while deploying; if the app is compromised, the attacker cannot reshape or drop the schema, and a compromised pipeline cannot read production data it has no reason to read.
- **Blast radius.** Assume injection will happen once. What the login can do decides whether it is "a bad day" or "game over". `sa` can read the operating system of the server; a schema-limited login can only touch what the application can already touch.
- **Transport encryption has two halves:** *encrypt* (confidentiality) and *validate the certificate* (you are talking to the real server). `TrustServerCertificate=True` keeps the first and throws away the second – a man-in-the-middle presents any certificate. Microsoft.Data.SqlClient 4.0+ defaults to `Encrypt=True`, which is why "fixing" certificate errors by trusting everything is so common. In SQL Server on Linux you provide the certificate and key and set the network options in `mssql.conf` (`tlscert`, `tlskey`, `tlsprotocols`, `forceencryption`). The client can validate against the system trust store, or – in a lab with a self-signed certificate – be told which certificate to expect (see the `ServerCertificate` connection-string keyword). In production: a certificate from a CA the client trusts.
- **Secrets management.** Order of preference: no secret (managed identity, Part 2) → secret in a vault → secret in the environment injected at deploy time → secret in a git-ignored local file for development. Never in the repository, never in an image. ASP.NET Core configuration layers (`appsettings.json` < environment variables < command line; `ConnectionStrings__Default` maps to `ConnectionStrings:Default`) make the switch free. Generate secrets with a CSPRNG and make them long; rotate by changing the value and the login together.
- **Migrations.** Code-first schema history (`Migrations/` + the `__EFMigrationsHistory` table) replaces "create if missing". `dotnet ef migrations add` generates a migration from the model diff; `dotnet ef database update` applies it with whatever connection you give it. Review every generated migration: it is code that will run with schema-owner rights. The app should *check* that migrations are applied, not *apply* them with elevated rights at start-up (in production use a bundle or a pipeline step).
- **Encryption at rest, at three levels.** *Disk/TDE* protects stolen files, not a query. *Column encryption in the application* (this step) protects against anyone who reads the table – DBAs, backups, replicas, an injection – because the key lives elsewhere. *Always Encrypted* moves the key handling into the driver. Trade-offs of application-level encryption: you can no longer filter, sort or index on the column; deterministic encryption would allow equality search but leaks which rows are equal (the test demands the opposite: randomised); the key becomes the crown jewel.
- **Use a vetted library, not your own mode of operation.** ASP.NET Core **Data Protection** gives authenticated encryption (AES + HMAC by default), a random IV per call, versioned payloads, key rotation, and *purposes* (one protector per use; a ciphertext from one purpose cannot be opened with another). Alternative building block: `System.Security.Cryptography.AesGcm` (you manage nonce, key storage, rotation and format yourself). EF Core **value converters** apply a conversion at the model boundary, so queries and entities stay unchanged.
- **Key management is the real problem.** Where does the key ring live, who can read it, how is it backed up, what happens when it is lost (the data is gone) or leaked? Keys next to the database defeat the purpose; the lab stores them in a local folder; production uses a vault.

## Your turn
Tasks (do them in this order; each one makes more tests green):
1. **Secrets.** Run `bash docs/init-secrets.sh` (creates `.env`, strong passwords, a certificate in `certs/sql/`, and two connection strings). Make `docker-compose.yml`, `appsettings.json` and `docs/reset-database.sh` stop containing any password. Do **not** load `.env` into your shell yet.
2. **Server side.** Make the SQL Server container require TLS with that certificate and publish its port on loopback only. Re-create it (`docker compose down -v` – an existing data volume keeps the *old* `sa` password).
3. **Identities.** Write an idempotent SQL script (`infra/sql/init.sql`) run as `sa` that creates the database, the logins `seclab_app` and `seclab_migrator` (passwords from `.env`), their database users, and exactly the rights described above. Wrap the two scripts you need (setup, reset) so the steps are repeatable.
4. **Migrations.** Add the EF tooling, create an initial migration for the current model, remove `EnsureCreated`, make start-up fail with a clear message when migrations are pending, and apply migrations with `seclab_migrator`.
5. **Search.** Make the query parameterised and wildcard-safe.
6. **Guard rail.** Add the repository-level `.editorconfig`.
7. **Column encryption.** Encrypt phone and address transparently; keep the key out of the database.
8. Load `.env`, reset the database, run the tests, the attack script, and then try to break your own work (see *Verify*).

<details><summary>Hint 1 – where to look</summary>

`docker-compose.yml`, `backend/src/SecLab.Api/appsettings.json`, `docs/reset-database.sh`, `.env.example`; `Data/Seed.cs` (`EnsureCreated`), `Data/AppDbContext.cs`, `Endpoints/Api.cs` (search), `Program.cs` (`AddDbContext`); the test file shows the exact environment variable names it reads and what each login must (not) be able to do. Look at what `docs/init-secrets.sh` writes.
</details>

<details><summary>Hint 2 – which APIs</summary>

- Compose: `${VAR}` interpolation from `.env`; bind-mounting files into the container; `ports: "127.0.0.1:…"`. SQL Server on Linux: `mssql.conf` `[network]` options `tlscert`, `tlskey`, `tlsprotocols`, `forceencryption`; the files must be readable by the container user.
- Client: connection-string keywords `Encrypt`, `TrustServerCertificate`, `ServerCertificate` (Microsoft.Data.SqlClient 6.1+; look at the generated strings).
- T-SQL: `CREATE LOGIN … WITH PASSWORD`, `CREATE USER … FOR LOGIN`, fixed database roles (`db_ddladmin`, `db_datareader`, `db_datawriter`), `GRANT … ON SCHEMA::dbo`; `sqlcmd -v NAME=value` and `$(NAME)` for script variables; `IF SUSER_ID(…) IS NULL` for idempotency.
- EF Core: NuGet `Microsoft.EntityFrameworkCore.Design` (`PrivateAssets="all"`), a **local tool manifest** for `dotnet-ef` (`dotnet new tool-manifest`, `dotnet tool install dotnet-ef`), `dotnet ef migrations add`, `dotnet ef database update --connection`, `Database.GetPendingMigrations()`.
- LINQ string methods (`Contains`) vs. `EF.Functions.Like` with an escape character. `dotnet_diagnostic.EF100x.severity` in `.editorconfig`.
- `AddDataProtection()` (`SetApplicationName`, `PersistKeysToFileSystem`), `IDataProtectionProvider.CreateProtector(purpose)`, `Protect`/`Unprotect`, `ValueConverter<string,string>`, `PropertyBuilder.HasConversion`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

- One SQL script, three blocks: server level (database + two logins; on re-run `ALTER LOGIN` rotates the password), database level (two users), permissions (the migrator gets DDL plus read/write for the history table; the app gets the four row operations on the whole `dbo` schema and nothing else).
- A setup script waits for the server, runs the SQL script as `sa`, then runs the migrations with the migrator connection string. The reset script drops the database and calls the setup script.
- The `DbContext` receives `IDataProtectionProvider`, builds *one* protector with a versioned purpose string, and gives both properties the same converter. Remember what a converter does to rows written before you added it.
- The key ring folder comes from configuration, with a default outside the repository.
- Start-up reads the connection string from configuration only; no fallback value in code.
</details>

## Verify
```bash
# the starter is red on purpose (without .env: the app is still 'sa', nothing is encrypted). NOTE: the stacked-statement
# payload really runs against the starter's raw SQL and can drop the Blogs table - run `bash docs/reset-database.sh` after the red run.
dotnet test backend/SecLab.slnx --filter "Step=15"       # 17 test cases

# after your changes: load the secrets into this shell, (re)create the database, run
set -a; source .env; set +a
bash docs/reset-database.sh                              # drop, logins + rights, migrations
dotnet test backend/SecLab.slnx --filter "Step=15"
dotnet test backend/SecLab.slnx                          # everything: earlier steps still green, incl. the gateway tests

# live stack: set -a; source .env; set +a  in every terminal that starts the API
dotnet run --project backend/src/SecLab.Api              # (see step 14's launch profile and gateway)
bash docs/attack-scripts/15-sql-attacks.sh
```
Checklist:
- [ ] `Step=15` green (17) and the complete backend suite green with `.env` loaded
- [ ] `15-sql-attacks.sh`: sections 1–3 print nothing / `0` / `0`; sections 4–5 `Login failed`; section 6 shows ciphertext
- [ ] `grep -rIn "Passw0rd" . --exclude-dir={bin,obj,node_modules}` finds the old password only where it is *meant* to appear (this step's attack script, which shows the old attack; the Part 2 CI example, which uses its own throw-away value) – not in config, compose, or the reset script. `.env` and `certs/` are git-ignored
- [ ] Try it: write the *old* vulnerable search again (concatenated string directly in `FromSqlRaw`) → build error. Put the same concatenation into a local variable first → no error. Write down why that matters.
- [ ] Try it: as `seclab_app` (`sqlcmd -U seclab_app …`) run `SELECT TOP 1 Phone FROM Users`: ciphertext. Run `DROP TABLE Blogs`: denied.
- [ ] Try it: put `TrustServerCertificate=True` into the connection string: the test goes red. Remove `forceencryption` from `mssql.conf`: what changes for a client that does not ask for encryption?
- [ ] Try it: switch the encryption off for one column, run the two data-at-rest tests, switch it back, **reset the database** (rows written in plaintext cannot be decrypted).
- [ ] Short note (in your own words): where is the key, who can read it, what is the plan when it leaks?

## Pitfalls
- `MSSQL_SA_PASSWORD` is only read when the data volume is created. Changing `.env` afterwards changes nothing until `docker compose down -v` (this deletes the data).
- Fixing a certificate error with `TrustServerCertificate=True`. Fix the certificate (or pin it), not the validation.
- `.env` sourced in one terminal only: the API or the tests silently fall back to configuration without a connection string and fail with a clear message – or, worse, to a stale value from an earlier shell.
- Giving the app `db_owner` "just so migrations work". Give migrations their own identity.
- Granting `db_datareader`/`db_datawriter` and thinking that is "least privilege": it covers **every** table in the database. Grant on the schema you actually use and nothing else.
- `FromSqlRaw` with a local variable that was built from user input: the analyzers do not see it. `FromSql($"…")` with interpolation is safe *because* it parameterises; `FromSqlRaw($"…")` is the same-looking line that is not.
- Escaping quotes by hand (`q.Replace("'", "''")`). It "works" until the first encoding or `\` trick, and it does not help with `LIKE` wildcards at all.
- Encrypting with a key stored next to the ciphertext (a column in the same database, a file in the same backup).
- Deterministic or fixed-IV encryption ("so that I can still search"): equal values are visible as equal; an attacker with a dictionary of phone numbers recovers them. Search on a separate keyed hash if you need equality lookups.
- Hand-rolled crypto: ECB mode, a static IV, CBC without a MAC, `AesGcm` with a reused nonce, home-made key derivation.
- Forgetting existing rows: the converter cannot read plaintext written before it existed. Real systems need a one-off, restartable re-encryption job (here: reset the database).
- Applying migrations from the running API with a powerful connection string "only in Development" and then shipping that code path to production.
- Treating the database as trusted input: data read back from the table is still untrusted when it is rendered (step 10).
- Logging connection strings or SQL parameter values (step 12): both are secrets-adjacent.

## Further reading
- SQL injection – OWASP Cheat Sheets: *SQL Injection Prevention*, *Query Parameterization*, *Database Security*; OWASP Top 10 A05 Injection, API Security Top 10 API8
- EF Core: *Raw SQL queries* (`FromSql`, `SqlQuery`, `ExecuteSql`, parameters, injection warning) – https://learn.microsoft.com/ef/core/querying/sql-queries ; *Value conversions* – https://learn.microsoft.com/ef/core/modeling/value-conversions ; *Migrations overview*, *Applying migrations* (bundles) – https://learn.microsoft.com/ef/core/managing-schemas/migrations/
- EF Core analyzers (EF1001–EF1003) – https://learn.microsoft.com/ef/core/querying/sql-queries#passing-parameters ; .editorconfig severity – https://learn.microsoft.com/dotnet/fundamentals/code-analysis/configuration-options
- ASP.NET Core Data Protection (introduction, key management, key storage providers, encrypting keys at rest) – https://learn.microsoft.com/aspnet/core/security/data-protection/introduction
- SQL Server permissions hierarchy; fixed database roles; *Configure SQL Server on Linux with mssql-conf* (network.tlscert, forceencryption); *Connection encryption and certificate validation* for Microsoft.Data.SqlClient – https://learn.microsoft.com/sql/relational-databases/security/
- Safe storage of app secrets in development (User Secrets) – https://learn.microsoft.com/aspnet/core/security/app-secrets
- **Part B ideas (not required here):** one database schema per trust zone (public content vs. personal data vs. audit) with separate grants; **row-level security** policies so a bug in a query cannot cross tenants; **ledger tables** for tamper-evident audit data; **Always Encrypted** (client-side keys, secure enclaves for range queries); **dynamic data masking** (convenience, not security); TDE and backup encryption; **Microsoft Entra-only authentication** with a managed identity in Azure SQL, no passwords at all, private endpoints and auditing (Part 2, step P2-04).

Stuck or done? Compare with the solution: [`docs/solutions/15-database-security.md`](solutions/15-database-security.md) and `solutions/15-database-security.patch` (applies on top of 01–14).
