# 16 – Testing: unit, integration, contract (and testing your tests)

> Prerequisites: steps 01–15 done (or apply patches `01`–`15`), SQL Server running, `.env` loaded (`set -a; source .env; set +a`), as in step 15. Time: 2–3 hours. **You write tests in this step, not application code** – with one exception you will discover yourself.

## Goal
Every earlier step ended with "the shipped test is green". From now on **you** own the tests: the suite must be able to tell you, on any day, that a security control stopped working – and it must be *provably* able to. A green suite proves nothing until you have seen it go red when the control is removed.

Write the suite in **`backend/tests/SecLab.Api.Tests/Learner/`** (namespace `SecLab.Api.Tests.Learner`). Conventions the shipped checks rely on: every test class or method carries `[Trait("Step", "16")]` and exactly one `[Trait("Kind", "...")]` – `Matrix`, `Negative`, `Unit`, `Contract` or `Integration`; no skipped tests; negative tests carry `[OwaspApi("APIn")]` (the attribute is in `Step16Support.cs`). Use the existing `Harness` for HTTP and database access; read the services of the host your clients talk to from `Harness.Services`.

Acceptance criteria (`backend/tests/SecLab.Api.Tests/Step16TestingTests.cs` checks the structure; two scripts check the quality):

**1. Authorization matrix** (`Kind=Matrix`, at least 3 test methods, one of them a `[Theory]`)
1. One table says, per route, who may call it: *anonymous*, *any signed-in user*, *admin*, *owner only*, *owner or admin*, *needs step-up*, *API key of level read/write/admin*. The table is written from the requirements of steps 05–06, not copied from what the API answers.
2. **The live endpoints and the table are the same set**: the endpoints are discovered from `EndpointDataSource` (of the running host); a route that is added, renamed or removed makes a test fail until the table is updated.
3. The table is checked against the endpoint **metadata** (`IAllowAnonymous`, `IAuthorizeData`) and the **default-deny fallback policy** is asserted to exist.
4. **Behaviour**: every route × every kind of caller (anonymous, owner, other user, admin, key read/write/admin) gets exactly the status the table implies: `401` for "not authenticated", `403` for "authenticated but not allowed", and *not* `401/403` (and no 5xx) for "allowed". Cells that say "denied" are the valuable ones.

**2. Negative tests** (`Kind=Negative`, at least 8, each tagged with the OWASP API Security Top 10:2023 risk it checks)
5. At least one test for each of **API1, API2, API3, API4, API5, API7, API8, API9** (API6 optional; API10 is not testable offline – see the solution notes). A negative test states what must *not* happen, tries it, and then checks the **state** (database, response body) – a `403` alone does not prove nothing changed.

**3. Unit tests** (`Kind=Unit`, at least 10; no host, no database, no network)
6. The small security helpers: API-key hashing and level ranking, the outbound-URL policy (`TryValidate`, `IsPublic`), the admin-network requirement, log-text cleaning, the HTML sanitizer, the request validation of the contract types, the column-encryption converter. Table-driven, with the boundaries from *both* sides.

**4. Contract tests** (`Kind=Contract`, at least 4)
7. **Shape snapshots** in `Learner/Snapshots/*.json` (at least 8): every property path and JSON type of the important responses (own profile, the three profile views, blogs v1 and v2, admin user list, key list/creation, …). A new, renamed or removed field fails the test until the snapshot is updated *in a reviewed diff*.
8. **Invariants** over every sampled response: no property that looks like a password, hash, salt, lock-out detail, passkey credential or token is ever serialised – with explicit, commented exceptions.
9. **Error contract**: every error (400, 401, 403, 404, 405, 409, 415, 500) is `application/problem+json` with `status`, `title`, `traceId`, an `X-Trace-Id` header and nothing about the inside. The two API versions keep their documented shapes.

**5. Integration tests** (`Kind=Integration`, at least 4)
10. Real HTTP pipeline + real EF Core + the **real SQL Server** from `docker compose`, running as the application's own least-privilege login (no in-memory provider, no SQLite). Each test creates uniquely named data and asks the database, not only the API.
11. **At least two tests whose name contains `Concurrent`** that fire identical requests at the same moment (`Task.WhenAll`) and then check the database. *If one of them goes red, you have found a real defect of this codebase – fix it (in the application) and keep the test.*

**6. Prove the tests can fail**
12. `bash docs/attack-scripts/16-mutants.sh`: your suite is green on the real app and **red for every one of the 8 mutants** (a mutant silently breaks one control in the test host – see *Threat*).
13. **Stryker.NET** configured in `backend/tests/SecLab.Api.Tests/stryker-config.json`: mutation targets `OutboundUrlPolicy`, `AdminNetwork`, `ContentSanitizer`, `ColumnEncryption`; test filter `Kind=Unit`; thresholds with `break` ≥ 75 (the reference solution uses 90); the tool pinned in `dotnet-tools.json`; reports git-ignored. `bash docs/attack-scripts/16-mutation.sh` passes, and every survivor is either killed by a new test or explained as an *equivalent mutant*.

**7. The test code is part of the supply chain**
14. Lock files for every project match the package references (the test project too – CI restores in locked mode); `bash docs/attack-scripts/16-supply-chain.sh` reports no vulnerable or deprecated package and no high/critical `npm audit` finding; you can describe how the unit and integration tests run in CI (see *Concepts*, Part 2 step P2-02).

Out of scope: browser/UI tests, load tests, consumer-driven contract testing with Pact, fuzzing, DAST in CI (Part 2, P2-05).

## Threat / why
Controls rot silently. Someone "temporarily" removes a role check, a refactoring makes an endpoint public, a serializer starts returning the entity, a new route ships without a decision about who may call it. None of that is visible in a green build unless a test was written to fail for exactly that – and a test that has never failed is a hope, not a control. Coverage numbers do not help: a loop that calls every endpoint without asserting anything has 100 % coverage.

The attack on **your suite** is the *mutant*. `Step16Support.cs` can change the **test host** (never the production code) so that one control quietly stops working:

| Mutant | What silently breaks |
|--------|---------------------|
| `admin-open` | any signed-in user passes the Admin policy |
| `ownership-skip` | owner/author checks always succeed |
| `fallback-off` | an endpoint without explicit metadata becomes public |
| `phantom-route` | a new endpoint appears that nobody classified |
| `password-leak` | JSON responses gain a `passwordHash` property |
| `error-shape` | errors lose the problem-details shape and carry a stack trace |
| `strip-headers` | `nosniff`, CSP, `no-store` … disappear |
| `no-rate-limit` | the global rate limiter is off |

```bash
bash docs/attack-scripts/16-mutants.sh          # baseline green, then each mutant: want "killed" 8 times
bash docs/attack-scripts/16-mutation.sh         # Stryker on the pure security helpers: want score >= break
bash docs/attack-scripts/16-supply-chain.sh     # restore --locked-mode, --vulnerable, --deprecated, npm audit
```
On the starter (no suite yet) the first script says "no tests ran". With your suite, the survivors are your to-do list.

## Concepts
- **Test the control, not the implementation.** "A normal user cannot call `/api/admin/users`" survives a rewrite; "the handler calls `RequireRole`" does not. Write the expectation from the *requirement* (the step's goal) and let the application disagree – if the table is copied from the API's answers it can only confirm what is already true.
- **The pyramid, for security.** *Unit* tests (milliseconds, no I/O) cover parsers, validators and policies – the places with many edge cases. *Integration* tests (the real pipeline and database) cover the wiring: policies actually attached, data actually encrypted, constraints actually enforced. *Contract* tests pin what clients receive. A few *negative end-to-end* tests per OWASP risk tie it to the threat model. Many unit, fewer integration, a handful of end-to-end.
- **Positive and negative.** "Alice can edit her post" proves the feature; "Bob cannot" proves the control. A matrix has far more denied cells than allowed ones. Beware ambiguous statuses: `401` can come from the authentication middleware (no/invalid credentials) or from a handler that says "wrong password"; `403` can mean "your role is wrong" or "step-up missing". The table needs a vocabulary (*who*, *what happens*), not just numbers. Always check **state** after a denied write.
- **Inventory by discovery.** `EndpointDataSource` (used in step 13) lists every route with its metadata (`IAllowAnonymous`, `IAuthorizeData`, `HttpMethodMetadata`). Enumerate it in the test and compare with your table: forgetting a route is then a red test, not a code-review hope. Remember that routes with *no* metadata are governed by the **fallback policy** – assert that policy, otherwise "no metadata" silently becomes "public". Note which host you enumerate: the factory's base host is not the host your clients call.
- **Table-driven and boundary tests.** `[Theory]` with `InlineData`/`MemberData`: one row per case, named by its inputs. Test each boundary from both sides (2048 and 2049 characters, `172.15` / `172.16` / `172.31` / `172.32`, `100.63` / `100.64`), each *part* of a compound condition on its own (the second octet alone must not make an address private), and known-answer vectors for crypto helpers (SHA-256 of the empty string). Property-style invariants (round trip, "ciphertext never contains the plaintext, two encryptions differ") complement examples.
- **Contract (snapshot/approval) tests.** Record the *shape* (paths and types, not values) of each response in a file under version control; the test fails on any difference; changing a contract is a deliberate, reviewed edit (`SECLAB_UPDATE_SNAPSHOTS=1`, then read the diff!). Add invariants that must hold for *every* response (never a credential-like property) and for every *error* (one shape, one correlation id, no internals). Without an OpenAPI document the snapshots *are* the contract; with one, diff the document in CI. Consumer-driven contracts (Pact) go further and are only mentioned in *Further reading*.
- **Integration tests with the real engine.** `WebApplicationFactory<Program>` runs the real pipeline in-process (no sockets); the repository uses the same SQL Server as the application because the in-memory and SQLite providers have no permissions, different SQL translation and different constraint behaviour. Testcontainers is the alternative when each run should start its own database (optional here; the lab's compose container plays that role). Make tests **independent**: unique names (GUID suffix) instead of clean-up, no assumptions about other rows, limits not under test lifted (`EnvScope`), no sleeps – and no test that only passes in a certain order. Run as the *application's* login so that missing permissions show up in tests, not in production.
- **Concurrency bugs only appear under concurrency.** "Check, then insert" is two statements; two requests can both pass the check. Sequential tests never see it. The cure is a constraint in the database (unique index, primary key) plus handling its violation; the test fires N identical requests at once, repeated a few rounds because a race is a matter of timing, and asks the **database** what happened.
- **Fault injection and mutation testing.** *Coverage* says a line ran; *mutation testing* says a wrong line would be noticed. A tool (Stryker.NET) rewrites the code in small ways (flip `<` to `<=`, drop a statement, empty a string) and runs your tests per mutant: killed = a test failed, **survived** = nobody noticed. The *mutation score* is killed / (killed + survived). Survivors are either missing tests or *equivalent mutants* (the change does not alter behaviour, e.g. clearing a list that is already what you set) – write that down instead of chasing 100 %. It is slow, so run it on the security-critical pure code with the unit tests only, and on a schedule or per pull request in CI, not on every push. The shipped *mutants* do the same at the level of whole controls, in the test host.
- **Determinism.** Random data, the clock, ports, rate-limit windows and ordering all make tests flaky. A flaky security test is worse than none (people learn to ignore red). Seed or inject what you can, isolate what you cannot, and treat "fails sometimes" as a finding: in this step it will be one.
- **Test code is code.** It has dependencies (restored by lock file, audited like the rest), it must never contain real secrets, and it must not switch security off (`TrustServerCertificate=True`, accept-all certificate callbacks) to make a test pass.
- **In CI** (Part 2, P2-02): build → **unit tests first** (`--filter "Kind=Unit"`, seconds, no database) → integration, matrix, contract and negative tests against SQL Server → lock-file restore, `dotnet list package --vulnerable`, `npm audit` → Stryker nightly or on demand (artifact: the HTML report). Branch protection requires these jobs.

## Your turn
Tasks (the order gives you fast feedback first):
1. **Look first.** Read `Step16Support.cs` (attribute, mutants), `Step16TestingTests.cs` (the checks), and `Harness.cs`, `TestIdp.cs`, `EnvScope.cs`. Run `dotnet test backend/SecLab.slnx --filter "Step=16"` and read why each check is red. Create the `Learner/` folder.
2. **Unit tests** (`Learner/SecurityUnitTests.cs`): the helpers named in criterion 6. Start with what they must refuse.
3. **Mutation testing of the helpers.** Write `stryker-config.json`, pin the tool, run `16-mutation.sh`, read the survivors, add tests, repeat. Note the equivalent mutants.
4. **Authorization matrix** (`Learner/AuthorizationMatrixTests.cs`): table → inventory test → metadata test → fallback test → behaviour theory. Set up callers once (a class fixture), create the objects a route needs per case, lift the rate limits for the run.
5. **Negative tests** (`Learner/OwaspNegativeTests.cs`): one risk at a time; check state, not only status.
6. **Contract tests** (`Learner/ContractTests.cs` + `Snapshots/`): sample real responses; shape function; snapshot compare with an update switch; invariants; error contract.
7. **Integration tests** (`Learner/DatabaseIntegrationTests.cs`): login identity and migrations, hashing, lock-out across hosts, API-key lifecycle, encrypted columns, **concurrency**. When a test finds a defect: fix it (small, in the application), keep the test, and write one sentence on why a sequential test could not have found it.
8. **Run the mutants** (`16-mutants.sh`). Every survivor: which of your tests *should* have failed? Add or strengthen it.
9. **Supply chain and CI.** Run `16-supply-chain.sh`; add what your own test project needs to the lock file; write down (README or step notes) the CI job layout from *Concepts*.

<details><summary>Hint 1 – where to look</summary>

`Harness.NewPerson/Anonymous/InDb/DatabaseContains/BearerFor/Services`, `TestIdp` (tokens, `AttackerKey`, `UnsignedToken`), `EnvScope` (rate limits are configuration: `RateLimiting__Anonymous` …), `Repo.Path_`. Earlier `StepNN*Tests.cs` show how to build requests (API keys in step 06, CORS preflight in 09, versions in 08). `Endpoints/*.cs` for the routes, `Program.cs` for the policies, `Validation/Contracts.cs` for the request types. Everything the unit tests need is `public`.
</details>

<details><summary>Hint 2 – which APIs</summary>

- Discovery: `Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()`, `RoutePattern.RawText`, `endpoint.Metadata.GetMetadata<HttpMethodMetadata>()`, `GetMetadata<IAllowAnonymous>()`, `OfType<IAuthorizeData>()`; `IAuthorizationPolicyProvider.GetFallbackPolicyAsync()` and `DenyAnonymousAuthorizationRequirement`. Route templates carry constraints (`{id:int}`) – normalise them.
- xUnit: `[Theory]` + `[MemberData]` (use simple, serialisable arguments such as strings and enums), `IClassFixture<T>` for expensive set-up (one host for 200+ cases), `[InlineData]`.
- Unit tests: `Validator.TryValidateObject(obj, new ValidationContext(obj), results, validateAllProperties: true)` for the record types with `[property: …]` attributes; `DefaultHttpContext` and `AuthorizationHandlerContext` for the admin-network handler; `ConfigurationBuilder().AddInMemoryCollection(...)`; `EphemeralDataProtectionProvider` and `ValueConverter.ConvertToProvider/ConvertFromProvider` for the encryption converter.
- Contract: `System.Text.Json.JsonDocument`/`JsonElement` walk; a flat `SortedDictionary<string,string>` (path → type) serialises to a readable, diffable file.
- Concurrency: `Task.WhenAll(Enumerable.Range(0, n).Select(_ => client.PostAsync(...)))`; `DbUpdateException` and `SqlException.Number` 2601/2627 when you fix the defect.
- Stryker: `dotnet new tool-manifest` is already done (`dotnet-tools.json`); `dotnet tool install dotnet-stryker`; configuration keys `project`, `mutate` (globs, optional `{from..to}` line ranges), `test-case-filter`, `thresholds`, `reporters`; the JSON report lists every mutant with its status.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

- **Matrix**: an `enum Access`, a `Dictionary<string, Access>` keyed by `"METHOD /normalised/route"`, a `Caller` enum, a pure function `Expected(access, caller) -> Allowed | 401 | 403`, and a theory over the cartesian product. Per case: pick the caller's client (or an anonymous client with an `X-Api-Key` header), build the path with ids of freshly created objects, send `{}` as JSON (a real multipart body for the avatar route), compare. "Allowed" means "not 401/403 and not 5xx". One route (login) legitimately answers `401` itself – decide how the vocabulary expresses that.
- **Negative tests**: Arrange with `Harness.NewPerson`; act with the attack; assert the response *and* `InDb(...)`. For API2 mint tokens with `TestIdp`; for API4 build a host with `EnvScope(("RateLimiting__Anonymous","3"), …)` *before* the first client is created.
- **Contract**: a `Samples()` method creating real data and returning name → `JsonElement`; one test compares each sample with `Snapshots/<name>.json`; one test applies a regular expression to every leaf property name; one test samples errors of each kind.
- **Integration**: `new Harness(factory)` twice = two hosts sharing one database = a "restart".
- **Stryker config**: four files in `mutate`; use a line range where a file mixes pure code with code only an integration test can reach (a connect callback); thresholds `high`/`low`/`break`.
</details>

## Verify
```bash
set -a; source .env; set +a                                        # as in step 15
dotnet test backend/SecLab.slnx --filter "Step=16"                 # shipped checks: red on the starter (see below), green with your suite
dotnet test backend/SecLab.slnx --filter "Step=16&Kind=Unit"       # milliseconds, no database
bash docs/attack-scripts/16-mutants.sh                             # about 2-3 minutes
bash docs/attack-scripts/16-mutation.sh                            # about 30 seconds
bash docs/attack-scripts/16-supply-chain.sh
dotnet test backend/SecLab.slnx                                    # everything, incl. the gateway tests
```
On the starter 6 of the 9 checks in `Step16TestingTests` are red (no suite, no Stryker configuration …); the other three guard conventions your suite must not break (no secrets or sleeps, units without a host, lock files up to date).

Checklist:
- [ ] `Step=16` green; your suite has all five kinds, the matrix has a `[Theory]`, every OWASP API risk in scope has a negative test
- [ ] `16-mutants.sh`: baseline green, **8 of 8 mutants killed**
- [ ] `16-mutation.sh`: score above the `break` threshold; survivors listed and explained
- [ ] `16-supply-chain.sh` finds nothing to act on; `git status` shows no `StrykerOutput/`, no `.env`
- [ ] Try it: add a new route in `Api.cs` without touching your table → the inventory test goes red (do not commit the route). Remove `.RequireAuthorization("Admin")` from one admin route → which of your tests fail, and are they the ones you expected?
- [ ] Try it: rename a response property in `FullProfile` → the snapshot test names the path. Add `Password` to it → two different tests fail.
- [ ] Try it: change `b[0] == 169 && b[1] == 254` in `OutboundUrlPolicy.IsPublic` to `||` by hand → which unit test fails? (If none: that is exactly what Stryker would have told you.)
- [ ] Short note (own words): which of your tests would *not* have caught the concurrency defect, and why?

## Pitfalls
- **Asserting only status codes** for denied requests. A `403` with the data already changed is a failure; check the database or the body.
- **Reading the expectation from the application** (copy the answers into the table). The test then confirms the bug it was supposed to find.
- **Enumerating the wrong host.** The base factory's services are not the services of the host your clients use (this is what the `phantom-route` mutant exploits).
- **One 401 for two meanings.** The login endpoint answers `401` for "wrong credentials"; the middleware answers `401` for "no credentials". Do not let a matrix treat them alike without noticing.
- **Rate limits in tests**: 200 requests from one test address trip the anonymous limit and make the matrix fail for the wrong reason. Lift the limits you are not testing; test the limiter on its own with a tiny limit.
- **Snapshot blindness.** `SECLAB_UPDATE_SNAPSHOTS=1` followed by commit without reading the diff turns the contract test into a rubber stamp. The checks refuse snapshots with credential-looking property names – but only the ones you thought of.
- **A mutation score as a goal.** Killing mutants by pinning implementation details (exact log text, private ordering) makes tests brittle. Equivalent mutants exist; explain them.
- **Sleeping or retrying until green.** `Thread.Sleep`, retry attributes and "run it again" hide races – including the ones in your product.
- **Shared mutable data.** Assertions about "all users" or counts of tables break as soon as another test (or the seed) adds rows. Assert about the rows you created.
- **Weakening security to make a test pass** (`TrustServerCertificate=True`, a test-only bypass in the application). If the test needs a fake, fake the *outside* (token issuer, clock), not the control.
- **Forgetting the lock file** after adding a test package: CI restores in locked mode and fails; `dotnet restore` locally and commit `packages.lock.json`.
- **Treating the shipped mutants as the whole threat model.** Eight mutants are a start; the useful habit is asking "which test would fail if I deleted this line?" for every control you add.

## Further reading
- OWASP: *Web Security Testing Guide* (WSTG), *API Security Testing* in the OWASP API Security Project, *Application Security Verification Standard* (ASVS) chapter V1 (architecture) and the verification levels
- Microsoft: *Integration tests in ASP.NET Core* (`WebApplicationFactory`, replacing services) – https://learn.microsoft.com/aspnet/core/test/integration-tests ; *Test against your production database system* (why not in-memory/SQLite) – https://learn.microsoft.com/ef/core/testing/choosing-a-testing-strategy
- Stryker.NET documentation (configuration, mutators, `mutate` line ranges, thresholds, CI use) – https://stryker-mutator.io/docs/stryker-net/introduction/
- xUnit.net: *Shared context between tests* (class fixtures, collections), *Parallel test execution*
- Testcontainers for .NET (SQL Server module) as an alternative to the compose container; Verify / approval testing libraries as an alternative to hand-made snapshots
- Pact and consumer-driven contract testing; OpenAPI diffing (`oasdiff`) when an API description is generated
- Property-based testing (FsCheck) and fuzzing for parsers; *Chaos engineering* for the production-side version of fault injection
- NuGet: *Auditing packages for security vulnerabilities*, *Lock files* (`RestoreLockedMode`) ; `npm audit`; GitHub: *Dependency review*
- **Part B ideas (not required here):** mutation testing in a nightly pipeline with a trend; consumer-driven contract tests for the external service the API calls (API10); DAST (OWASP ZAP) against the deployed API (P2-05); a security regression test for every fixed vulnerability (name it after the finding).

Stuck or done? Compare with the solution: [`docs/solutions/16-testing.md`](solutions/16-testing.md) and `solutions/16-testing.patch` (applies on top of 01–15).
