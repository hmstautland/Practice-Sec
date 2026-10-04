# 13 – OWASP review: prove it, close the gaps

> Prerequisites: steps 01–12 done (or apply patches `01`–`12`). Time: 3 hours. No schema change.
> This step is different: mostly **review and evidence**, plus the last generic hardening. The deliverable is a completed `docs/owasp-matrix.md` that a reviewer can check against runnable evidence.

## Goal
Step back from individual fixes and answer honestly: **against the two OWASP lists, what is the state of SecLab, where is the proof, and what is still open?** Then close the remaining generic gaps.

Deliverables (the tests check every one):

1. **`docs/owasp-matrix.md` completed** for all 20 categories – OWASP Top 10:2025 (A01–A10) and API Security Top 10:2023 (API1–API10). Each row: where the risk exists *in this app*, what mitigates it, **evidence** (a `Step=NN` test filter that exists, or a file path that exists), and an honest status: `Mitigated`, `Partial`, `Accepted risk` (with an `owner:` and justification), or `Not applicable` (with justification). No `?`/`TODO` left. The rules are at the top of that file.
2. **Response hardening headers on every response**: `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `Permissions-Policy` that disables camera, microphone and geolocation, `Cross-Origin-Resource-Policy: same-site`; **`Cache-Control: no-store` on every `/api` response**; still no `Server`/`X-Powered-By`; **never a `Set-Cookie`**. A component that needs something stricter (the static avatar files) must keep its own value.
3. **SPA policy:** the production build is served with a strict CSP – `default-src 'self'`, `script-src 'self'` (no `unsafe-*`), `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `form-action 'self'`, `connect-src` only `'self'` + the API + the IdP – plus `nosniff`, `Referrer-Policy`, `Permissions-Policy`. Put it in the Vite **preview** server config (the dev server cannot use it: hot reload needs inline scripts) and make the test runner pick up `*.test.ts` files as well as `*.test.tsx`. `index.html` must contain no inline scripts.
4. **Endpoint inventory is a test:** exactly `/api/auth/login`, `/api/auth/register`, `/health/live`, `/health/ready` are anonymous; every `/api` route belongs to the API version set; nothing else is exposed (no swagger/debug UI by accident).
5. **Supply chain:** `backend/Directory.Build.props` turns on NuGet audit for **direct and transitive** packages, makes advisories NU1901–NU1904 **build errors**, uses **lock files** (`packages.lock.json` generated and committed) and locked restore in CI. `dotnet list package --vulnerable --include-transitive` and `npm audit --omit=dev` are clean; **outdated packages are reviewed and security-relevant patch releases applied**; unused package references removed.
6. **`SECURITY.md`** at the repository root: supported versions, how to report privately, what response to expect.

Out of scope: a formal threat model (do one for your real app: STRIDE), penetration testing (do one), the database (step 15), cloud (Part 2).

## Threat / why
Fixing bugs one at a time leaves *classes* of problems unexamined. The OWASP lists are checklists distilled from thousands of breaches; walking them against your own system finds what your step-by-step work did not target – misconfiguration, supply chain, design flaws – and forces a written statement of residual risk. Response headers are cheap, broad defence in depth (a bug that injects HTML into a response is far less dangerous behind a CSP). Dependencies are code you did not write and still ship.

```bash
bash docs/attack-scripts/13-review.sh          # headers, exposure probes, vulnerable/outdated packages, secrets grep, matrix status
```

## Concepts
- **OWASP Top 10:2025** – A01 Broken Access Control (now including SSRF), A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions. **API Security Top 10:2023** – API1 BOLA, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption, API5 BFLA, API6 Unrestricted Access to Sensitive Business Flows, API7 SSRF, API8 Security Misconfiguration, API9 Improper Inventory Management, API10 Unsafe Consumption of APIs. Read the official pages, not just titles.
- **Evidence-based security:** "we did X" is a claim; a test or script that fails when X is undone is evidence. Rows in the matrix without evidence are wishes.
- **Honest statuses.** `Partial` and `Accepted risk` are respectable answers; unowned, unwritten risk is the problem.
- **Security headers:** `nosniff` (MIME sniffing), CSP (what the response may load/run; for JSON APIs `default-src 'none'`; for the SPA a strict script policy is the main XSS damper), `frame-ancestors`/`X-Frame-Options` (clickjacking), `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-*` policies, `Cache-Control: no-store` for personal data, HSTS (step 01). Test them, because a proxy or a refactor silently drops them.
- **CSRF** needs ambient credentials (cookies, HTTP auth). This API uses bearer tokens in a header and sets **no** cookies – so CSRF does not apply; the test that no response ever sets a cookie is what keeps it that way. If you later add cookie sessions (e.g. a BFF), you need antiforgery tokens and `SameSite`.
- **Inventory as code:** enumerate endpoints from the running app (`EndpointDataSource`) and assert on their metadata – authorization, versions, allow-anonymous – instead of trusting a spreadsheet.
- **Supply chain (A03/A08):** NuGet Audit (advisories from GitHub Advisory Database via NuGet), `NuGetAuditMode=all` (transitive!), lock files + locked mode (reproducible builds; a compromised newer version isn't pulled silently), `npm audit`/`npm ci`, minimal dependencies (every package is attack surface), keep patch levels current, later: SBOM, signed artifacts, pinned CI actions (Part 2).
- **Coordinated disclosure:** `SECURITY.md` and a monitored mailbox turn a stranger's finding into a fix instead of a headline.
- **Analyzers:** .NET and EF Core analyzers flag risky patterns at build time (e.g. EF1002 for SQL built from strings) – decide which become errors.

## Your turn
Tasks:
1. Walk both lists. For every row, find the place in SecLab where the risk lives, name the mitigation and the evidence, and set an honest status. Where you cannot point to evidence, decide: build it now, or mark `Partial`/`Accepted risk` with an owner.
2. Add a middleware for the response headers (mind order and "add if absent").
3. Add the SPA's preview-server headers and fix the test include pattern.
4. Add `Directory.Build.props`; restore so lock files are created; run the audits; update what is outdated; remove what is unused.
5. Write `SECURITY.md`.
6. Run the tests and `13-review.sh`.

<details><summary>Hint 1 – where to look</summary>

`docs/owasp-matrix.md` (the rules are in its header), `Program.cs` (a new middleware near the top of the pipeline), `frontend/vite.config.ts` (`preview.headers`, `test.include`), the repository root and `backend/`, and the output of `dotnet list package --outdated` / `--vulnerable --include-transitive`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`HttpResponse.OnStarting` (headers must be set before the body starts; check `ContainsKey` first); `EndpointDataSource`, `RouteEndpoint.Metadata` for the inventory; MSBuild properties `NuGetAudit`, `NuGetAuditMode`, `NuGetAuditLevel`, `WarningsAsErrors`, `RestorePackagesWithLockFile`, `RestoreLockedMode`; NU1510 tells you a package reference is redundant; Vite `preview.headers`; Vitest `test.include`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Matrix: 20 rows, mostly `Mitigated`/`Partial`, each pointing at a `Step=NN` you already have. One 25-line middleware. One props file. Expect the audit to teach you something: which packages are behind, which one is no longer needed.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=13"     # 8 tests (headers, cookies, inventory, audit settings, lock files, SECURITY.md, matrix ×2)
cd frontend && npm test                                # includes the CSP test
bash docs/attack-scripts/13-review.sh
```
Checklist:
- [ ] `Step=13` green; full backend suite and frontend tests green
- [ ] `dotnet list package --vulnerable --include-transitive` → no vulnerable packages; `npm audit --omit=dev` → 0
- [ ] `dotnet list package --outdated` shows no *patch* updates left (major-version test tooling may stay; say why)
- [ ] `docs/owasp-matrix.md`: 20 rows, statuses honest, evidence paths exist
- [ ] `curl -i https://localhost:5443/api/me` shows all headers and no `Server`
- [ ] `npm run build && npm run preview` → response headers contain the CSP (`curl -I`)

## Pitfalls
- Filling the matrix with "Mitigated" everywhere. If the evidence column is thin, the row is not mitigated.
- Setting headers with `Append` on every response (duplicates) or overwriting a stricter header from a more specific component.
- A CSP that breaks the app in dev (inline scripts for hot reload) and is then loosened everywhere with `unsafe-inline`. Keep dev and production policies separate and test the production one.
- `NuGetAuditMode` left at the default `direct`: transitive vulnerabilities (the usual ones) stay invisible.
- Turning advisories into errors without a process for accepting a risk temporarily (`NuGetAuditSuppress` with an expiry and an owner).
- Lock files that are generated but not committed, or `RestoreLockedMode` in developers' local builds (frustration → people disable it).
- `npm install` in CI instead of `npm ci`.
- Treating "outdated" as noise: patch releases of the framework and of EF Core/ASP.NET packages are where security fixes ship.
- `SECURITY.md` with an address nobody reads.

## Further reading
- OWASP Top 10:2025 – https://top10.owasp.org/2025 ; OWASP API Security Top 10:2023 – https://owasp.org/API-Security/
- Auditing packages for security vulnerabilities (NuGet Audit) – https://learn.microsoft.com/nuget/concepts/auditing-packages
- Repeatable package restores with lock files – https://learn.microsoft.com/nuget/consume-packages/package-references-in-project-files#locking-dependencies
- ASP.NET Core security topics (headers, CSRF/antiforgery, HSTS) – https://learn.microsoft.com/aspnet/core/security/
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- OWASP Secure Headers Project, HTTP Headers Cheat Sheet, CSRF Prevention Cheat Sheet, Vulnerable Dependency Management Cheat Sheet; MDN Content-Security-Policy

Stuck or done? Compare with the solution: [`docs/solutions/13-owasp-review.md`](solutions/13-owasp-review.md) and `solutions/13-owasp-review.patch` (applies on top of 01–12).
