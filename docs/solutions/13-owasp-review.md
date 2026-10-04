# Solution – 13 OWASP review

> Spoiler. Try the step yourself first: [`../13-owasp-review.md`](../13-owasp-review.md). Patch: `solutions/13-owasp-review.patch` (after 01–12; it also contains the generated `packages.lock.json` files, so it is long).

## What was verified
- **168 backend tests** (steps 01–13) pass on a fresh database; the frontend has **10 passing Vitest tests** (5 XSS + 5 CSP/headers); `npm run build` and `npm audit --omit=dev` (0 vulnerabilities) are clean.
- `dotnet list package --vulnerable --include-transitive`: none. `dotnet list package --outdated` initially showed EF Core SqlServer, JwtBearer, Mvc.Testing and System.Formats.Cbor at 10.0.0 with 10.0.12 available → updated; only test-tooling major versions (Test SDK 18, xunit runner 4) remain, deliberately.
- Live `13-review.sh`: all hardening headers present, no `Server`/`Set-Cookie`, every probe path (`/swagger`, `/actuator`, `/.env`, `/appsettings.json`, `/metrics`, …) answered `401` (nothing exposed).
- **Not verified:** the preview-server CSP through a real browser (only the config is asserted by the test), and `RestoreLockedMode` under `CI=true` (only the presence of the setting).
- One full test run took ~12 minutes once (with one unrelated failure in the step-08 paging test) and could not be reproduced (the next runs took 41–44 s); it looked like a stalled host, not a code problem.

## 1. The matrix (`docs/owasp-matrix.md`)
Filled with 20 rows; abbreviated view of the honest statuses:

| | Status | Why |
|---|---|---|
| A01, API1, API3, API5, API7 | Mitigated | steps 05, 06, 09 (tests exist for object, property, function level and SSRF) |
| A06, A07, API2, API4, API8, API9, A10 | Mitigated | steps 03/04/07/08/11/13 |
| A02 | Partial | headers/CORS/errors done; SQL `sa` login and secrets → step 15, Part 2 |
| A03 | Partial | audit + lock files here; pinned CI actions, image scanning → Part 2 |
| A04 | Partial | TLS, password and key hashing done; column encryption → step 15 |
| A05 | Partial | XSS/validation done; SQL injection in `/api/blogs/search` → step 15 |
| A08 | Partial | token/signature validation and sanitising done; signed artifacts → Part 2 |
| A09 | Partial | events, metrics, detection done; central storage/alert rules → Part 2 |
| API6 | Partial | limits and lockout, no CAPTCHA/quotas |
| API10 | Partial | fetched content treated as untrusted, contracts follow in step 16 |

Evidence cells use `Step=NN` filters and, for API9, the inventory test in step 13 itself. The test verifies that each cited step really has tests and each cited path exists.

## 2. Headers (`Security/SecurityHeaders.cs`)
An `app.Use` that registers `Response.OnStarting` and sets six headers **only if absent** (so the static-file options from step 09 keep their stricter `sandbox` CSP) and `Cache-Control: no-store` for `/api/*`. It is the first middleware, so 401s, errors from the exception handler and rate-limit responses carry the headers too. `AddServerHeader = false` (step 11) handles `Server`; there is no cookie-setting code, and the test keeps it that way.

## 3. SPA (`frontend/vite.config.ts`)
- `preview.headers` = CSP (`default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' https://localhost:5443 http://localhost:8081; img-src 'self' https://localhost:5443 https://i.pravatar.cc data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`), `nosniff`, `Referrer-Policy`, `Permissions-Policy`.
- `test.include` widened to `tests/**/*.test.{ts,tsx}`; the certificate read became conditional (`fs.existsSync`) so tests also run on machines without the dev certificate.
- The dev server intentionally has no CSP (hot-reload uses inline scripts).

## 4. Supply chain
`backend/Directory.Build.props`:
```xml
<NuGetAudit>true</NuGetAudit><NuGetAuditMode>all</NuGetAuditMode><NuGetAuditLevel>low</NuGetAuditLevel>
<WarningsAsErrors>$(WarningsAsErrors);NU1901;NU1902;NU1903;NU1904</WarningsAsErrors>
<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
<RestoreLockedMode Condition="'$(CI)' == 'true'">true</RestoreLockedMode>
```
- `packages.lock.json` generated for all three projects (committed).
- NU1510 revealed that `Microsoft.Extensions.Identity.Core` (added in step 02) is **already part of the .NET 10 shared framework** → reference removed (smaller dependency surface).
- Package bumps: EF Core SqlServer, JwtBearer (API and tests), Mvc.Testing, System.Formats.Cbor → 10.0.12.
- A blanket `AnalysisLevel=latest-recommended` was tried and dropped: it produced hundreds of style warnings (test names with underscores) and no security signal.

## 5. Cleanups found by the build
While here: `Fido2Configuration.ServerDomain/ServerName` are obsolete (`RPID`, `RPName`) and `ForwardedHeadersOptions.KnownNetworks` is obsolete (`KnownIPNetworks`) – replaced; the build is warning-free.

## 6. `SECURITY.md`
Supported versions table (starter explicitly unsupported), private reporting channel (address on a reserved `.example` domain – replace with a real mailbox), 3-/10-business-day and 90-day commitments, scope and safe-harbour sentence.

## Other test changes in this step
`Step11ErrorHandlingTests`: "success responses carry no `no-store`" became "success responses carry no `X-Trace-Id`", because `/api` responses are now uniformly `no-store`.

## Deliberately left open
- No formal threat model; no pen test; no SBOM or artifact signing (Part 2).
- `unsafe-inline` styles are avoided in the CSP, but any future library that injects inline styles will need a nonce-based policy.
- The API's own CSP is `default-src 'none'`; the SPA's policy is only enforced where the static files are served (preview, CDN, gateway in step 14).
