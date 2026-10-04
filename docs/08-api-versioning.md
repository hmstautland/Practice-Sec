# 08 – API versioning

> Prerequisites: steps 01–07 done (or apply patches `01`–`07`). Time: 1.5–2 hours. No schema change.
> Design note: this tutorial versions by **header / query string** (`api-version`), not by URL segment. Reason: every test and script from steps 01–07 uses unversioned URLs, and header/query versioning lets old clients keep working while the tests keep meaning something. The Concepts section compares the styles.

## Goal
Change the API's contract without breaking clients silently – and **retire the old contract on purpose**, because forgotten old versions are attack surface (OWASP API9: Improper Inventory Management).

Contract (the tests encode it):

1. Two versions exist: **1.0** (default, *deprecated*) and **2.0** (current). The version is read from the header **`api-version`** or the query parameter **`api-version`**.
2. A request that names no version is treated as **1.0**. Every response reports **`api-supported-versions`** (2.0) and **`api-deprecated-versions`** (1.0). Responses served as 1.0 also carry **`Deprecation: true`** and a **`Sunset`** header (HTTP date) plus a `Link` to the migration notes. Responses served as 2.0 carry neither.
3. Sunset date comes from configuration **`Api:V1SunsetDate`** (default `2027-06-30`). From that instant, version 1.0 answers **`410 Gone`** (problem details JSON) while 2.0 keeps working.
4. Unknown versions (`3.0`), malformed ones (`banana`) and **contradicting** ones (header `1.0` + query `2.0`) → **`400`**, never a silent fallback.
5. What differs in **2.0**: `GET /api/blogs` returns an envelope `{ items, page, pageSize, total }` with `page` ≥ 1 and **`pageSize` 1–50** (default 20; out of range → `400`; a page beyond the end → empty `items`). In 1.0 it stays a bare, unbounded array. Every other endpoint is available in both versions unchanged.
6. **Versioning must not change who may call what:** authentication and authorization behave identically in every version.
7. Frontend: always sends `api-version: 2.0`; *Experience* uses the paged blog list with a "Load more" button.

Out of scope: URL-segment versioning, OpenAPI documents per version (mentioned in Concepts), the gateway (step 14).

## Threat / why
- **Zombie APIs.** The v1 endpoint keeps running long after v2 fixed its problems (here: an unbounded response – one request can pull the whole table). Attackers look for `/v1`, `?version=1`, old mobile clients.
- **Silent behaviour changes** break clients; **silent fallbacks** ("unknown version → newest/oldest") break security assumptions.
- Version-specific routes tend to be forgotten by the security review: a missing `[Authorize]` on the v1 copy is a classic.

```bash
bash docs/attack-scripts/08-old-versions.sh
```
The script shows what a client gets without asking for a version, how big the v1 response is, and that bad/contradicting versions are refused.

## Concepts
- **Versioning styles:** URL segment (`/api/v2/…` – most visible, easy to route and to cache, easy to see in logs; changes every URL), header (`api-version`; clean URLs, invisible in browsers, needs client discipline), query string (easy to test, ends up in logs/caches), media type (`Accept: application/vnd…+json`). Combine readers only if you also decide precedence and reject conflicts.
- **What deserves a new version?** Breaking changes to a contract (removed/renamed fields, changed semantics, stricter validation). Adding optional fields is not breaking. Security fixes that change behaviour are a legitimate reason – and a reason to retire the old version *fast*.
- **Lifecycle:** *supported → deprecated (announce) → sunset (410) → removed*. Use standard signals: `Sunset` (RFC 8594), `Deprecation` (RFC 9745), `Link rel="sunset"/"deprecation"`, plus `api-supported-versions` / `api-deprecated-versions`. Put dates in configuration so ops can move them without a release.
- **Default version policy.** "Assume default when unspecified" keeps legacy clients alive but means clients that forgot the header get the *old* contract. Decide consciously; never default to "latest" (a deployment then silently changes everybody's contract).
- **Libraries:** `Asp.Versioning.Http` (minimal APIs) / `Asp.Versioning.Mvc` (controllers): `AddApiVersioning`, version *sets*, `MapToApiVersion`, `ReportApiVersions`, sunset *policies*. Version-neutral endpoints are available in all versions.
- **Security consequences:** one authorization model across versions (share the same policies/handlers), the same rate limits (step 07), inventory of every version in every environment, contract tests per supported version (step 16), kill switch for old versions.
- **Documentation:** each supported version needs its own description (OpenAPI) and migration notes.

## Your turn
Tasks:
1. Add API versioning with the readers, default, reporting and sunset settings above.
2. Group the endpoints so that both versions exist, keep unchanged endpoints available in both, and implement the two `GET /api/blogs` variants.
3. Enforce the deprecation signal and the `410` after the sunset date.
4. Return problem-details JSON for version errors.
5. Adapt the frontend. Run the tests and the script.

<details><summary>Hint 1 – where to look</summary>

`Program.cs` (services + a small middleware), `Endpoints/Api.cs` (the route group and the `/blogs` route), `appsettings.json`, `frontend/src/api/client.ts` and `pages/Experience.tsx`.
</details>

<details><summary>Hint 2 – which APIs</summary>

NuGet `Asp.Versioning.Http`; `AddApiVersioning(o => …)` with `DefaultApiVersion`, `AssumeDefaultVersionWhenUnspecified`, `ReportApiVersions`, `ApiVersionReader.Combine(HeaderApiVersionReader, QueryStringApiVersionReader)`, `o.Policies.Sunset(1.0).Effective(date)`; `app.NewApiVersionSet().HasDeprecatedApiVersion(...).HasApiVersion(...)`; `.WithApiVersionSet(...)` on the group; `.MapToApiVersion(...)` on version-specific routes; `AddProblemDetails()`; `IApiVersioningFeature` for the requested version.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One version set on the `/api` group (1.0 deprecated, 2.0 current). Two `MapGet("/blogs")` declarations, each pinned to one version. A middleware after routing: if the requested version is 1.x → add `Deprecation`; if the sunset instant has passed → write `410` and stop. Be careful what your middleware does when the versioning layer itself is about to reject the request (ambiguous versions).
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=08"      # 6 tests (the sunset test starts a host with Api__V1SunsetDate=2000-01-01)
bash docs/attack-scripts/08-old-versions.sh
```
Checklist:
- [ ] `Step=08` (6) green; all earlier steps still green
- [ ] Unversioned `GET /api/blogs` → array + `Deprecation`, `Sunset`, `api-*-versions` headers
- [ ] `api-version: 2.0` → envelope, no deprecation headers; `pageSize=1000` → 400
- [ ] `9.9`, `banana`, and header≠query → 400 (not 500!)
- [ ] With `Api__V1SunsetDate=2000-01-01`, v1 and unversioned → 410, v2 → 200
- [ ] Browser: Experience shows 10 posts and "Load more"

## Pitfalls
- Reading the requested version in your own middleware **before** the versioning layer had a chance to reject an ambiguous request → an unhandled exception and a `500` (found while writing the reference solution).
- Adding a v2 route but forgetting that the v1 copy is still mapped – with its old authorization.
- Defaulting to the *newest* version, or falling back silently for unknown versions.
- Copy-pasting handlers per version, so a security fix lands in one version only. Share code, version the *contract* (DTOs, paging), not the business rules.
- `Sunset` in the past but nothing enforcing it: a header is a hint, `410` is a decision.
- Keeping versions forever "for that one customer": inventory customers by version (step 12 logging helps) and set a date.
- Version in the query string only: it leaks into logs/caches and is dropped by some proxies.
- Different rate limits or error formats per version by accident.

## Further reading
- Asp.Versioning documentation – https://github.com/dotnet/aspnet-api-versioning/wiki
- API versioning and minimal APIs – same wiki (Minimal APIs, Sunset policies)
- RFC 8594 (Sunset header), RFC 9745 (Deprecation header), RFC 9457 (problem details)
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- OWASP API Security Top 10 (API9 Improper Inventory Management); OWASP REST Security Cheat Sheet

Stuck or done? Compare with the solution: [`docs/solutions/08-api-versioning.md`](solutions/08-api-versioning.md) and `solutions/08-api-versioning.patch` (applies on top of 01–07).
