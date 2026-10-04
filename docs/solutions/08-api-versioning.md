# Solution – 08 API versioning

> Spoiler. Try the step yourself first: [`../08-api-versioning.md`](../08-api-versioning.md). Patch: `solutions/08-api-versioning.patch` (after 01–07). Package: `Asp.Versioning.Http` 10.2.3.

## What was verified
- **75 tests** (steps 01–08) pass on a fresh database.
- Live `08-old-versions.sh`: unversioned request → `Deprecation: true`, `api-supported-versions: 2.0`, `api-deprecated-versions: 1.0`, `Sunset: Wed, 30 Jun 2027 …`, `Link … rel="sunset"`; v1 returned the whole table (29 items at that point); `pageSize=1000` → 400; `9.9` → 400; header≠query → 400. The 410 path is covered by the automated test (host started with `Api__V1SunsetDate=2000-01-01`).
- Frontend builds; UI not click-tested.

## Wiring
`Program.cs`
```csharp
builder.Services.AddProblemDetails();                          // version errors come back as problem+json
builder.Services.AddApiVersioning(o =>
{
    o.DefaultApiVersion = new ApiVersion(1, 0);
    o.AssumeDefaultVersionWhenUnspecified = true;
    o.ReportApiVersions = true;
    o.ApiVersionReader = ApiVersionReader.Combine(new HeaderApiVersionReader("api-version"), new QueryStringApiVersionReader("api-version"));
    o.Policies.Sunset(1.0).Effective(v1Sunset).Link("docs/08-api-versioning.md").Title("Migrate to API v2").Type("text/markdown");
});
```
The sunset date is read once from `Api:V1SunsetDate`. `Policies.Sunset(...)` produces the `Sunset` and `Link` headers on responses served as 1.0.

`Endpoints/Api.cs`
```csharp
var versions = app.NewApiVersionSet().HasDeprecatedApiVersion(new ApiVersion(1, 0)).HasApiVersion(new ApiVersion(2, 0)).ReportApiVersions().Build();
var api = app.MapGroup("/api").WithApiVersionSet(versions);
api.MapGet("/blogs", …array…).MapToApiVersion(1, 0);
api.MapGet("/blogs", …page envelope…).MapToApiVersion(2, 0);
```
Routes without `MapToApiVersion` are available in every version of the set – which is what "everything else is unchanged" needs. Authorization metadata lives on the group/fallback policy, so both `/blogs` variants are protected identically (a test proves anonymous callers get 401 in all versions).

**Sunset enforcement and `Deprecation`** – a small middleware placed before authentication:
```csharp
try { requested = ctx.Features.Get<IApiVersioningFeature>()?.RequestedApiVersion; }
catch (AmbiguousApiVersionException) { await next(); return; }      // let the versioning layer answer 400
if (requested is { MajorVersion: 1 }) { Deprecation: true; if (now >= v1Sunset) → 410 problem+json }
```

**v2 paging** validates `page ≥ 1`, `1 ≤ pageSize ≤ 50` (`ValidationProblem` → 400), computes the offset in `long` (no int overflow for absurd pages), returns `{ items, page, pageSize, total }`.

## Bugs found while writing it
1. Reading `RequestedApiVersion` in the middleware threw `AmbiguousApiVersionException` for header≠query, which the developer exception page turned into a **500**. The versioning layer would have answered 400, but the middleware ran first. Fix: catch and pass through.
2. My first test expected `api-supported-versions` to list 1.0. It lists only *non-deprecated* versions; deprecated ones are in `api-deprecated-versions`.
3. `Link("/docs/…")` was rendered as `<//docs/…>`; the library prefixes the slash itself.

## Frontend
`client.ts` adds `api-version: 2.0` to every request; `api.blogs(page)` returns the envelope; `Experience.tsx` appends pages with a "Load more" button (search results stay a plain array).

## Deliberately left open
- Header/query versioning only; no per-version OpenAPI documents.
- Contract (Pact) tests per version come in step 16.
- The sunset instant is configuration, not a feature flag store; the deprecation notice has no analytics on who still calls v1 (step 12 gives you the data).
