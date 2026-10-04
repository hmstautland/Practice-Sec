# Solution – 09 Allow-listing

> Spoiler. Try the step yourself first: [`../09-allow-listing.md`](../09-allow-listing.md). Patch: `solutions/09-allow-listing.patch` (after 01–08).

## What was verified
- **105 tests** (steps 01–09) pass on a fresh database.
- Live `09-allowlists.sh`: evil-origin preflight got no CORS headers; the real frontend got the exact origin, `GET,POST,PUT,DELETE`, the four headers, `max-age 600` and `Vary: Origin`; `Host: evil.example` → 400; HTML-as-PNG → 400; a real PNG named `../../evil.html` → `/avatars/<guid>.png`; all six SSRF URLs → 400; `https://example.com/` → title "Example Domain" (real outbound request); Keycloak answered 400 for an unregistered `redirect_uri`.
- **Not verified:** `ConnectCallback` (`SafeConnect`) against a hostile DNS server – the tests replace the primary handler, so only the URL policy is exercised automatically. `Proxy`-aware admin-network checks behind a real gateway (step 14).

## CORS (`Program.cs`)
```csharp
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(allowedOrigins)                                     // Cors:AllowedOrigins
    .WithMethods("GET", "POST", "PUT", "DELETE")
    .WithHeaders("Authorization", "Content-Type", "api-version", "X-StepUp")
    .WithExposedHeaders("Retry-After", "Sunset", "Deprecation", "api-supported-versions", "api-deprecated-versions")
    .SetPreflightMaxAge(TimeSpan.FromMinutes(10))));                 // no AllowCredentials: bearer tokens, not cookies
```
plus a tiny middleware that always appends `Vary: Origin` (ASP.NET Core skips it when exactly one origin is configured).

## Hosts
`appsettings.json`: `"AllowedHosts": "localhost;seclab.example"`. (`seclab.example` is there because the step-01 HSTS test runs against that host name in Production.)

## Admin network
`Security/AdminNetwork.cs`: `AdminNetworkRequirement` + `AdminNetworkHandler` (reads `Admin:AllowedNetworks`, `IPNetwork.Parse` once). The handler takes `context.Resource as HttpContext`, maps IPv4-mapped IPv6 to IPv4, denies when the address is unknown, otherwise succeeds if any network contains it. It is added to the existing policy: `AddPolicy("Admin", p => p.RequireRole("Admin").AddRequirements(new AdminNetworkRequirement()))` – so `/api/admin/*` **and** `/api/debug/*` are covered without touching the routes.

The test host cannot have a real socket, so `TestIdp` installs a test-only startup filter that sets `RemoteIpAddress` to `127.0.0.1` or to the value of the `X-Test-Remote-Ip` request header.

## Avatars (`Endpoints/Api.cs`)
1. Authorize (`Operations.Edit`, from step 05); `file.Length` between 1 byte and 2 MB.
2. Read the first 12 bytes → `ImageType.Detect`: PNG `89 50 4E 47 0D 0A 1A 0A`, JPEG `FF D8 FF`, WebP `RIFF….WEBP`. Everything else → 400.
3. Name = `Guid.NewGuid().ToString("N") + detectedExtension`; `FileMode.CreateNew`.
4. Static files get `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; sandbox`.
5. Defence in depth: Kestrel `Limits.MaxRequestBodySize = 3 MB` for the whole API.

## Link preview (`Endpoints/Tools.cs`, `Security/OutboundUrlPolicy.cs`)
`TryValidate`: length ≤ 2048 → `Uri.TryCreate(Absolute)` → scheme `https` → empty `UserInfo` → default port → `HostNameType == Dns` (rejects IPv4/IPv6 literals in every notation) → `IdnHost` exactly in the allow-list (case-insensitive). Invalid → `ValidationProblem` (400) before any I/O.

The named client: `AddHttpClient("outbound", timeout 5 s)` with a `SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = 3 s, ConnectCallback = SafeConnect }`. `SafeConnect` resolves the name itself, refuses if **any** answer is non-public (loopback, RFC1918, link-local incl. 169.254/16, CGNAT, multicast, ULA …), and connects to the validated address – closing the DNS-rebinding gap between "validate" and "connect".

The endpoint reads with `ResponseHeadersRead`, treats 3xx as an error (`502`), reads at most `1 MB + 1` bytes (over → `502`), extracts `<title>` with a source-generated regex that has a 500 ms timeout, HTML-decodes and collapses whitespace.

## Bug found while writing it
My first version of the CORS change replaced a block of `Program.cs` with a range-based edit and **silently deleted the step-01 `AddHsts` configuration**. The step-01 test (`max-age too short: 2592000`) caught it immediately – a good reason to keep every earlier step's tests in the suite.

Another finding: `RequestSizeLimitAttribute` is an MVC type and does not exist in a pure minimal-API project; the Kestrel limit is the simple, global alternative.

## Deliberately left open
- Allow-lists are static configuration; production would want them per environment (Part 2: app settings / Key Vault references).
- No re-encoding of uploaded images (which would strip metadata and polyglot payloads) and no antivirus scan.
- The link-preview title is returned as text; it must still be output-encoded by the UI (step 10).
- Security response headers for the API and SPA (CSP, frame-ancestors, referrer policy …) → step 13.
