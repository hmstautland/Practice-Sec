# 09 – Allow-listing

> Prerequisites: steps 01–08 done (or apply patches `01`–`08`). Time: 3 hours. No schema change.
> The pattern in one sentence: **enumerate what is allowed and refuse everything else** – because you can never enumerate what is dangerous.

## Goal
Replace five "anything goes" defaults with explicit allow-lists, and add one feature (link previews) that is safe by construction.

| Area | Allow-list (configuration key) | Required behaviour |
|---|---|---|
| **CORS** | `Cors:AllowedOrigins` = `["https://localhost:5173"]` | Only exact matches get CORS headers. Methods: `GET, POST, PUT, DELETE`. Request headers: `Authorization, Content-Type, api-version, X-StepUp` (**not** `X-Api-Key`). No wildcards, no credentials. Any other origin (`https://evil.example`, `https://localhost:5173.evil.example`, `http://localhost:5173`, `null`) gets **no** `Access-Control-Allow-*` headers. Responses tell caches to `Vary: Origin`. |
| **Host names** | `AllowedHosts` = `localhost;seclab.example` | A request whose `Host` header is not listed → `400`. |
| **Admin network** | `Admin:AllowedNetworks` = `["127.0.0.1/32", "::1/128"]` (CIDR) | Everything behind the **Admin** policy (`/api/admin/*`, `/api/debug/*`) also requires the caller's IP to be inside a listed network; unknown address → deny. Wrong network *with* the Admin role → `403`. |
| **Avatar files** | PNG, JPEG, WebP, ≤ 2 MB | Type decided from the **content** (magic bytes), never from the client's file name or `Content-Type`. Anything else (HTML, SVG, GIF, empty, oversized) → `400`. Files are stored under a **server-generated name** with the extension of the detected type. Served with `X-Content-Type-Options: nosniff`. |
| **Outbound URLs** | `Outbound:AllowedHosts` = `["example.com"]` | New endpoint **`POST /api/tools/link-preview`** `{ "url": "…" }` (signed-in users) fetches the page and returns `{ url, title }`. It only ever requests: `https`, port 443, a DNS host name that is *exactly* an allow-listed host (case-insensitive), no user-info, no IP literals. Anything else → `400` **and no request is made**. **Redirects are not followed**; responses > 1 MB and upstream errors → `502`. Uses a *named* `HttpClient` called **`outbound`** (`IHttpClientFactory`) – the tests replace its primary handler to observe calls. |

Also (manual): the OAuth **redirect URI** allow-list lives at the IdP – prove that Keycloak refuses an unlisted redirect URI (the attack script does).

Out of scope: input validation of text fields (step 10), security headers such as CSP for the SPA (step 13), gateway-level allow-lists (step 14).

## Threat / why
- **CORS misconfiguration** (`AllowAnyOrigin`, reflecting the `Origin`, regex/suffix checks) lets any website a user visits talk to your API *as that user's browser*.
- **Host header attacks** poison generated links (password-reset, redirects), caches, and virtual-host routing.
- **Admin surface exposed to the internet**: a stolen admin token is useless from an unexpected network.
- **Unrestricted uploads**: HTML/SVG served from your origin = stored XSS; `../` names overwrite files; huge files fill the disk. (The red run of this step's tests on the starter actually wrote a file *outside* `wwwroot`.)
- **SSRF** (OWASP API Security Top 10 API7; folded into A01:2025 Broken Access Control in the Top 10:2025): a feature that fetches user-supplied URLs turns your server into a proxy into your own network – cloud metadata services (`169.254.169.254`), internal admin ports, `localhost`.

```bash
bash docs/attack-scripts/09-allowlists.sh
```

## Concepts
- **Allow-list vs. deny-list.** Deny-lists ("block 127.0.0.1, 10.*, …") always miss a spelling (`0x7f.1`, `[::ffff:127.0.0.1]`, decimal IPs, DNS names pointing inward). Allow-lists fail closed.
- **Exact matching.** The classic bugs are `EndsWith(".example.com")` (matches `evilexample.com`), `Contains`, regexes without anchors, and comparing before normalisation (case, trailing dot, IDN/punycode, percent-encoding). Parse first (`Uri`), compare on the parsed components.
- **CORS is a browser rule, not authentication.** It only tells *browsers* whether a page from another origin may read responses. `curl` ignores it. It does not replace authorization – and a preflight is just an `OPTIONS` request. ASP.NET Core's policy builder is explicit about origins, methods, headers, exposed headers and credentials; think about `Vary: Origin` when the answer depends on the `Origin` header.
- **Host filtering** (`AllowedHosts`) is enforced by the host filtering middleware from configuration – `*` means "anything".
- **Network allow-lists** are defence in depth: they narrow *where* privileged calls may come from, and are only as good as your knowledge of the client IP (forwarded headers, step 07). Express them as an **authorization requirement** so the rule sits with the policy, not scattered in endpoints. `System.Net.IPNetwork` handles CIDR.
- **File uploads.** Decide type by content; generate the name yourself; cap size (Kestrel `MaxRequestBodySize`, form limits, your own check); store outside the web root or serve with `nosniff` and a locked-down CSP; consider re-encoding images. SVG is XML that can carry script – not an "image" for this purpose.
- **SSRF defence layers:** (1) allow-list of hosts/schemes/ports, (2) don't follow redirects (or re-validate each hop), (3) check the **resolved IP** at connect time (DNS rebinding: a name can resolve to something different from what you validated), (4) short timeouts and size caps, (5) network egress rules and no credentials on the fetching host (Part 2). A `SocketsHttpHandler.ConnectCallback` is where (3) belongs.
- **`IHttpClientFactory`** gives you named/typed clients with one place to configure handlers, timeouts and policies – exactly what outbound calls need (and what step 16's contract tests will reuse).
- **Redirect-URI allow-list** (OAuth): the IdP must match `redirect_uri` exactly against registered values; wildcards are an open-redirect/token-theft risk.

## Your turn
Tasks:
1. CORS from configuration with the rules above; ensure `Vary: Origin`.
2. Restrict host names; add the admin-network requirement to the Admin policy (mind the `HttpContext` resource and IPv4-mapped IPv6 addresses).
3. Rewrite the avatar upload as an allow-listed, server-named, size-capped operation; serve files with `nosniff`.
4. Build the link-preview endpoint with the `outbound` client and every rule in the table.
5. Run the tests and the attack script; try the IdP redirect-URI check.

<details><summary>Hint 1 – where to look</summary>

`Program.cs` (CORS, static files, policy registration, HTTP client), `appsettings.json`, the avatar route in `Endpoints/Api.cs`, a new endpoints file and a new `Security/` folder for the two policy classes.
</details>

<details><summary>Hint 2 – which APIs</summary>

`CorsPolicyBuilder.WithOrigins/WithMethods/WithHeaders/WithExposedHeaders/SetPreflightMaxAge`; `AllowedHosts`; `AuthorizationHandler<TRequirement>` with `context.Resource as HttpContext`; `IPNetwork.Parse/Contains`, `IPAddress.MapToIPv4`; `IFormFile`, `Stream.ReadAtLeastAsync`, `Guid.NewGuid().ToString("N")`; `StaticFileOptions.OnPrepareResponse`; `Uri.TryCreate`, `Uri.IdnHost`, `HostNameType`, `UserInfo`, `IsDefaultPort`; `AddHttpClient("outbound")…ConfigurePrimaryHttpMessageHandler(new SocketsHttpHandler { AllowAutoRedirect = false, ConnectCallback = … })`; `HttpCompletionOption.ResponseHeadersRead`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One static "policy" class with `TryValidate(url, allowedHosts)` (parse → scheme → user-info → port → host-name type → exact host match) and `IsPublic(ip)` used in a connect callback. The endpoint validates, calls the named client without redirects, reads at most 1 MB + 1 byte, extracts `<title>` with a time-limited regex. Avatar: read the first 12 bytes, map signatures to extensions, write `CreateNew` under a GUID name. Admin: requirement + handler registered as `IAuthorizationHandler`, added to the existing `Admin` policy.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=09"     # 30 test cases (theories included); the tests fake client IPs and the outbound HTTP handler
bash docs/attack-scripts/09-allowlists.sh
```
Checklist:
- [ ] `Step=09` green; all earlier steps still green
- [ ] Evil origins: no `Access-Control-*` headers; the real origin: exact echo + `Vary: Origin`
- [ ] `Host: evil.example` → 400
- [ ] Admin routes from a non-listed IP → 403 (the tests use a header-controlled fake IP; on a real deployment behind a proxy you also need step 07's trusted-proxy setup)
- [ ] An HTML file named `x.png` → 400; a real PNG named `../../evil.html` → stored as `<guid>.png`
- [ ] Link preview: metadata IP, `localhost`, `http://`, user-info and suffix tricks → 400 and **zero** outbound calls; `example.com` works
- [ ] Keycloak refuses `redirect_uri=https://evil.example/cb`

## Pitfalls
- **`Vary: Origin` is not added automatically when only one origin is allowed** – a shared cache can then hand the "allowed" response to other origins (or the "no CORS" response to your frontend). The tests check for it.
- CORS `AllowAnyOrigin` + `AllowCredentials`, or reflecting whatever `Origin` arrives.
- `AllowedHosts: "*"` left in production config.
- Admin network check that ignores `::ffff:127.0.0.1` (IPv4-mapped IPv6) or trusts `X-Forwarded-For` from anyone.
- Trusting the multipart `Content-Type` or the extension; keeping the client's file name; serving uploads from the same origin without `nosniff`.
- Validating the URL string but letting the HTTP client follow a redirect to `http://169.254.169.254/`.
- Validating the host name, then resolving it again at request time (rebinding). Validate the address you actually connect to.
- Allow-listing by `Contains("example.com")`, or accepting `https://example.com@evil.example`.
- Reading unbounded responses into memory; missing timeouts.
- Per-route `IPNetwork` checks copy-pasted into endpoints instead of one authorization requirement.

## Further reading
- Enable Cross-Origin Requests (CORS) in ASP.NET Core – https://learn.microsoft.com/aspnet/core/security/cors
- Host filtering / AllowedHosts – https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/host-filtering
- Upload files in ASP.NET Core (security considerations) – https://learn.microsoft.com/aspnet/core/mvc/models/file-uploads
- Make HTTP requests with IHttpClientFactory – https://learn.microsoft.com/aspnet/core/fundamentals/http-requests
- OWASP API Security Top 10 API7 (SSRF); OWASP SSRF Prevention, File Upload, CORS and Input Validation Cheat Sheets

Stuck or done? Compare with the solution: [`docs/solutions/09-allow-listing.md`](solutions/09-allow-listing.md) and `solutions/09-allow-listing.patch` (applies on top of 01–08).
