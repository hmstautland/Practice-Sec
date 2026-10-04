# Solution – 12 Logging, observability and monitoring

> Spoiler. Try the step yourself first: [`../12-logging-observability.md`](../12-logging-observability.md). Patch: `solutions/12-logging-observability.patch` (after 01–11). New packages: `OpenTelemetry.*` 1.19.x (Extensions.Hosting, Instrumentation.AspNetCore/Http/Runtime, Exporter.OpenTelemetryProtocol), `Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore` 10.0.12.

## What was verified
- **160 tests** (steps 01–12) pass on a fresh database. **Mutation check:** passing the raw username to the log (skipping `Clean`) made exactly the log-forging test fail.
- **JSON logs:** one object per line, e.g. `{"Category":"SecLab.Audit","LogLevel":"Warning","State":{"Event":"login.failed","Username":"victim1","ClientIp":"::1","Reason":"unknown_user"},"Scopes":[{"TraceId":"00c0…","SpanId":"…"},…]}`.
- **OpenTelemetry:** with `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318` (a 20-line Python sink standing in for a collector) the API POSTed `/v1/traces`, `/v1/metrics` (the payload contained `seclab.auth.login.failures`) and `/v1/logs` (containing `login.failed`).
- **Detection exercise:** `12-attack-and-detect.sh` + `12-detect.py` reported credential stuffing (19 failed logins, 12 accounts), the lockout, "user denied 3 times" with the three admin endpoints, 4 rejected API keys, and listed `role.changed`.
- Health endpoints answered `Healthy`.
- **Not verified:** the Aspire dashboard container UI (the compose service is provided but I did not open the UI); gRPC OTLP (only the HTTP/protobuf endpoint was exercised).

## The audit vocabulary (`Observability/Audit.cs`)
```csharp
_log.LogWarning("Audit {Event}: user {Username} from {ClientIp}, reason {Reason}", "login.failed", Clean(username), Ip(ctx), reason);
```
- One class (`AuditLog`), one category (`SecLab.Audit`), fixed property names (`Event`, `ClientIp`, `UserId`, `KeyId`, `TargetUserId`, `NewRole`, `Endpoint`, `Reason`, `Level`, `Stage`).
- `Clean(value, 64)` drops every `char.IsControl` character and truncates; applied to the username and to endpoint strings. Passwords, keys and tokens are never parameters of any method – **the API of the audit class makes leaking a secret impossible by construction**, which is stronger than "remember not to".
- `Ip(ctx)` maps IPv4-mapped IPv6 to IPv4 and uses the connection address after the trusted-proxy handling from step 07.
- Event methods also bump the matching counter (login failures by `reason`, lockouts, authz denied, rate-limited, key rejected).

Call sites: login (unknown user / locked / bad password / lockout threshold / success), registration, key create/revoke (endpoints), key rejection (inside `ApiKeyAuthHandler`, once per request because the authentication result is cached), passkey registration/failure/step-up, role change, account deletion, unhandled exceptions (metric in `GlobalExceptionHandler`).

## One place for 401 / 403 / 429
```csharp
app.UseSecurityAudit();      // right after UseExceptionHandler/UseStatusCodePages
// await next(); then: status 401 → authn.required, 403 → authz.denied, 429 → ratelimit.rejected
```
Because it wraps the whole pipeline it sees denials from JWT/API-key authentication, policies, resource handlers (`Results.Forbid()`), the rate limiter and validation – nothing has to remember to log. `Endpoint` comes from `HttpContext.GetEndpoint()?.DisplayName` (route *template*, e.g. `HTTP: PUT /api/admin/users/{id:int}/role`), not the raw URL, which keeps cardinality and attacker-controlled text out.

## Metrics
`SecurityMetrics` creates the meter through `IMeterFactory` (`"SecLab.Security"`) and six `Counter<long>`s. Tags: only `reason` on two counters. The OpenTelemetry metrics builder registers `.AddMeter("SecLab.Security")`, so they are exported next to ASP.NET Core, HttpClient and runtime metrics.

## Logging setup (`Program.cs`)
```csharp
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(o => { o.IncludeScopes = true; o.UseUtcTimestamp = true; o.TimestampFormat = "o"; });
builder.Logging.AddOpenTelemetry(o => { o.IncludeScopes = true; o.IncludeFormattedMessage = true; o.ParseStateValues = true; });
```
Trace correlation comes for free: the host's `ActivityTrackingOptions` push `TraceId/SpanId/ParentId` scopes, and the step-11 error body shows the same trace id (`Activity.Current.Id`). `traceparent` from a caller is adopted by ASP.NET Core's diagnostics.
`appsettings.json` sets `Microsoft.AspNetCore: Warning` and `…EntityFrameworkCore.Database.Command: Warning` (SQL noise; with sensitive-data logging off EF would not log parameter values anyway), `SecLab.Audit: Information`.

## Telemetry export
```csharp
var telemetry = builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("seclab-api"))
    .WithTracing(t => t.AddAspNetCoreInstrumentation().AddHttpClientInstrumentation())
    .WithMetrics(m => m.AddAspNetCoreInstrumentation().AddHttpClientInstrumentation().AddRuntimeInstrumentation().AddMeter(SecurityMetrics.MeterName));
if (!string.IsNullOrEmpty(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"])) telemetry.UseOtlpExporter();   // logs, traces and metrics
```
`docker-compose.yml` gained a `dashboard` service (profile `observability`, `mcr.microsoft.com/dotnet/aspire-dashboard`, UI 18888, OTLP gRPC 4317) – auth is **disabled** for the lab and must not be reused anywhere real.

## Health
`AddHealthChecks().AddDbContextCheck<AppDbContext>("database", tags: ["ready"])`; `/health/live` (no checks) and `/health/ready` (tag `ready`) mapped on the app, `AllowAnonymous().DisableRateLimiting()`. The default response writer prints only the status word.

## Findings while building it
- `ISupportExternalScope` (not `…Provider`) is the interface a custom log provider implements to receive scopes – needed by the test provider.
- `ClearProviders()` only removes providers registered up to that point; the tests' provider is added later through DI and survives.
- The JSON console formatter puts each state property under `State`, and scopes as an array; the detector reads exactly that.

## Deliberately left open
- No log shipping, retention, or tamper protection (Part 2: Log Analytics, immutable storage, alert rules as code).
- `authn.required` (every 401) is logged at Information; in production consider sampling or dropping it and alerting on *rates* only.
- Audit events for reads of sensitive data (profile views by admins) are not implemented.
- OTLP over gRPC/TLS with authentication to a real collector is a deployment concern.
- IP addresses and usernames are personal data: retention and access rules are a policy decision this repository cannot make for you.
