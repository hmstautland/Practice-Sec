# 12 – Logging, observability and monitoring

> Prerequisites: steps 01–11 done (or apply patches `01`–`11`). Time: 3–4 hours. No schema change.
> Infrastructure provided: an optional local OpenTelemetry dashboard (`docker compose --profile observability up -d dashboard`, UI http://localhost:18888, OTLP on `localhost:4317`) and a small log detector (`docs/attack-scripts/12-detect.py`).

## Goal
Be able to answer, *after the fact and while it is happening*: **who did what, from where, when, with what result – and is something abnormal going on right now?** Without logging secrets, without letting attackers write your logs, and without drowning in noise.

Contract (the tests encode it):

**1 · Security (audit) events** – logged under the dedicated category **`SecLab.Audit`** with structured properties (message *templates*, not string interpolation):

| `Event` | Level | Properties besides `Event` and `ClientIp` |
|---|---|---|
| `login.failed` | Warning | `Username` (sanitised), `Reason` (`unknown_user`, `bad_password`, `locked`) |
| `login.succeeded` | Information | `UserId` |
| `login.locked` (once, when the threshold is reached) | Warning | `UserId` |
| `user.registered` | Information | `UserId` |
| `apikey.created` / `apikey.revoked` | Information | `UserId`, `KeyId` (+ `Level` on create) |
| `apikey.rejected` | Warning | `Reason` – **never the key** |
| `passkey.registered`, `stepup.granted` / `passkey.failed` | Information / Warning | `UserId` (+ `Stage`) |
| `role.changed` | Warning | `UserId` (actor), `TargetUserId`, `NewRole` |
| `account.deleted` | Warning | `UserId` |
| `authz.denied` (any `403`) | Warning | `UserId`, `Endpoint` |
| `ratelimit.rejected` (any `429`) | Warning | `UserId` (or `anonymous`), `Endpoint` |
| `authn.required` (any `401`) | Information | `UserId`, `Endpoint` |

`ClientIp` is the *trusted* client address (step 07). The 401/403/429 events come from **one** place in the pipeline, so nothing that refuses a request can forget to log it.

**2 · Never in a log:** passwords (right or wrong), password hashes, bearer/step-up tokens, API keys or their secrets, e-mail addresses, request bodies. **User-supplied text** that is logged (usernames) has control characters removed and length capped at 64, so it cannot forge or split log lines.

**3 · Correlation:** the trace id of an error response (`traceId`, step 11) is the `TraceId` in the log scope of every entry written during that request – including the full exception. An incoming W3C `traceparent` is honoured (not replaced). Logs are written as **JSON, one object per line**, with scopes.

**4 · Metrics** (meter **`SecLab.Security`**, counters): `seclab.auth.login.failures` (tag `reason`), `seclab.auth.lockouts`, `seclab.authz.denied`, `seclab.ratelimit.rejected`, `seclab.apikey.rejected` (tag `reason`), `seclab.errors.unhandled`. **At most two tags, small fixed value sets – never user names, IPs, e-mails, ids or paths.**

**5 · Health:** `GET /health/live` and `GET /health/ready` (database check) – anonymous, exempt from rate limits, body exactly `Healthy`/`Unhealthy`/`Degraded`, no details.

**6 · Telemetry export:** traces, metrics (incl. `SecLab.Security`) and logs are exported with **OpenTelemetry (OTLP)** when `OTEL_EXPORTER_OTLP_ENDPOINT` is set – and not at all otherwise.

**7 · Monitoring (thinking, not code):** write down five detections (signal → threshold → who gets told → first response step) and run `12-attack-and-detect.sh` + `12-detect.py` to see whether *your* events would have caught the scenario.

Out of scope: log storage, retention and immutability in the cloud (Part 2: Log Analytics, alerts), SIEM integration, distributed tracing across services.

## Threat / why
Security controls that nobody can observe are assumptions. Without audit events a credential-stuffing run, a stolen API key, or an admin abusing a role leaves no trace; without correlation ids a user's "it failed at 14:02" cannot be found; logging done wrong *creates* vulnerabilities (secrets in logs, log forging, PII hoarding). OWASP Top 10:2025 A09 – *Security Logging and Alerting Failures* – is a category of its own for this reason: breaches are found late when nobody looks.

```bash
dotnet run --project backend/src/SecLab.Api 2>&1 | tee /tmp/seclab.log          # terminal 1 (RateLimiting__Login=1000 to let the flood reach the login code)
bash docs/attack-scripts/12-attack-and-detect.sh                                  # terminal 2: a small "incident"
python3 docs/attack-scripts/12-detect.py /tmp/seclab.log                          # terminal 3: what would you alert on?
```

## Concepts
- **The three pillars:** *logs* (discrete events, high detail), *metrics* (cheap numeric time series for alerting/trends), *traces* (one request's path across components). **OpenTelemetry** is the vendor-neutral standard for all three (API/SDK + OTLP). .NET's `ILogger`, `Meter`/`Counter` (`System.Diagnostics.Metrics`) and `Activity` map directly onto it.
- **Structured logging:** `logger.LogWarning("… {Username} …", user)` keeps `Username` as a field; string interpolation destroys structure and invites injection. Use consistent property names; use **LoggerMessage** source generation on hot paths.
- **Audit vs diagnostic logs:** audit = security-relevant *decisions and actions* with actor, action, target, outcome, time, source; needs longer retention, restricted access and tamper resistance (append-only/immutable storage). Diagnostic = debugging; short retention.
- **What to log / what not to:** OWASP Logging Cheat Sheet lists events: authentication successes/failures, access-control failures, input-validation failures, sensitive-data access, admin actions, session/token lifecycle, system errors. Never: credentials, tokens, keys, full card/ID numbers, session ids, full request bodies. Minimise personal data (IP addresses and user names *are* personal data under GDPR – define purpose and retention).
- **Log injection:** an attacker who controls a logged string can insert newlines and fake entries or terminal escape sequences. Defences: structured/JSON output (escapes for you), sanitise/trim at the point of logging, never log raw request bodies.
- **Correlation:** W3C Trace Context (`traceparent`), `Activity.Current`, and ASP.NET's activity-tracking log scopes attach `TraceId`/`SpanId` to every entry. The id you show the *user* (step 11) must be the id you can *search for*.
- **Metrics for security:** rates and counts (failures/min, lockouts, denials, rejects, 5xx), not identities. High-cardinality tags explode storage and leak PII; per-user detail belongs in logs.
- **Health checks:** liveness ("restart me?") vs readiness ("send me traffic?"). Keep them cheap, anonymous-safe and free of detail; do not let them depend on user auth or be rate limited into flapping.
- **Detection engineering:** an alert needs *signal, threshold, owner, action*. Typical starters: failed logins per IP/min; distinct usernames per IP; lockouts; repeated 403 per user; rejected API keys per IP; any `role.changed`/`account.deleted` (always review); spikes of 5xx; audit gaps (a service that stops logging is itself an alert).
- **Where logs go:** console (JSON) → collector → store. In containers write to stdout and let the platform ship it (Part 2). Protect the pipeline: an attacker with your logs knows your users and your defences.
- **Overhead & sampling:** sample traces, not audit events; drop `Microsoft.*` noise via log filters.

## Your turn
Tasks:
1. Design a small audit API (one class, one category) and call it at every place in the table – including the pipeline-level 401/403/429 events.
2. Add the security meter with the counters above and increment them next to the corresponding audit events (and for unhandled exceptions).
3. Sanitise user-supplied values before they are logged; prove that no secret can reach a log.
4. Switch the console to JSON with scopes; make sure the trace id reaches log scopes.
5. Add health checks; wire up OpenTelemetry export (only when a collector is configured); optionally start the dashboard and look at your data.
6. Do task 7 from the contract: write down five detections.

<details><summary>Hint 1 – where to look</summary>

`Program.cs` (logging, telemetry, health, pipeline), a new `Observability/` folder, every place that decides something security-relevant: login/register in `Endpoints/Api.cs`, key endpoints in `ApiKeys.cs`, the key handler in `Authorization/ApiKeyAuthentication.cs`, `Passkeys.cs`, `Errors/GlobalExceptionHandler.cs`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`ILoggerFactory.CreateLogger("SecLab.Audit")`, message templates with named placeholders, `builder.Logging.AddJsonConsole(o => o.IncludeScopes = true)`, `IMeterFactory.Create` + `Meter.CreateCounter<long>` + `KeyValuePair<string, object?>` tags, `AddHealthChecks().AddDbContextCheck<T>(tags:)` (NuGet `Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore`), `MapHealthChecks(...).AllowAnonymous().DisableRateLimiting()`, NuGet `OpenTelemetry.Extensions.Hosting` + `…Instrumentation.AspNetCore/Http/Runtime` + `…Exporter.OpenTelemetryProtocol`: `AddOpenTelemetry().WithTracing/WithMetrics(...AddMeter(name))`, `UseOtlpExporter()`, `builder.Logging.AddOpenTelemetry(...)`, `char.IsControl`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

A singleton `AuditLog` with one method per event (fixed property names, sanitising helper, client IP helper) and a singleton `SecurityMetrics`; endpoints call them right after the decision is made (after the DB commit for state changes). A tiny middleware placed just after the exception/status-code middleware awaits `next()` and then, for final status 401/403/429, emits the corresponding event using `HttpContext.GetEndpoint()`. Telemetry export is conditional on configuration.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=12"     # 10 tests: a log capture provider and a meter listener watch the app from inside
bash docs/attack-scripts/12-attack-and-detect.sh && python3 docs/attack-scripts/12-detect.py /tmp/seclab.log
# optional:  docker compose --profile observability up -d dashboard
#            OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 dotnet run --project backend/src/SecLab.Api    → http://localhost:18888
```
Checklist:
- [ ] `Step=12` (10) green; the full suite green
- [ ] The detector reports credential stuffing, a lockout, admin probing, key guessing, and lists the `role.changed` audit line
- [ ] `grep -i "password\|Bearer\|sl_" /tmp/seclab.log` finds no credential
- [ ] Logs are one JSON object per line and contain `TraceId` scopes; the `traceId` from a `500` response can be grepped in the log
- [ ] Without `OTEL_EXPORTER_OTLP_ENDPOINT` nothing tries to connect anywhere
- [ ] Your five detections are written down with owner and first response

## Pitfalls
- Logging the *request* (body/headers) "to debug" – that is where passwords and tokens live. Log decisions, not payloads.
- String interpolation in log calls (`$"user {name}"`): no structure, and injection.
- Unsanitised usernames: people paste **passwords into the username field** – you would log them. Truncating and stripping control characters limits the damage; not logging the failed username at all is an option for high-security systems.
- High-cardinality metric tags (user id, IP, path with ids) – cost and privacy problems in one.
- Alerting on every `401`/`404`: constant noise trains people to ignore alerts. Alert on *rates* and *combinations*.
- Logging after `SaveChanges` failed or before the decision is final: record what actually happened.
- Logs readable by everyone who can read the app: restrict, retain per policy, and monitor access to them.
- Health endpoints that echo exception messages, or that require auth so the orchestrator marks the app dead.
- Losing correlation: generating your own request id instead of using the W3C trace id.
- Forgetting the *absence* of logs as a signal (a service that goes quiet).

## Further reading
- Logging in .NET / ASP.NET Core – https://learn.microsoft.com/aspnet/core/fundamentals/logging/
- High-performance logging with `LoggerMessage` – https://learn.microsoft.com/dotnet/core/extensions/logger-message-generator
- .NET observability with OpenTelemetry – https://learn.microsoft.com/dotnet/core/diagnostics/observability-with-otel
- Metrics in .NET (`System.Diagnostics.Metrics`) – https://learn.microsoft.com/dotnet/core/diagnostics/metrics
- Health checks in ASP.NET Core – https://learn.microsoft.com/aspnet/core/host-and-deploy/health-checks
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- OWASP Logging Cheat Sheet, Logging Vocabulary Cheat Sheet; OWASP Top 10:2025 A09; NIST SP 800-92 (log management); W3C Trace Context

Stuck or done? Compare with the solution: [`docs/solutions/12-logging-observability.md`](solutions/12-logging-observability.md) and `solutions/12-logging-observability.patch` (applies on top of 01–11).
