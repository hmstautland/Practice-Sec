# 11 – Error handling

> Prerequisites: steps 01–10 done (or apply patches `01`–`10`). Time: 1.5–2 hours. No schema change.

## Goal
Make failures **safe** (nothing useful for an attacker), **uniform** (one machine-readable shape for every error) and **traceable** (a support person can go from the user's screenshot to the exact log entry).

Contract (the tests encode it):

1. **Unhandled exceptions** → `500` with `Content-Type: application/problem+json` and a body containing only `status`, a generic `title` and a **`traceId`**. No exception type or message, no stack trace, no file paths, no connection strings, no SQL errors – in **any** environment, *including Development*. Clients that send `Accept: text/html` still get JSON, never an HTML page.
2. The full exception is **logged server-side together with the same trace id**.
3. Detailed errors exist only behind an explicit switch, **`Diagnostics:DetailedErrors`** (default `false`, even in Development). When `true`, the problem body may carry `detail` (for a developer's own machine).
4. **Every** error response – `400` (validation), `401`, `403`, `404`, `405`, `415`, `409`, `500`, `502`, whoever produced it (framework, middleware, endpoint) – is problem-details JSON with `status`, `title`, `traceId`, plus the response header **`X-Trace-Id`** (same value) and **`Cache-Control: no-store`**. Successful responses carry none of these.
5. Every error gets its **own** trace id.
6. Authentication failures reveal nothing: unknown user and wrong password give the same status and the same title, with no wording such as "wrong password" or "no such user".
7. The server does not advertise itself (`Server:` header) and there is no developer exception page anywhere.
8. Known conditions map to the right status instead of `500` (bad request bodies → `400`, optimistic-concurrency conflict → `409`), and a client that hung up is not reported as a server error.
9. Frontend: shows the error's `title`, field messages and the **reference (trace id)**; it never renders server-supplied text as HTML.

Out of scope: structured logging, log retention and alerting (step 12), gateway-level error pages (step 14).

## Threat / why
- **Information disclosure.** The starter's developer exception page prints source code, stack traces, configuration, headers and sometimes secrets (`/api/debug/crash` even names its connection string). Attackers use errors to learn frameworks, versions, table and column names and file layouts – then tailor SQL injection, path traversal and CVE exploits.
- **Oracles.** Different messages for "no such user" / "wrong password" / "locked" enumerate accounts.
- **Inconsistency** breaks clients and monitoring: HTML from one layer, empty bodies from another, JSON from a third – and clients end up rendering raw responses.
- **No correlation** means incidents cannot be investigated.

```bash
bash docs/attack-scripts/11-error-probing.sh
```

## Concepts
- **RFC 9457 Problem Details** (`application/problem+json`): `type`, `title`, `status`, `detail`, `instance`, plus extension members (`traceId`, `errors`). ASP.NET Core has first-class support: `AddProblemDetails`, `IProblemDetailsService`, `IProblemDetailsWriter`, `CustomizeProblemDetails`.
- **Where errors come from** – three producers you must all cover: (1) **exceptions** → `UseExceptionHandler` + `IExceptionHandler` (.NET 8+; chainable handlers, one per concern); (2) **status codes without a body** (401/403/404/405/415…) → `UseStatusCodePages`; (3) **endpoint results** (`Results.BadRequest`, validation problems, custom results) which may or may not pass through the problem-details service – check each.
- **Content negotiation gotcha.** The default problem-details writer only writes when the request's `Accept` header allows JSON. A browser navigation sends `text/html`. Decide what your API does and test it.
- **Log the detail, return the reference.** The trace id (W3C `traceparent`, `Activity.Current.Id`, or `HttpContext.TraceIdentifier`) is the join key between the sanitised response and the full log entry. Log level by class of error: 5xx = error, expected 4xx = information/warning – not everything is an incident.
- **Fail closed.** If error handling itself fails, the response must still be generic. Never put exception text in a response by default; make debug detail a deliberate, off-by-default switch.
- **Uniform failure for security-relevant paths** (login, password reset, API-key checks): same status, same body, similar timing (step 02).
- **Mapping exceptions to status:** validation → 400, not found → 404, conflict/concurrency → 409, upstream failures → 502/504, everything else → 500. Cancelled requests (client disconnects) are not errors.
- **Headers:** `Server`/`X-Powered-By`/`X-AspNet-Version` disclose stack details; error responses shouldn't be cached (`no-store`).
- **Frontend:** parse problem details, show a human message and the reference, keep raw payloads out of the DOM.

## Your turn
Tasks:
1. Remove the developer exception page. Add a global exception handler that produces the generic problem and logs the real exception with the trace id; add the `DetailedErrors` switch.
2. Make status-code-only responses (401/403/404/405/415…) carry a problem body too.
3. Add the correlation data (trace id property + header, `no-store`) in *one* place so every producer gets it – including endpoint-produced errors (login failure, conflicts, 502 from the link-preview).
4. Make sure `Accept: text/html` cannot switch the format.
5. Hide the `Server` header. Update the SPA's request wrapper.
6. Run the suite – older tests that compare error *bodies* byte-for-byte will now need to ignore the trace id.

<details><summary>Hint 1 – where to look</summary>

`Program.cs` (services + the first middleware in the pipeline), `Endpoints/Api.cs` (`Fail()` in login, registration conflict), `Endpoints/Tools.cs` (502 answers), a new `Errors/` folder, `appsettings.json`, `frontend/src/api/client.ts`, and the two earlier tests that compare bodies (steps 02 and 06).
</details>

<details><summary>Hint 2 – which APIs</summary>

`AddProblemDetails(o => o.CustomizeProblemDetails = …)`, `AddExceptionHandler<T>()`, `UseExceptionHandler()`, `UseStatusCodePages()`, `IExceptionHandler.TryHandleAsync`, `IProblemDetailsService.TryWriteAsync(new ProblemDetailsContext …)`, `IProblemDetailsWriter` (register yours **before** `AddProblemDetails`), `Activity.Current?.Id`, `ILogger.LogError(exception, …)`, Kestrel `AddServerHeader = false`. Note: `Results.Problem(...)` does **not** run `CustomizeProblemDetails` – find out what does.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One handler class (switch on exception type → status/title; log; write through the service), one always-JSON writer (serialise by *runtime* type so validation `errors` survive), one tiny `IResult` that writes through `IProblemDetailsService` for endpoint-produced errors, a single customise callback adding `traceId`/`X-Trace-Id`/`Cache-Control`. Pipeline: exception handler first, status-code pages next.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=11"     # 5 tests; then the WHOLE suite
bash docs/attack-scripts/11-error-probing.sh
curl -sk -i https://localhost:5443/api/me | head        # no Server header, JSON 401 with X-Trace-Id
```
Checklist:
- [ ] `Step=11` green and the complete suite green
- [ ] Crash endpoint: body has only `title/status/traceId`; the *server log* has the exception with the same id
- [ ] Every error shape identical (script section 3); login failures identical (section 4)
- [ ] `Diagnostics__DetailedErrors=true` shows detail; unset → gone
- [ ] No `Server:` / `X-Powered-By:` header; `git grep UseDeveloperExceptionPage` is empty
- [ ] SPA shows "…(ref 00-…)" for a failed request

## Pitfalls
- Leaving `UseDeveloperExceptionPage` (or `ASPNETCORE_ENVIRONMENT=Development`) on anywhere reachable from the internet.
- `Results.Problem()` / `Results.BadRequest(new {…})` in endpoints: different shape, no trace id. Use one mechanism.
- The default writer is silent for `Accept: text/html`; without a fallback you get an empty `500`.
- Serialising `ProblemDetails` by its base type: `HttpValidationProblemDetails.Errors` silently disappears (validation tests failed until the runtime type was used).
- Logging the response body but not the exception, or logging secrets contained in exception messages (connection strings in `SqlException`, tokens in URLs).
- Returning `detail = ex.Message` "just for now".
- Error messages that differ by *cause* on security paths ("user not found" vs "wrong password").
- Catching `Exception` in endpoints and returning `200` with an `error` field.
- `Cache-Control` missing on errors: a proxy may cache your `404`/`500` and serve it to everybody.
- Treating client aborts (`OperationCanceledException`) as `500` floods your alerts.

## Further reading
- Handle errors in ASP.NET Core APIs (Problem Details, `IExceptionHandler`) – https://learn.microsoft.com/aspnet/core/fundamentals/error-handling
- Handle errors in minimal APIs – https://learn.microsoft.com/aspnet/core/fundamentals/minimal-apis/handle-errors
- RFC 9457 – Problem Details for HTTP APIs
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- OWASP Error Handling Cheat Sheet, Logging Cheat Sheet; OWASP Top 10:2025 A02 Security Misconfiguration and A10 Mishandling of Exceptional Conditions; API Security Top 10 API8

Stuck or done? Compare with the solution: [`docs/solutions/11-error-handling.md`](solutions/11-error-handling.md) and `solutions/11-error-handling.patch` (applies on top of 01–10).
