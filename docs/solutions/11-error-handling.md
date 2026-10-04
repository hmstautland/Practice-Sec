# Solution – 11 Error handling

> Spoiler. Try the step yourself first: [`../11-error-handling.md`](../11-error-handling.md). Patch: `solutions/11-error-handling.patch` (after 01–10).

## What was verified
- **150 tests** (steps 01–11) pass on a fresh database.
- Live `11-error-probing.sh` against real Keycloak tokens: the crash produced `{"title":"An unexpected error occurred.","status":500,"traceId":"00-…"}` with `x-trace-id`, `cache-control: no-cache,no-store` and **no** `Server` header, even for `Accept: text/html`; the *server log* contained `Unhandled exception. TraceId=00-… Path=/api/debug/crash` with the exception; 404/403/401/405 all had `status`, `title`, `traceId`; both login failures printed `{"title":"Authentication failed.","status":401}`.
- Frontend builds. Not click-tested.

## Pipeline
```csharp
builder.Services.AddSingleton<IProblemDetailsWriter, AlwaysJsonProblemWriter>();   // tried first
builder.Services.AddProblemDetails(o => o.CustomizeProblemDetails = ctx =>
{
    var traceId = Activity.Current?.Id ?? ctx.HttpContext.TraceIdentifier;
    ctx.ProblemDetails.Extensions["traceId"] = traceId;
    ctx.HttpContext.Response.Headers["X-Trace-Id"] = traceId;
    ctx.HttpContext.Response.Headers.CacheControl = "no-store";
});
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
...
app.UseExceptionHandler();      // replaces UseDeveloperExceptionPage
app.UseStatusCodePages();       // body for bare 401/403/404/405/415
```
`Kestrel: AddServerHeader = false`.

## The three producers of errors
1. **Exceptions** → `GlobalExceptionHandler : IExceptionHandler`: `BadHttpRequestException` → its own status (400/413…), `DbUpdateConcurrencyException` → 409, client abort → swallowed, else 500. It logs with `LogError(exception, "… TraceId={TraceId} Path={Path}")` for 5xx (a warning without the stack for 4xx), then writes a generic `ProblemDetails` through `IProblemDetailsService`. `Diagnostics:DetailedErrors=true` adds `detail = exception.ToString()`.
2. **Bare status codes** → `UseStatusCodePages()` (it uses the problem-details service when registered).
3. **Endpoint results** → `Problems.Create(status, title)`, a small `IResult` that calls `IProblemDetailsService`. `Results.Problem(...)` was used before and **did not** add the trace id or headers (it bypasses `CustomizeProblemDetails`), so login failures, registration conflicts and the link-preview `502`s now use `Problems.Create`. Validation errors from `AddValidation()` already go through the service.

## `AlwaysJsonProblemWriter`
Two lessons in one class:
- The default writer requires the request to *accept* JSON; with `Accept: text/html` the 500 body was **empty** (the first test run showed `Content-Type: null`).
- `WriteAsJsonAsync(problem, options)` serialises by the declared type `ProblemDetails`; `HttpValidationProblemDetails.Errors` vanished and ~15 validation tests failed. The fix is the overload taking `problem.GetType()`.
It also calls `CustomizeProblemDetails` itself, because it replaces the code path that normally does.

## Tests that had to change
Steps 02 and 06 compared two error bodies byte-for-byte to prove "unknown user and wrong password are indistinguishable". Bodies now include a per-request `traceId`, so those tests strip it first (the meaningful invariant is *same status and same title*).

## Frontend
`client.ts`: `ApiError` (status, traceId, field errors) built from the problem body; message = `title` + field messages + `(ref <traceId>)`. (Constructor parameter properties are not allowed by the template's `erasableSyntaxOnly`, so fields are declared explicitly.)

## Deliberately left open
- Logging is still plain `ILogger` text to the console; structure, redaction, correlation across services and alerting are step 12.
- `type` URIs are the library defaults (RFC 9110 sections), not links to your own error catalogue.
- Only the web tier is covered; the gateway (step 14) should return the same shape for its own errors.
- Rate limiting (`429`) and API-version errors already used problem+json and pass the same tests.
