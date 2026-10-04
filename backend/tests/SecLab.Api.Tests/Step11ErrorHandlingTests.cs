using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecLab.Api.Tests;

// Step 11 – Error handling. Contract: docs/11-error-handling.md.
[Trait("Step", "11")]
public class Step11ErrorHandlingTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly List<IDisposable> _disposables = [];
    public void Dispose() { foreach (var d in _disposables) d.Dispose(); }

    Harness Start(params (string, string)[] settings)
    {
        if (settings.Length > 0) _disposables.Add(new EnvScope(settings));
        var h = new Harness(factory);
        _disposables.Add(h);
        return h;
    }

    static string[] Leaks =>
    [
        "Boom", "connection string", "Server=", "User Id", "InvalidOperationException", "System.", "   at ", "StackTrace",
        ".cs:line", "SecLab.Api.Endpoints", "/home/", "\\Users\\", "Microsoft.AspNetCore", "Exception",
    ];

    static async Task<(HttpResponseMessage Res, JsonElement Body, string Raw)> Read(HttpResponseMessage res)
    {
        var raw = await res.Content.ReadAsStringAsync();
        var body = string.IsNullOrWhiteSpace(raw) ? default : JsonDocument.Parse(raw).RootElement.Clone();
        return (res, body, raw);
    }

    static void AssertProblem(HttpResponseMessage res, JsonElement body, HttpStatusCode expected)
    {
        Assert.Equal(expected, res.StatusCode);
        Assert.Equal("application/problem+json", res.Content.Headers.ContentType?.MediaType);
        Assert.Equal((int)expected, body.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("title").GetString()));
        var traceId = body.GetProperty("traceId").GetString();
        Assert.False(string.IsNullOrWhiteSpace(traceId));
        Assert.True(res.Headers.TryGetValues("X-Trace-Id", out var header), "missing X-Trace-Id header");
        Assert.Equal(traceId, header!.Single());
        Assert.Contains("no-store", res.Headers.CacheControl?.ToString() ?? "");
    }

    // ---------- unhandled exceptions ----------

    [Fact]
    public async Task An_unhandled_exception_becomes_a_generic_500_that_tells_an_attacker_nothing()
    {
        var admin = Start().NewPerson("Admin");

        var (res, body, raw) = await Read(await admin.Http.GetAsync("/api/debug/crash"));

        AssertProblem(res, body, HttpStatusCode.InternalServerError);
        foreach (var leak in Leaks) Assert.DoesNotContain(leak, raw, StringComparison.OrdinalIgnoreCase);
        Assert.False(body.TryGetProperty("detail", out var d) && !string.IsNullOrEmpty(d.GetString()), "no 'detail' outside explicit debug mode");
        Assert.False(body.TryGetProperty("exception", out _));
        Assert.False(body.TryGetProperty("stackTrace", out _));
    }

    [Fact]
    public async Task Clients_that_ask_for_html_still_get_json_never_a_developer_page()
    {
        var admin = Start().NewPerson("Admin");
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/debug/crash");
        req.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml");

        var (res, body, raw) = await Read(await admin.Http.SendAsync(req));

        AssertProblem(res, body, HttpStatusCode.InternalServerError);
        Assert.DoesNotContain("<html", raw, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Detailed_errors_exist_only_behind_an_explicit_switch()
    {
        var admin = Start(("Diagnostics__DetailedErrors", "true")).NewPerson("Admin");

        var (res, body, raw) = await Read(await admin.Http.GetAsync("/api/debug/crash"));

        Assert.Equal(HttpStatusCode.InternalServerError, res.StatusCode);
        Assert.Equal("application/problem+json", res.Content.Headers.ContentType?.MediaType);
        Assert.Contains("Boom", raw);                 // opt-in only: developers on their own machine
    }

    // ---------- every kind of failure has the same shape ----------

    [Fact]
    public async Task Client_errors_use_the_same_problem_format()
    {
        var h = Start();
        var user = h.NewPerson();

        var unauthenticated = await Read(await h.Anonymous().GetAsync("/api/me"));
        AssertProblem(unauthenticated.Res, unauthenticated.Body, HttpStatusCode.Unauthorized);

        var forbidden = await Read(await user.Http.GetAsync("/api/admin/users"));
        AssertProblem(forbidden.Res, forbidden.Body, HttpStatusCode.Forbidden);

        var notFound = await Read(await user.Http.GetAsync("/api/does-not-exist"));
        AssertProblem(notFound.Res, notFound.Body, HttpStatusCode.NotFound);

        var missingUser = await Read(await user.Http.GetAsync("/api/users/2000000000"));
        AssertProblem(missingUser.Res, missingUser.Body, HttpStatusCode.NotFound);

        var wrongMethod = await Read(await user.Http.PatchAsync("/api/blogs", JsonContent.Create(new { })));
        AssertProblem(wrongMethod.Res, wrongMethod.Body, HttpStatusCode.MethodNotAllowed);

        var wrongMedia = await Read(await user.Http.PostAsync("/api/blogs", new StringContent("x", Encoding.UTF8, "text/plain")));
        AssertProblem(wrongMedia.Res, wrongMedia.Body, HttpStatusCode.UnsupportedMediaType);

        var invalid = await Read(await user.Http.PostAsJsonAsync("/api/blogs", new { title = "", body = "" }));
        AssertProblem(invalid.Res, invalid.Body, HttpStatusCode.BadRequest);
        Assert.True(invalid.Body.TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task Every_error_gets_its_own_trace_id_and_success_responses_carry_no_trace_header()
    {
        var user = Start().NewPerson();

        var a = await Read(await user.Http.GetAsync("/api/does-not-exist"));
        var b = await Read(await user.Http.GetAsync("/api/does-not-exist"));
        Assert.NotEqual(a.Body.GetProperty("traceId").GetString(), b.Body.GetProperty("traceId").GetString());

        var ok = await user.Http.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.False(ok.Headers.Contains("X-Trace-Id"));                                  // the correlation header belongs to error responses
    }

    // ---------- authentication failures do not reveal which part was wrong ----------

    [Fact]
    public async Task Failed_logins_look_identical_and_carry_no_hints()
    {
        var anon = Start().Anonymous();
        var unknown = await Read(await anon.PostAsJsonAsync("/api/auth/login", new { username = "nobody-" + Guid.NewGuid().ToString("N")[..6], password = "wrong-password-1" }));
        var wrong = await Read(await anon.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = "wrong-password-1" }));

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.Res.StatusCode);
        Assert.Equal(unknown.Res.StatusCode, wrong.Res.StatusCode);
        Assert.Equal(unknown.Body.GetProperty("title").GetString(), wrong.Body.GetProperty("title").GetString());
        Assert.DoesNotContain("password", wrong.Raw.Replace("\"title\"", ""), StringComparison.OrdinalIgnoreCase);   // no "wrong password" / "unknown user" wording
        Assert.DoesNotContain("user", wrong.Raw.Replace("traceId", ""), StringComparison.OrdinalIgnoreCase);
    }
}
