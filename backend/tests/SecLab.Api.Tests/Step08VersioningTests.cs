using System.Globalization;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecLab.Api.Tests;

// Step 08 – API versioning. Contract: docs/08-api-versioning.md.
// Versions: 1.0 (default, deprecated, with a sunset date from config Api:V1SunsetDate) and 2.0 (current).
// The version is read from the `api-version` header or the `api-version` query parameter.
[Trait("Step", "08")]
public class Step08VersioningTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
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

    static async Task<HttpResponseMessage> Get(HttpClient c, string url, string? versionHeader = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (versionHeader is not null) req.Headers.Add("api-version", versionHeader);
        return await c.SendAsync(req);
    }

    static string Header(HttpResponseMessage res, string name) => res.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : "";
    static async Task<JsonElement> Json(HttpResponseMessage res) => JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.Clone();

    [Fact]
    public async Task Unversioned_requests_get_version_1_and_are_told_it_is_deprecated_and_when_it_ends()
    {
        var p = Start().NewPerson();

        var res = await Get(p.Http, "/api/blogs");

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal(JsonValueKind.Array, (await Json(res)).ValueKind);                       // v1 shape: a bare array
        Assert.Contains("2.0", Header(res, "api-supported-versions"));       // supported = current versions
        Assert.Contains("1.0", Header(res, "api-deprecated-versions"));      // deprecated = still served, on its way out
        Assert.True(res.Headers.Contains("Deprecation"), "missing Deprecation header");
        Assert.True(res.Headers.TryGetValues("Sunset", out var sunset), "missing Sunset header");
        Assert.True(DateTimeOffset.Parse(sunset!.Single(), CultureInfo.InvariantCulture) > DateTimeOffset.UtcNow, "the default sunset date should lie in the future");
    }

    [Fact]
    public async Task Version_2_is_selected_by_header_or_query_string_and_is_not_deprecated()
    {
        var p = Start().NewPerson();

        foreach (var res in new[] { await Get(p.Http, "/api/blogs", "2.0"), await Get(p.Http, "/api/blogs?api-version=2.0") })
        {
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            var body = await Json(res);
            Assert.Equal(JsonValueKind.Object, body.ValueKind);
            foreach (var field in new[] { "items", "page", "pageSize", "total" }) Assert.True(body.TryGetProperty(field, out _), $"v2 envelope lacks '{field}'");
            Assert.False(res.Headers.Contains("Sunset")); Assert.False(res.Headers.Contains("Deprecation"));
            Assert.Contains("2.0", Header(res, "api-supported-versions"));
        }
    }

    [Fact]
    public async Task Version_2_pages_are_bounded()
    {
        var p = Start().NewPerson();
        for (var i = 0; i < 3; i++) await p.Http.PostAsync("/api/blogs", JsonBody(new { title = "t" + i, body = "b" }));

        var page = await Json(await Get(p.Http, "/api/blogs?pageSize=2&page=1", "2.0"));
        Assert.True(page.GetProperty("items").GetArrayLength() <= 2);
        Assert.Equal(2, page.GetProperty("pageSize").GetInt32());
        Assert.True(page.GetProperty("total").GetInt32() >= 3);

        Assert.Equal(HttpStatusCode.BadRequest, (await Get(p.Http, "/api/blogs?pageSize=1000", "2.0")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Get(p.Http, "/api/blogs?pageSize=0", "2.0")).StatusCode);
        Assert.Equal(0, (await Json(await Get(p.Http, "/api/blogs?page=100000&pageSize=10", "2.0"))).GetProperty("items").GetArrayLength());
    }

    static StringContent JsonBody(object o) => new(JsonSerializer.Serialize(o), System.Text.Encoding.UTF8, "application/json");

    [Fact]
    public async Task Unknown_malformed_and_contradicting_versions_are_rejected_not_guessed()
    {
        var p = Start().NewPerson();

        var unsupported = await Get(p.Http, "/api/blogs", "3.0");
        Assert.Equal(HttpStatusCode.BadRequest, unsupported.StatusCode);
        Assert.Contains("json", unsupported.Content.Headers.ContentType?.MediaType);

        Assert.Equal(HttpStatusCode.BadRequest, (await Get(p.Http, "/api/blogs", "banana")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Get(p.Http, "/api/blogs?api-version=2.0", "1.0")).StatusCode);   // two different versions in one request
    }

    [Fact]
    public async Task After_the_sunset_date_version_1_is_gone_but_version_2_keeps_working()
    {
        var p = Start(("Api__V1SunsetDate", "2000-01-01")).NewPerson();

        var v1 = await Get(p.Http, "/api/blogs");                       // unversioned == 1.0
        Assert.Equal(HttpStatusCode.Gone, v1.StatusCode);
        Assert.Equal(HttpStatusCode.Gone, (await Get(p.Http, "/api/blogs", "1.0")).StatusCode);
        Assert.Contains("json", v1.Content.Headers.ContentType?.MediaType);

        Assert.Equal(HttpStatusCode.OK, (await Get(p.Http, "/api/blogs", "2.0")).StatusCode);
    }

    [Fact]
    public async Task Choosing_a_version_never_changes_who_may_call()
    {
        var h = Start();
        var anon = h.Anonymous();
        foreach (var version in new string?[] { null, "1.0", "2.0" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await Get(anon, "/api/blogs", version)).StatusCode);

        var p = h.NewPerson();
        foreach (var version in new string?[] { null, "1.0", "2.0" })
            Assert.Equal(HttpStatusCode.OK, (await Get(p.Http, "/api/me", version)).StatusCode);       // unchanged endpoints work in every version
        Assert.Equal(HttpStatusCode.Forbidden, (await Get(p.Http, "/api/admin/users", "2.0")).StatusCode);   // and admin routes stay admin-only
    }
}
