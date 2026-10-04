using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SecLab.Gateway.Tests;

// Step 14 – the API gateway. Contract: docs/14-api-gateway.md.
// Config keys: Gateway:RateLimitPerMinute (per client IP), Gateway:AdminNetworks (CIDR list), AllowedHosts, standard YARP "ReverseProxy" section.
[Trait("Step", "14")]
public class Step14GatewayTests
{
    static HttpRequestMessage Req(HttpMethod m, string url, params (string, string)[] headers)
    {
        var r = new HttpRequestMessage(m, url);
        foreach (var (k, v) in headers) r.Headers.TryAddWithoutValidation(k, v);
        return r;
    }

    static readonly (string, string) Bearer = ("Authorization", "Bearer some.opaque.token");

    static async Task AssertProblem(HttpResponseMessage res, HttpStatusCode status)
    {
        Assert.Equal(status, res.StatusCode);
        Assert.Contains("problem+json", res.Content.Headers.ContentType?.MediaType);
        var body = JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal((int)status, body.GetProperty("status").GetInt32());
    }

    // ---------------- routing: only what is published ----------------

    [Fact]
    public async Task Api_calls_are_proxied_with_path_query_method_and_body_unchanged()
    {
        using var gw = new Gw();
        var req = Req(HttpMethod.Post, "/api/blogs?x=1&y=%C3%A6", Bearer);
        req.Content = new StringContent("{\"title\":\"t\"}", Encoding.UTF8, "application/json");

        var res = await gw.Client().SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("\"from\":\"api\"", await res.Content.ReadAsStringAsync());
        var seen = Assert.Single(gw.Api.Requests);
        Assert.Equal("/api/blogs?x=1&y=%C3%A6", seen.RequestUri!.PathAndQuery);
        Assert.Equal(HttpMethod.Post, seen.Method);
        Assert.Equal("{\"title\":\"t\"}", await seen.Content!.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/swagger")]
    [InlineData("/health/live")]                 // probes are for the platform, not for the internet
    [InlineData("/health/ready")]
    [InlineData("/api2/blogs")]
    [InlineData("/apis")]
    [InlineData("/avatars/x.png/../../secret")]
    [InlineData("/avatarsx/a.png")]
    [InlineData("/metrics")]
    public async Task Anything_that_is_not_a_published_route_stops_at_the_gateway(string path)
    {
        using var gw = new Gw();
        var res = await gw.Client().SendAsync(Req(HttpMethod.Get, path, Bearer));
        await AssertProblem(res, HttpStatusCode.NotFound);
        Assert.Empty(gw.Api.Requests);
    }

    [Fact]
    public async Task Avatar_images_are_published_read_only_and_without_credentials_because_img_tags_cannot_send_tokens()
    {
        using var gw = new Gw();
        var c = gw.Client();

        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Req(HttpMethod.Get, "/avatars/0123456789abcdef.png"))).StatusCode);
        Assert.Single(gw.Api.Requests);
        Assert.Equal("/avatars/0123456789abcdef.png", gw.Api.Requests[0].RequestUri!.AbsolutePath);

        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Delete })
            Assert.True((await c.SendAsync(Req(method, "/avatars/0123456789abcdef.png", Bearer))).StatusCode is HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotFound);
        Assert.Single(gw.Api.Requests);        // only the GET got through
    }

    [Theory]
    [InlineData("/api/debug/crash")]
    [InlineData("/api/admin/users")]
    [InlineData("/API/Admin/users")]
    [InlineData("/api/%61dmin/users")]           // percent-encoded 'a'
    [InlineData("/api/./admin/users")]
    public async Task Admin_and_debug_routes_do_not_exist_from_outside_the_admin_network(string path)
    {
        using var gw = new Gw();
        var res = await gw.Client().SendAsync(Req(HttpMethod.Get, path, Bearer, ("X-Test-Remote-Ip", "203.0.113.50")));
        await AssertProblem(res, HttpStatusCode.NotFound);
        Assert.Empty(gw.Api.Requests);
    }

    [Fact]
    public async Task Admin_routes_are_reachable_from_the_admin_network()
    {
        using var gw = new Gw();
        var res = await gw.Client().SendAsync(Req(HttpMethod.Get, "/api/admin/users", Bearer, ("X-Test-Remote-Ip", "127.0.0.1")));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Single(gw.Api.Requests);
    }

    [Theory]
    [InlineData("TRACE")]
    [InlineData("PATCH")]
    [InlineData("CONNECT")]
    [InlineData("PROPFIND")]
    public async Task Methods_the_api_does_not_use_are_refused_at_the_edge(string method)
    {
        using var gw = new Gw();
        var res = await gw.Client().SendAsync(Req(new HttpMethod(method), "/api/blogs", Bearer));
        Assert.True(res.StatusCode is HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotFound, $"got {(int)res.StatusCode}");
        Assert.Empty(gw.Api.Requests);
    }

    // ---------------- header hygiene ----------------

    [Fact]
    public async Task Client_supplied_forwarding_and_internal_headers_are_dropped_and_replaced_with_the_truth()
    {
        using var gw = new Gw();
        var req = Req(HttpMethod.Get, "/api/blogs", Bearer, ("X-Test-Remote-Ip", "198.51.100.23"),
            ("X-Forwarded-For", "10.9.9.9"), ("X-Forwarded-Host", "evil.example"), ("X-Forwarded-Proto", "http"),
            ("Forwarded", "for=10.9.9.9;host=evil.example"), ("X-Real-IP", "10.9.9.9"), ("X-Gateway-Auth", "let-me-in"), ("X-Original-URL", "/api/admin/users"));

        await gw.Client().SendAsync(req);

        var seen = Assert.Single(gw.Api.Requests);
        Assert.Equal("198.51.100.23", string.Join(",", seen.Headers.GetValues("X-Forwarded-For")));      // exactly the address the gateway saw, nothing appended to
        Assert.Equal("https", string.Join(",", seen.Headers.GetValues("X-Forwarded-Proto")));
        Assert.DoesNotContain("evil.example", string.Join(",", seen.Headers.TryGetValues("X-Forwarded-Host", out var h) ? h : []));
        foreach (var gone in new[] { "Forwarded", "X-Real-IP", "X-Gateway-Auth", "X-Original-URL" })
            Assert.False(seen.Headers.Contains(gone), $"{gone} reached the API");
        Assert.True(seen.Headers.Contains("Authorization"), "the bearer token must pass through");
    }

    [Fact]
    public async Task Response_headers_that_reveal_the_stack_are_removed_and_security_headers_added()
    {
        using var gw = new Gw(respond: _ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
            r.Headers.TryAddWithoutValidation("Server", "Kestrel"); r.Headers.TryAddWithoutValidation("X-Powered-By", "ASP.NET"); r.Headers.TryAddWithoutValidation("X-AspNet-Version", "10");
            return r;
        });

        var res = await gw.Client().SendAsync(Req(HttpMethod.Get, "/api/blogs", Bearer));

        foreach (var leak in new[] { "Server", "X-Powered-By", "X-AspNet-Version" }) Assert.False(res.Headers.Contains(leak), leak);
        Assert.Equal("nosniff", res.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.True(res.Headers.Contains("Referrer-Policy"));
    }

    // ---------------- authentication at the edge (coarse) ----------------

    [Fact]
    public async Task Requests_without_any_credential_are_rejected_at_the_edge_except_the_public_routes()
    {
        using var gw = new Gw();
        var c = gw.Client();

        await AssertProblem(await c.SendAsync(Req(HttpMethod.Get, "/api/me")), HttpStatusCode.Unauthorized);
        await AssertProblem(await c.SendAsync(Req(HttpMethod.Get, "/api/me", ("Authorization", "Basic dXNlcjpwYXNz"))), HttpStatusCode.Unauthorized);
        Assert.Empty(gw.Api.Requests);

        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Req(HttpMethod.Get, "/api/me", Bearer))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(Req(HttpMethod.Get, "/api/partner/blogs", ("X-Api-Key", "sl_ABCDEFGH_" + new string('x', 40))))).StatusCode);
        var login = Req(HttpMethod.Post, "/api/auth/login"); login.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(login)).StatusCode);
        var preflight = Req(HttpMethod.Options, "/api/me", ("Origin", "https://localhost:5173"), ("Access-Control-Request-Method", "GET"));
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(preflight)).StatusCode);      // browsers send no credentials on preflight
        Assert.Equal(4, gw.Api.Requests.Count);
    }

    // ---------------- limits ----------------

    [Fact]
    public async Task Oversized_bodies_are_refused_before_they_reach_the_api()
    {
        using var gw = new Gw();
        var req = Req(HttpMethod.Post, "/api/blogs", Bearer);
        req.Content = new ByteArrayContent(new byte[4 * 1024 * 1024]);
        req.Content.Headers.ContentType = new("application/json");

        var res = await gw.Client().SendAsync(req);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, res.StatusCode);
        Assert.Empty(gw.Api.Requests);
    }

    [Fact]
    public async Task Each_client_address_gets_a_fixed_allowance_and_then_429_with_retry_after()
    {
        using var gw = new Gw(settings: [("Gateway__RateLimitPerMinute", "3")]);
        var c = gw.Client();
        Task<HttpResponseMessage> Call(string ip) => c.SendAsync(Req(HttpMethod.Get, "/api/blogs", Bearer, ("X-Test-Remote-Ip", ip), ("X-Forwarded-For", "1.1.1.1")));

        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.OK, (await Call("203.0.113.1")).StatusCode);
        var limited = await Call("203.0.113.1");
        await AssertProblem(limited, HttpStatusCode.TooManyRequests);
        Assert.True(limited.Headers.Contains("Retry-After"));

        Assert.Equal(HttpStatusCode.OK, (await Call("203.0.113.2")).StatusCode);      // another client is unaffected
        Assert.Equal(4, gw.Api.Requests.Count);                                        // the 429 never reached the API
    }

    // ---------------- transport ----------------

    [Fact]
    public async Task Plain_http_is_redirected_and_unknown_host_names_are_refused()
    {
        using var gw = new Gw();
        var redirect = await gw.Client("http://localhost").SendAsync(Req(HttpMethod.Get, "/api/blogs"));
        Assert.True(redirect.StatusCode is HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect);
        Assert.Equal("https", redirect.Headers.Location?.Scheme);

        var evil = Req(HttpMethod.Get, "/api/blogs", Bearer); evil.Headers.Host = "evil.example";
        Assert.Equal(HttpStatusCode.BadRequest, (await gw.Client().SendAsync(evil)).StatusCode);
        Assert.Empty(gw.Api.Requests);
    }

    [Fact]
    public async Task Hsts_is_sent_outside_development()
    {
        using var gw = new Gw(environment: "Production");
        var res = await gw.Client("https://seclab.example").SendAsync(Req(HttpMethod.Get, "/api/blogs", Bearer));
        Assert.True(res.Headers.Contains("Strict-Transport-Security"));
    }

    // ---------------- failure behaviour ----------------

    [Fact]
    public async Task When_the_api_is_down_the_client_gets_a_generic_bad_gateway_and_no_internal_addresses()
    {
        using var gw = new Gw(respond: _ => throw new HttpRequestException("Connection refused (127.0.0.1:5100) secret-internal-detail"));

        var res = await gw.Client().SendAsync(Req(HttpMethod.Get, "/api/blogs", Bearer));

        Assert.True(res.StatusCode is HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout);
        var text = await res.Content.ReadAsStringAsync();
        Assert.DoesNotContain("127.0.0.1", text); Assert.DoesNotContain("5100", text); Assert.DoesNotContain("secret-internal-detail", text);
        Assert.Contains("problem+json", res.Content.Headers.ContentType?.MediaType);
    }

    // ---------------- configuration as code ----------------

    [Fact]
    public void Every_route_is_narrow_has_a_timeout_and_no_wildcard_methods()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "backend", "src", "SecLab.Gateway", "appsettings.json"))) dir = dir.Parent;
        Assert.NotNull(dir);
        var json = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!.FullName, "backend", "src", "SecLab.Gateway", "appsettings.json"))).RootElement;

        var routes = json.GetProperty("ReverseProxy").GetProperty("Routes").EnumerateObject().ToList();
        Assert.NotEmpty(routes);
        foreach (var (name, route) in routes.Select(r => (r.Name, r.Value)))
        {
            var match = route.GetProperty("Match");
            Assert.True(match.TryGetProperty("Methods", out var methods) && methods.GetArrayLength() > 0, $"{name}: list the HTTP methods explicitly");
            Assert.DoesNotContain(methods.EnumerateArray().Select(m => m.GetString()), m => m is "*" or "TRACE" or "CONNECT");
            Assert.True(route.TryGetProperty("Timeout", out var timeout) && TimeSpan.Parse(timeout.GetString()!) <= TimeSpan.FromSeconds(60), $"{name}: needs a Timeout of at most 60 s");
            var pathPattern = match.GetProperty("Path").GetString()!;
            Assert.True(pathPattern.StartsWith("/api/") || pathPattern.StartsWith("/avatars/"), $"{name}: only /api and /avatars are published");
            if (pathPattern.StartsWith("/avatars/")) Assert.All(methods.EnumerateArray().Select(m => m.GetString()), m => Assert.True(m is "GET" or "HEAD", $"{name}: avatars are read-only"));
        }
        var destinations = json.GetProperty("ReverseProxy").GetProperty("Clusters").EnumerateObject()
            .SelectMany(c => c.Value.GetProperty("Destinations").EnumerateObject()).Select(d => d.Value.GetProperty("Address").GetString()!).ToList();
        Assert.All(destinations, a => Assert.True(a.StartsWith("http://127.0.0.1") || a.StartsWith("http://localhost") || a.StartsWith("https://"), $"unexpected destination {a}"));
    }
}
