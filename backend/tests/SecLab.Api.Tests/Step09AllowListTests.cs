using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecLab.Api.Tests;

// Step 09 – Allow-listing. Contract: docs/09-allow-listing.md.
// Config keys: Cors:AllowedOrigins, AllowedHosts, Admin:AllowedNetworks, Outbound:AllowedHosts.
[Trait("Step", "09")]
public class Step09AllowListTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    const string Frontend = "https://localhost:5173";
    readonly List<IDisposable> _disposables = [];
    readonly List<string> _createdFiles = [];

    public void Dispose()
    {
        foreach (var d in _disposables) d.Dispose();
        foreach (var f in _createdFiles) try { File.Delete(f); } catch { /* best effort */ }
    }

    Harness Start(Action<IServiceCollection>? services = null, params (string, string)[] settings)
    {
        if (settings.Length > 0) _disposables.Add(new EnvScope(settings));
        var h = new Harness(factory, services);
        _disposables.Add(h);
        return h;
    }

    static HttpRequestMessage Req(HttpMethod m, string url, params (string, string)[] headers)
    {
        var r = new HttpRequestMessage(m, url);
        foreach (var (k, v) in headers) r.Headers.TryAddWithoutValidation(k, v);
        return r;
    }

    static string Header(HttpResponseMessage r, string name) => r.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : "";

    // ================= CORS =================

    [Fact]
    public async Task A_preflight_from_the_real_frontend_is_allowed_for_exactly_the_listed_methods_and_headers()
    {
        var res = await Start().Anonymous().SendAsync(Req(HttpMethod.Options, "/api/blogs",
            ("Origin", Frontend), ("Access-Control-Request-Method", "DELETE"), ("Access-Control-Request-Headers", "authorization,api-version,content-type")));

        Assert.True(res.IsSuccessStatusCode, $"preflight returned {(int)res.StatusCode}");
        Assert.Equal(Frontend, Header(res, "Access-Control-Allow-Origin"));
        var methods = Header(res, "Access-Control-Allow-Methods").ToUpperInvariant();
        Assert.Contains("DELETE", methods); Assert.DoesNotContain("PATCH", methods); Assert.DoesNotContain("*", methods);
        var headers = Header(res, "Access-Control-Allow-Headers").ToLowerInvariant();
        Assert.Contains("authorization", headers); Assert.DoesNotContain("*", headers);
        Assert.False(res.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [Theory]
    [InlineData("https://evil.example")]
    [InlineData("https://localhost:5173.evil.example")]
    [InlineData("http://localhost:5173")]            // wrong scheme
    [InlineData("https://LOCALHOST:5173.")]
    [InlineData("null")]
    public async Task Other_origins_get_no_cors_permission_at_all(string origin)
    {
        var anon = Start().Anonymous();

        var preflight = await anon.SendAsync(Req(HttpMethod.Options, "/api/blogs", ("Origin", origin), ("Access-Control-Request-Method", "GET")));
        var simple = await anon.SendAsync(Req(HttpMethod.Get, "/api/blogs", ("Origin", origin)));

        foreach (var res in new[] { preflight, simple })
        {
            Assert.False(res.Headers.Contains("Access-Control-Allow-Origin"), $"ACAO leaked to {origin}: {Header(res, "Access-Control-Allow-Origin")}");
            Assert.False(res.Headers.Contains("Access-Control-Allow-Credentials"));
        }
    }

    [Fact]
    public async Task Machine_credentials_and_unlisted_methods_and_headers_are_not_allowed_from_browsers()
    {
        var anon = Start().Anonymous();
        var keyHeader = await anon.SendAsync(Req(HttpMethod.Options, "/api/partner/blogs", ("Origin", Frontend), ("Access-Control-Request-Method", "GET"), ("Access-Control-Request-Headers", "x-api-key")));
        Assert.DoesNotContain("x-api-key", Header(keyHeader, "Access-Control-Allow-Headers").ToLowerInvariant());

        var patch = await anon.SendAsync(Req(HttpMethod.Options, "/api/blogs", ("Origin", Frontend), ("Access-Control-Request-Method", "PATCH")));
        Assert.DoesNotContain("PATCH", Header(patch, "Access-Control-Allow-Methods").ToUpperInvariant());
    }

    [Fact]
    public async Task Allowed_origins_are_echoed_never_star_and_caches_are_told_to_vary()
    {
        var res = await Start().Anonymous().SendAsync(Req(HttpMethod.Get, "/api/blogs", ("Origin", Frontend)));
        Assert.Equal(Frontend, Header(res, "Access-Control-Allow-Origin"));
        Assert.Contains("Origin", Header(res, "Vary"));
    }

    // ================= hosts =================

    [Fact]
    public async Task Requests_for_a_host_name_we_do_not_serve_are_refused()
    {
        var anon = Start().Anonymous();
        var evil = Req(HttpMethod.Get, "/api/blogs"); evil.Headers.Host = "evil.example";
        Assert.Equal(HttpStatusCode.BadRequest, (await anon.SendAsync(evil)).StatusCode);

        var ok = Req(HttpMethod.Get, "/api/blogs"); ok.Headers.Host = "localhost";
        Assert.NotEqual(HttpStatusCode.BadRequest, (await anon.SendAsync(ok)).StatusCode);
    }

    // ================= admin network =================

    [Fact]
    public async Task Admin_functions_work_only_from_listed_networks_even_for_admins()
    {
        var admin = Start().NewPerson("Admin"); var user = Start().NewPerson();   // separate hosts are fine here
        Task<HttpStatusCode> Call(Harness.Person p, string url, string? ip)
        {
            var r = Req(HttpMethod.Get, url); if (ip is not null) r.Headers.Add("X-Test-Remote-Ip", ip);
            return p.Http.SendAsync(r).ContinueWith(t => t.Result.StatusCode);
        }

        Assert.Equal(HttpStatusCode.OK, await Call(admin, "/api/admin/users", "127.0.0.1"));
        Assert.Equal(HttpStatusCode.OK, await Call(admin, "/api/admin/users", "::1"));
        Assert.Equal(HttpStatusCode.Forbidden, await Call(admin, "/api/admin/users", "203.0.113.9"));       // right role, wrong place
        Assert.Equal(HttpStatusCode.Forbidden, await Call(admin, "/api/debug/crash", "198.51.100.7"));
        Assert.Equal(HttpStatusCode.Forbidden, await Call(user, "/api/admin/users", "127.0.0.1"));          // right place, wrong role
    }

    // ================= avatar file types =================

    static readonly byte[] Png = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==");

    async Task<HttpResponseMessage> Upload(Harness.Person p, byte[] content, string fileName, string contentType)
    {
        var part = new ByteArrayContent(content);
        part.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        using var form = new MultipartFormDataContent { { part, "file", fileName } };
        return await p.Http.PostAsync($"/api/users/{p.Id}/avatar", form);
    }

    [Fact]
    public async Task Only_real_png_jpeg_and_webp_images_are_accepted_whatever_the_name_or_declared_type_says()
    {
        var p = Start().NewPerson();

        Assert.Equal(HttpStatusCode.BadRequest, (await Upload(p, Encoding.UTF8.GetBytes("<html><script>alert(1)</script></html>"), "avatar.png", "image/png")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Upload(p, Encoding.UTF8.GetBytes("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"), "a.svg", "image/svg+xml")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Upload(p, Encoding.ASCII.GetBytes("GIF89a......"), "a.gif", "image/gif")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Upload(p, [], "empty.png", "image/png")).StatusCode);
        Assert.True((await Upload(p, Png, "harmless.exe", "application/octet-stream")).IsSuccessStatusCode);     // real PNG: name and type are irrelevant
    }

    [Fact]
    public async Task Stored_avatars_get_server_generated_names_and_a_type_derived_from_the_content()
    {
        var p = Start().NewPerson();
        var res = await Upload(p, Png, "../../../evil.html", "text/html");

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var url = (await res.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("avatarUrl").GetString()!;
        Assert.Matches(@"^/avatars/[A-Za-z0-9\-]{16,}\.png$", url);
        Assert.DoesNotContain("evil", url);

        var env = factory.Services.GetRequiredService<IWebHostEnvironment>();
        _createdFiles.Add(Path.Combine(env.WebRootPath, "avatars", Path.GetFileName(url)));
        var served = await p.Http.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal("image/png", served.Content.Headers.ContentType?.MediaType);
        Assert.Equal("nosniff", Header(served, "X-Content-Type-Options"));
    }

    [Fact]
    public async Task Oversized_uploads_are_refused()
    {
        var p = Start().NewPerson();
        var big = Png.Concat(new byte[3 * 1024 * 1024]).ToArray();
        var status = (await Upload(p, big, "big.png", "image/png")).StatusCode;
        Assert.True(status is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge, $"got {(int)status}");
    }

    // ================= outbound URLs (SSRF) =================

    sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (Requests) Requests.Add(request.RequestUri!);
            return Task.FromResult(respond(request));
        }
    }

    static HttpResponseMessage Html(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/html") };

    (Harness, RecordingHandler) StartWithOutbound(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var handler = new RecordingHandler(respond);
        var h = Start(s => s.AddHttpClient("outbound").ConfigurePrimaryHttpMessageHandler(() => handler));
        return (h, handler);
    }

    [Theory]
    [InlineData("http://example.com/")]                                   // not https
    [InlineData("https://localhost/admin")]
    [InlineData("https://127.0.0.1/")]
    [InlineData("https://169.254.169.254/latest/meta-data/")]             // cloud metadata service
    [InlineData("https://[::1]/")]
    [InlineData("https://10.0.0.5/")]
    [InlineData("https://example.com@evil.example/")]                     // userinfo trick: the host is evil.example
    [InlineData("https://example.com.evil.example/")]                     // suffix trick
    [InlineData("https://evil.example/?u=https://example.com/")]
    [InlineData("https://example.com:8443/")]                             // unexpected port
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://example.com/")]
    [InlineData("not a url")]
    [InlineData("")]
    public async Task Link_previews_refuse_everything_that_is_not_an_allow_listed_https_host_and_never_make_the_request(string url)
    {
        var (h, handler) = StartWithOutbound(_ => Html("<title>secret</title>"));
        var p = h.NewPerson();

        var res = await p.Http.PostAsJsonAsync("/api/tools/link-preview", new { url });

        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task An_allow_listed_url_is_fetched_once_and_its_title_returned()
    {
        var (h, handler) = StartWithOutbound(_ => Html("<html><head><title>Hello  world</title></head><body>x</body></html>"));
        var p = h.NewPerson();

        var res = await p.Http.PostAsJsonAsync("/api/tools/link-preview", new { url = "https://EXAMPLE.com/some/page?x=1" });

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("Hello world", (await res.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("title").GetString());
        Assert.Single(handler.Requests);
        Assert.Equal("example.com", handler.Requests[0].Host);
    }

    [Fact]
    public async Task Redirects_are_not_followed_because_the_target_was_never_checked()
    {
        var (h, handler) = StartWithOutbound(_ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.Found);
            r.Headers.Location = new Uri("https://169.254.169.254/latest/meta-data/");
            return r;
        });
        var p = h.NewPerson();

        var res = await p.Http.PostAsJsonAsync("/api/tools/link-preview", new { url = "https://example.com/redirect" });

        Assert.False(res.IsSuccessStatusCode);
        Assert.Single(handler.Requests);
        Assert.DoesNotContain(handler.Requests, u => u.Host.StartsWith("169."));
    }

    [Fact]
    public async Task Huge_responses_are_cut_off_and_link_previews_need_a_signed_in_user()
    {
        var (h, _) = StartWithOutbound(_ => Html("<title>x</title>" + new string('a', 3 * 1024 * 1024)));
        var p = h.NewPerson();
        Assert.False((await p.Http.PostAsJsonAsync("/api/tools/link-preview", new { url = "https://example.com/big" })).IsSuccessStatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await h.Anonymous().PostAsJsonAsync("/api/tools/link-preview", new { url = "https://example.com/" })).StatusCode);
    }
}
