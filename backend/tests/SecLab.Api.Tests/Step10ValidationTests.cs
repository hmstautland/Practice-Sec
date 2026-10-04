using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecLab.Api.Tests;

// Step 10 – Input validation & output sanitising. Contract: docs/10-input-validation.md.
[Trait("Step", "10")]
public class Step10ValidationTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly Harness _h = new(factory);
    public void Dispose() => _h.Dispose();

    static async Task<JsonElement> Json(HttpResponseMessage res)
    {
        var text = await res.Content.ReadAsStringAsync();
        return string.IsNullOrWhiteSpace(text) ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    static string Str(int n) => new('a', n);

    /// <summary>A validation failure is a 400 problem+json that names the offending field and never echoes the raw input.</summary>
    static async Task AssertRejected(HttpResponseMessage res, string field, string? mustNotEcho = null)
    {
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        var text = await res.Content.ReadAsStringAsync();
        var body = JsonDocument.Parse(text).RootElement;
        Assert.Equal(400, body.GetProperty("status").GetInt32());
        var names = body.GetProperty("errors").EnumerateObject().Select(p => p.Name.ToLowerInvariant()).ToList();
        Assert.Contains(names, n => n.Contains(field.ToLowerInvariant()));
        if (mustNotEcho is not null) Assert.DoesNotContain(mustNotEcho, text);
    }

    // ---------- registration ----------

    [Theory]
    [InlineData("username", "ab", "long-enough-password")]                                  // too short
    [InlineData("username", "has space", "long-enough-password")]
    [InlineData("username", "<script>alert(1)</script>", "long-enough-password")]
    [InlineData("username", "аlice", "long-enough-password")]                                // Cyrillic 'а' - a homoglyph of "alice"
    [InlineData("username", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "long-enough-password")]   // > 32
    [InlineData("password", "validname", "short")]
    [InlineData("password", "validname", "way-too-long-way-too-long-way-too-long-way-too-long-way-too-long-way-too-long-way-too-long-way-too-long-way-too-long-way-too-long")]
    public async Task Registration_rejects_bad_usernames_and_passwords(string field, string username, string password)
    {
        var res = await _h.Anonymous().PostAsJsonAsync("/api/auth/register", new { username, password, displayName = "Name", email = "ok@example.com" });
        await AssertRejected(res, field, mustNotEcho: "<script>");
    }

    [Theory]
    [InlineData("email", "not-an-email")]
    [InlineData("email", "a@b@c.com")]
    [InlineData("email", "with space@example.com")]
    [InlineData("displayname", "")]
    [InlineData("displayname", "<img src=x onerror=alert(1)>")]
    public async Task Registration_rejects_bad_email_and_display_names(string field, string value)
    {
        var body = new Dictionary<string, string> { ["username"] = "valid_" + Guid.NewGuid().ToString("N")[..8], ["password"] = "long-enough-password", ["displayName"] = "Name", ["email"] = "ok@example.com" };
        body[field == "displayname" ? "displayName" : field] = value;
        await AssertRejected(await _h.Anonymous().PostAsJsonAsync("/api/auth/register", body), field, mustNotEcho: "onerror");
    }

    [Fact]
    public async Task Registration_rejects_absurdly_long_email()
    {
        var res = await _h.Anonymous().PostAsJsonAsync("/api/auth/register", new { username = "valid_" + Guid.NewGuid().ToString("N")[..8], password = "long-enough-password", displayName = "N", email = Str(250) + "@example.com" });
        await AssertRejected(res, "email");
    }

    // ---------- profile ----------

    [Theory]
    [InlineData("phone", "call me maybe")]
    [InlineData("phone", "+47 123 <b>")]
    [InlineData("email", "nope")]
    [InlineData("displayName", "")]
    [InlineData("displayName", "<script>x</script>")]
    public async Task Profile_updates_reject_bad_values_and_change_nothing(string field, string value)
    {
        var me = _h.NewPerson();
        var before = _h.InDb(db => db.Users.Single(u => u.Id == me.Id).DisplayName);
        var body = new Dictionary<string, string?> { [field] = value };

        await AssertRejected(await me.Http.PutAsJsonAsync($"/api/users/{me.Id}", body), field);

        Assert.Equal(before, _h.InDb(db => db.Users.Single(u => u.Id == me.Id).DisplayName));
    }

    [Fact]
    public async Task Profile_text_fields_have_length_limits()
    {
        var me = _h.NewPerson();
        await AssertRejected(await me.Http.PutAsJsonAsync($"/api/users/{me.Id}", new { bio = Str(501) }), "bio");
        await AssertRejected(await me.Http.PutAsJsonAsync($"/api/users/{me.Id}", new { address = Str(201) }), "address");
        Assert.Equal(HttpStatusCode.OK, (await me.Http.PutAsJsonAsync($"/api/users/{me.Id}", new { bio = Str(500), phone = "+47 (900) 12-345" })).StatusCode);
    }

    // ---------- blogs ----------

    [Theory]
    [InlineData("title", "")]
    [InlineData("title", "   ")]
    [InlineData("title", "<b>bold</b>")]
    public async Task Blog_titles_are_short_plain_text(string field, string title)
    {
        var res = await _h.NewPerson().Http.PostAsJsonAsync("/api/blogs", new { title, body = "<p>ok</p>" });
        await AssertRejected(res, field);
    }

    [Fact]
    public async Task Blog_titles_and_bodies_have_length_limits_and_may_not_be_empty()
    {
        var p = _h.NewPerson();
        await AssertRejected(await p.Http.PostAsJsonAsync("/api/blogs", new { title = Str(121), body = "x" }), "title");
        await AssertRejected(await p.Http.PostAsJsonAsync("/api/blogs", new { title = "ok", body = "" }), "body");
        await AssertRejected(await p.Http.PostAsJsonAsync("/api/blogs", new { title = "ok", body = Str(10_001) }), "body");
        Assert.True((await p.Http.PostAsJsonAsync("/api/blogs", new { title = Str(120), body = Str(10_000) })).IsSuccessStatusCode);
    }

    public static IEnumerable<object[]> XssPayloads() =>
    [
        ["<script>alert(1)</script><p>keep</p>"],
        ["<p>keep</p><img src=x onerror=alert(1)>"],
        ["<p onclick=\"alert(1)\">keep</p>"],
        ["<a href=\"javascript:alert(1)\">keep</a>"],
        ["<a href=\"JaVaScRiPt:alert(1)\">keep</a>"],
        ["<a href=\"&#106;avascript:alert(1)\">keep</a>"],
        ["<svg><script>alert(1)</script></svg><p>keep</p>"],
        ["<iframe src=\"https://evil.example\"></iframe><p>keep</p>"],
        ["<p style=\"background:url(javascript:alert(1))\">keep</p>"],
        ["<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=1 onerror=alert(1)&gt;\">"],
        ["<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object><p>keep</p>"],
        ["<form action=\"https://evil.example\"><input name=x></form><p>keep</p>"],
    ];

    static readonly string[] Forbidden = ["<script", "onerror", "onclick", "javascript:", "<iframe", "<object", "<svg", "<form", "<style", "style=", "<img", "<math"];

    static void AssertClean(string html)
    {
        foreach (var bad in Forbidden) Assert.DoesNotContain(bad, html, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [MemberData(nameof(XssPayloads))]
    public async Task Blog_bodies_are_sanitised_on_every_write_path(string payload)
    {
        var p = _h.NewPerson();

        // create
        var created = await p.Http.PostAsJsonAsync("/api/blogs", new { title = "t", body = payload });
        Assert.True(created.IsSuccessStatusCode, $"create returned {(int)created.StatusCode}");
        var id = (await Json(created)).GetProperty("id").GetInt32();
        var stored = _h.InDb(db => db.Blogs.Single(b => b.Id == id).Body);
        AssertClean(stored);
        if (payload.Contains("<p")) Assert.Contains("keep", stored);

        // edit
        Assert.True((await p.Http.PutAsJsonAsync($"/api/blogs/{id}", new { title = "t2", body = payload })).IsSuccessStatusCode);
        AssertClean(_h.InDb(db => db.Blogs.Single(b => b.Id == id).Body));

        // the API-key route writes blogs too
        var keyRes = await p.Http.PostAsJsonAsync("/api/keys", new { name = "k", level = "write" });
        var key = (await Json(keyRes)).GetProperty("apiKey").GetString()!;
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/partner/blogs") { Content = JsonContent.Create(new { title = "t", body = payload }) };
        req.Headers.Add("X-Api-Key", key);
        var viaKey = await _h.Anonymous().SendAsync(req);
        Assert.True(viaKey.IsSuccessStatusCode, $"partner create returned {(int)viaKey.StatusCode}");
        var partnerId = (await Json(viaKey)).GetProperty("id").GetInt32();
        AssertClean(_h.InDb(db => db.Blogs.Single(b => b.Id == partnerId).Body));
    }

    [Fact]
    public async Task Safe_formatting_and_https_links_survive_sanitising()
    {
        var p = _h.NewPerson();
        var res = await p.Http.PostAsJsonAsync("/api/blogs", new { title = "t", body = "<h2>Head</h2><p>Some <strong>bold</strong>, <em>em</em> and <a href=\"https://example.com/x?y=1\">a link</a>.</p><ul><li>one</li></ul><pre><code>x &lt; y</code></pre>" });
        var id = (await Json(res)).GetProperty("id").GetInt32();
        var stored = _h.InDb(db => db.Blogs.Single(b => b.Id == id).Body);

        foreach (var keep in new[] { "<h2>", "<strong>bold</strong>", "<em>em</em>", "href=\"https://example.com/x?y=1\"", "<li>one</li>", "<code>" })
            Assert.Contains(keep, stored);
    }

    // ---------- transport-level input ----------

    [Fact]
    public async Task Malformed_json_wrong_types_and_wrong_content_types_are_client_errors_not_server_errors()
    {
        var p = _h.NewPerson();

        var broken = await p.Http.PostAsync("/api/blogs", new StringContent("{ \"title\": ", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, broken.StatusCode);

        var wrongType = await p.Http.PostAsync("/api/blogs", new StringContent("{\"title\": 5, \"body\": [1]}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, wrongType.StatusCode);

        var wrongContentType = await p.Http.PostAsync("/api/blogs", new StringContent("title=x&body=y", Encoding.UTF8, "text/plain"));
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongContentType.StatusCode);

        var empty = await p.Http.PostAsync("/api/blogs", new StringContent("", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);
    }

    [Fact]
    public async Task Search_terms_are_bounded()
    {
        var p = _h.NewPerson();
        await AssertRejected(await p.Http.GetAsync("/api/blogs/search?q=" + Str(101)), "q");
        await AssertRejected(await p.Http.GetAsync("/api/blogs/search?q="), "q");
        Assert.Equal(HttpStatusCode.OK, (await p.Http.GetAsync("/api/blogs/search?q=hello")).StatusCode);
    }

    [Fact]
    public async Task References_must_exist_you_cannot_like_a_blog_that_is_not_there()
    {
        var p = _h.NewPerson();
        Assert.Equal(HttpStatusCode.NotFound, (await p.Http.PostAsync("/api/blogs/2000000000/like", null)).StatusCode);
        Assert.Equal(0, _h.InDb(db => db.BlogLikes.Count(l => l.UserId == p.Id)));
    }
}
