using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecLab.Api.Tests;

// Step 06 – Leveled API keys. Contract: docs/06-api-keys.md.
[Trait("Step", "06")]
public class Step06ApiKeyTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly Harness _h = new(factory);
    public void Dispose() => _h.Dispose();

    static async Task<JsonElement> Json(HttpResponseMessage res)
    {
        var text = await res.Content.ReadAsStringAsync();
        return string.IsNullOrWhiteSpace(text) ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    /// <summary>Creates a key through the user-facing API and returns (id, key).</summary>
    async Task<(int Id, string Key)> CreateKey(Harness.Person owner, string level, int? expiresInSeconds = null)
    {
        var res = await owner.Http.PostAsJsonAsync("/api/keys", new { name = "test", level, expiresInSeconds });
        Assert.True(res.IsSuccessStatusCode, $"creating a {level} key returned {(int)res.StatusCode}");
        var body = await Json(res);
        return (body.GetProperty("id").GetInt32(), body.GetProperty("apiKey").GetString()!);
    }

    HttpRequestMessage Partner(HttpMethod method, string url, string? key, object? body = null)
    {
        var req = new HttpRequestMessage(method, url);
        if (key is not null) req.Headers.Add("X-Api-Key", key);
        if (body is not null) req.Content = JsonContent.Create(body);
        return req;
    }

    Task<HttpResponseMessage> Send(HttpRequestMessage req) => _h.Anonymous().SendAsync(req);

    // ---- key lifecycle ----

    [Fact]
    public async Task Creating_a_key_needs_a_signed_in_user_and_shows_the_secret_exactly_once()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _h.Anonymous().PostAsJsonAsync("/api/keys", new { name = "x", level = "read" })).StatusCode);

        var owner = _h.NewPerson();
        var (id, key) = await CreateKey(owner, "read");

        var parts = key.Split('_');
        Assert.Equal(3, parts.Length);
        Assert.Matches("^[A-Za-z0-9]{8}$", parts[1]);        // public prefix, used for lookup
        Assert.Matches("^[A-Za-z0-9]{32,}$", parts[2]);      // secret: >= 32 alphanumerics from a CSPRNG

        var list = await owner.Http.GetAsync("/api/keys");
        var text = await list.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        Assert.DoesNotContain(parts[2], text);
        Assert.Contains(id.ToString(), text);
    }

    [Fact]
    public async Task The_secret_is_never_stored_in_the_database_in_readable_form()
    {
        var (_, key) = await CreateKey(_h.NewPerson(), "write");
        var secret = key.Split('_')[2];

        Assert.False(_h.DatabaseContains(secret), "the raw secret must not appear in any column");
        Assert.False(_h.DatabaseContains(key), "neither may the full key");
    }

    [Fact]
    public async Task Users_only_list_and_revoke_their_own_keys_admins_can_revoke_any()
    {
        var alice = _h.NewPerson(); var mallory = _h.NewPerson(); var admin = _h.NewPerson("Admin");
        var (id, key) = await CreateKey(alice, "read");

        Assert.DoesNotContain(id.ToString(), await (await mallory.Http.GetAsync("/api/keys")).Content.ReadAsStringAsync());
        Assert.True((await mallory.Http.DeleteAsync($"/api/keys/{id}")).StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound);
        Assert.Equal(HttpStatusCode.OK, (await Send(Partner(HttpMethod.Get, "/api/partner/blogs", key))).StatusCode);   // still valid

        Assert.Equal(HttpStatusCode.NoContent, (await admin.Http.DeleteAsync($"/api/keys/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Partner(HttpMethod.Get, "/api/partner/blogs", key))).StatusCode);
    }

    [Fact]
    public async Task Ordinary_users_cannot_mint_admin_keys_and_unknown_levels_are_rejected()
    {
        var user = _h.NewPerson(); var admin = _h.NewPerson("Admin");

        Assert.Equal(HttpStatusCode.Forbidden, (await user.Http.PostAsJsonAsync("/api/keys", new { name = "x", level = "admin" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await user.Http.PostAsJsonAsync("/api/keys", new { name = "x", level = "root" })).StatusCode);
        Assert.True((await admin.Http.PostAsJsonAsync("/api/keys", new { name = "x", level = "admin" })).IsSuccessStatusCode);
    }

    [Fact]
    public async Task Keys_can_expire()
    {
        var (_, key) = await CreateKey(_h.NewPerson(), "read", expiresInSeconds: 1);
        Assert.Equal(HttpStatusCode.OK, (await Send(Partner(HttpMethod.Get, "/api/partner/blogs", key))).StatusCode);

        await Task.Delay(2500);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Partner(HttpMethod.Get, "/api/partner/blogs", key))).StatusCode);
    }

    [Fact]
    public async Task Use_of_a_key_is_recorded()
    {
        var owner = _h.NewPerson();
        var (id, key) = await CreateKey(owner, "read");
        await Send(Partner(HttpMethod.Get, "/api/partner/blogs", key));

        var list = await Json(await owner.Http.GetAsync("/api/keys"));
        var mine = list.EnumerateArray().Single(k => k.GetProperty("id").GetInt32() == id);
        Assert.NotEqual(JsonValueKind.Null, mine.GetProperty("lastUsedAt").ValueKind);
    }

    // ---- levels ----

    [Fact]
    public async Task Levels_are_ordered_read_below_write_below_admin()
    {
        var owner = _h.NewPerson("Admin");
        var (_, read) = await CreateKey(owner, "read");
        var (_, write) = await CreateKey(owner, "write");
        var (_, admin) = await CreateKey(owner, "admin");
        var post = new { title = "from a partner", body = "<p>hi</p>" };

        // read
        Assert.Equal(HttpStatusCode.OK, (await Send(Partner(HttpMethod.Get, "/api/partner/blogs", read))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(Partner(HttpMethod.Post, "/api/partner/blogs", read, post))).StatusCode);

        // write includes read
        Assert.Equal(HttpStatusCode.OK, (await Send(Partner(HttpMethod.Get, "/api/partner/blogs", write))).StatusCode);
        var created = await Send(Partner(HttpMethod.Post, "/api/partner/blogs", write, post));
        Assert.True(created.IsSuccessStatusCode);
        var blogId = (await Json(created)).GetProperty("id").GetInt32();
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(Partner(HttpMethod.Delete, $"/api/partner/blogs/{blogId}", write))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(Partner(HttpMethod.Delete, $"/api/partner/blogs/{blogId}", read))).StatusCode);

        // admin includes write
        Assert.Equal(HttpStatusCode.NoContent, (await Send(Partner(HttpMethod.Delete, $"/api/partner/blogs/{blogId}", admin))).StatusCode);
    }

    [Fact]
    public async Task Posts_made_with_a_key_belong_to_the_keys_owner()
    {
        var owner = _h.NewPerson(); var someoneElse = _h.NewPerson();
        var (_, key) = await CreateKey(owner, "write");

        var res = await Send(Partner(HttpMethod.Post, "/api/partner/blogs", key, new { title = "t", body = "b", authorId = someoneElse.Id }));

        var id = (await Json(res)).GetProperty("id").GetInt32();
        Assert.Equal(owner.Id, _h.InDb(db => db.Blogs.Single(b => b.Id == id).AuthorId));
    }

    // ---- authentication of the key itself ----

    [Fact]
    public async Task Missing_malformed_unknown_and_wrong_secret_keys_all_look_the_same()
    {
        var (_, key) = await CreateKey(_h.NewPerson(), "read");
        var parts = key.Split('_');
        var wrongSecret = $"{parts[0]}_{parts[1]}_{new string('a', parts[2].Length)}";
        var unknownPrefix = $"{parts[0]}_ZZZZZZZZ_{parts[2]}";

        var attempts = new string?[] { null, "", "garbage", "sl_short", wrongSecret, unknownPrefix };
        var results = new List<(HttpStatusCode, string)>();
        foreach (var attempt in attempts)
        {
            var res = await Send(Partner(HttpMethod.Get, "/api/partner/blogs", attempt));
            results.Add((res.StatusCode, await res.Content.ReadAsStringAsync()));
        }

        Assert.All(results, r => Assert.Equal(HttpStatusCode.Unauthorized, r.Item1));
        Assert.Single(results.Select(r => System.Text.RegularExpressions.Regex.Replace(r.Item2, "\"traceId\":\"[^\"]*\"", "")).Distinct());     // same body: no oracle for "prefix exists"
    }

    [Fact]
    public async Task Keys_are_accepted_in_the_header_only_never_in_the_url()
    {
        var (_, key) = await CreateKey(_h.NewPerson(), "read");
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Partner(HttpMethod.Get, $"/api/partner/blogs?api_key={key}", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Partner(HttpMethod.Get, $"/api/partner/blogs?apikey={key}", null))).StatusCode);
    }

    // ---- keeping credential types apart ----

    [Fact]
    public async Task User_tokens_do_not_work_on_partner_routes_and_keys_do_not_work_on_user_routes()
    {
        var owner = _h.NewPerson();
        var (_, key) = await CreateKey(owner, "write");

        Assert.Equal(HttpStatusCode.Unauthorized, (await owner.Http.GetAsync("/api/partner/blogs")).StatusCode);   // bearer on a key-only route

        foreach (var url in new[] { "/api/me", "/api/timeline", "/api/keys", $"/api/users/{owner.Id}" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Partner(HttpMethod.Get, url, key))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Partner(HttpMethod.Post, "/api/keys", key, new { name = "x", level = "read" }))).StatusCode);   // keys cannot mint keys
    }
}
