using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecLab.Api.Data;
using Xunit;

namespace SecLab.Api.Tests;

// Step 03 – OAuth2 / OpenID Connect: the API becomes a resource server that validates JWT access tokens.
// Requires the SQL Server container. Does NOT need Keycloak: TestIdp mints tokens itself.
[Trait("Step", "03")]
public class Step03OAuthTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly TestIdp _idp = new();
    public void Dispose() => _idp.Dispose();

    static HttpRequestMessage Get(string url, string? bearer = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (bearer is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return req;
    }

    HttpClient Client() => _idp.CreateClient(factory);

    [Fact]
    public async Task Requests_without_a_token_are_rejected_on_every_api_route()
    {
        foreach (var url in new[] { "/api/blogs", "/api/users/1", "/api/users/1/friends", "/api/timeline", "/api/me" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await Client().SendAsync(Get(url))).StatusCode);
    }

    [Fact]
    public async Task The_old_X_User_Id_header_no_longer_authenticates_anyone()
    {
        var req = Get("/api/timeline");
        req.Headers.Add("X-User-Id", "1");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task A_valid_token_gets_through_and_me_returns_the_matching_local_user_without_secrets()
    {
        var res = await Client().SendAsync(Get("/api/me", _idp.Token("alice")));

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadAsStringAsync();
        Assert.Equal("alice", JsonDocument.Parse(body).RootElement.GetProperty("username").GetString());
        Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Identity_comes_from_the_token_not_from_a_client_supplied_header()
    {
        // bob's token + a header claiming to be user 1 (alice): the timeline must still be bob's.
        var req = Get("/api/timeline", _idp.Token("bob"));
        req.Headers.Add("X-User-Id", "1");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var items = await res.Content.ReadFromJsonAsync<List<JsonElement>>() ?? [];
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var bob = db.Users.Single(u => u.Username == "bob").Id;
        var bobsFriends = db.Friendships.Where(f => f.UserId == bob).Select(f => f.FriendId).ToHashSet();

        Assert.NotEmpty(items);
        Assert.All(items, i => Assert.Contains(i.GetProperty("authorId").GetInt32(), bobsFriends));
    }

    [Fact]
    public async Task Expired_tokens_are_rejected()
    {
        var res = await Client().SendAsync(Get("/api/me", _idp.Token(expiresIn: TimeSpan.FromHours(-1))));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Tokens_that_expired_two_minutes_ago_are_rejected_so_clock_skew_must_be_small()
    {
        var res = await Client().SendAsync(Get("/api/me", _idp.Token(expiresIn: TimeSpan.FromMinutes(-2))));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Tokens_for_another_audience_are_rejected()
    {
        var res = await Client().SendAsync(Get("/api/me", _idp.Token(audience: "some-other-api")));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Tokens_from_another_issuer_are_rejected()
    {
        var res = await Client().SendAsync(Get("/api/me", _idp.Token(issuer: "https://evil.example/realms/seclab")));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Tokens_signed_with_someone_elses_key_are_rejected()
    {
        var res = await Client().SendAsync(Get("/api/me", _idp.Token(signWith: TestIdp.AttackerKey())));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Unsigned_alg_none_tokens_are_rejected()
    {
        var res = await Client().SendAsync(Get("/api/me", TestIdp.UnsignedToken()));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }
}
