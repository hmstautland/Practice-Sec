using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecLab.Api.Tests;

// Step 07 – Rate limiting. Contract: docs/07-rate-limiting.md. Limits are read from configuration keys
// RateLimiting:WindowSeconds, :Anonymous, :User, :Login, :ApiKeyRead, :ApiKeyWrite, :ApiKeyAdmin (requests per window),
// which these tests set through environment variables (RateLimiting__Anonymous=5 ...).
[Trait("Step", "07")]
public class Step07RateLimitTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly List<IDisposable> _disposables = [];
    public void Dispose() { foreach (var d in _disposables) d.Dispose(); }

    Harness Start(params (string, string)[] settings)
    {
        _disposables.Add(new EnvScope(settings));       // before the host is built
        var h = new Harness(factory);
        _disposables.Add(h);
        return h;
    }

    static (string, string) Setting(string name, int value) => ($"RateLimiting__{name}", value.ToString());

    static async Task<HttpStatusCode> Get(HttpClient c, string url, Action<HttpRequestMessage>? tweak = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        tweak?.Invoke(req);
        return (await c.SendAsync(req)).StatusCode;
    }

    [Fact]
    public async Task Anonymous_callers_are_limited_and_the_rejection_says_when_to_come_back()
    {
        var h = Start(Setting("WindowSeconds", 600), Setting("Anonymous", 5), Setting("User", 100), Setting("Login", 100));
        var anon = h.Anonymous();

        for (var i = 0; i < 5; i++) Assert.NotEqual(HttpStatusCode.TooManyRequests, await Get(anon, "/api/blogs"));
        var res = await anon.GetAsync("/api/blogs");

        Assert.Equal(HttpStatusCode.TooManyRequests, res.StatusCode);
        Assert.True(res.Headers.TryGetValues("Retry-After", out var values), "429 needs a Retry-After header");
        var seconds = int.Parse(values!.Single());
        Assert.InRange(seconds, 1, 600);
        var body = JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(429, body.GetProperty("status").GetInt32());
        Assert.Contains("json", res.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Spoofed_forwarding_headers_do_not_buy_a_fresh_allowance()
    {
        var h = Start(Setting("WindowSeconds", 600), Setting("Anonymous", 3), Setting("User", 100), Setting("Login", 100));
        var anon = h.Anonymous();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 6; i++)
            statuses.Add(await Get(anon, "/api/blogs", r => { r.Headers.Add("X-Forwarded-For", $"10.9.8.{i + 1}"); r.Headers.Add("X-Real-IP", $"10.9.7.{i + 1}"); }));

        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
    }

    [Fact]
    public async Task Login_and_registration_have_a_much_stricter_limit_whatever_username_is_tried()
    {
        var h = Start(Setting("WindowSeconds", 600), Setting("Anonymous", 100), Setting("User", 100), Setting("Login", 3));
        var anon = h.Anonymous();

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/api/auth/login", new { username = "user" + i, password = "wrong-password" })).StatusCode);

        var res = await anon.PostAsJsonAsync("/api/auth/login", new { username = "yet-another", password = "wrong-password" });
        Assert.Equal(HttpStatusCode.TooManyRequests, res.StatusCode);
        Assert.True(res.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task Signed_in_users_get_their_own_allowance_independent_of_each_other_and_of_anonymous_traffic()
    {
        var h = Start(Setting("WindowSeconds", 600), Setting("Anonymous", 2), Setting("User", 5), Setting("Login", 100));
        var busy = h.NewPerson(); var calm = h.NewPerson();

        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.OK, await Get(busy.Http, "/api/me"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Get(busy.Http, "/api/me"));

        Assert.Equal(HttpStatusCode.OK, await Get(calm.Http, "/api/me"));      // a different user, same server, same "IP"
    }

    [Fact]
    public async Task Api_keys_are_limited_per_key_and_the_allowance_grows_with_the_level()
    {
        var h = Start(Setting("WindowSeconds", 600), Setting("Anonymous", 100), Setting("User", 100), Setting("Login", 100),
                      Setting("ApiKeyRead", 2), Setting("ApiKeyWrite", 4), Setting("ApiKeyAdmin", 8));
        var owner = h.NewPerson();
        async Task<string> Key(string level)
        {
            var res = await owner.Http.PostAsJsonAsync("/api/keys", new { name = level, level });
            return (await res.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("apiKey").GetString()!;
        }
        var readA = await Key("read"); var readB = await Key("read"); var write = await Key("write");
        var anon = h.Anonymous();
        Task<HttpStatusCode> Use(string key) => Get(anon, "/api/partner/blogs", r => r.Headers.Add("X-Api-Key", key));

        Assert.Equal(HttpStatusCode.OK, await Use(readA)); Assert.Equal(HttpStatusCode.OK, await Use(readA));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Use(readA));
        Assert.Equal(HttpStatusCode.OK, await Use(readB));                                  // another key of the same level is unaffected

        for (var i = 0; i < 4; i++) Assert.Equal(HttpStatusCode.OK, await Use(write));      // write > read
        Assert.Equal(HttpStatusCode.TooManyRequests, await Use(write));
    }

    [Fact]
    public async Task The_allowance_returns_when_the_window_is_over()
    {
        var h = Start(Setting("WindowSeconds", 2), Setting("Anonymous", 2), Setting("User", 100), Setting("Login", 100));
        var anon = h.Anonymous();
        await Get(anon, "/api/blogs"); await Get(anon, "/api/blogs");
        Assert.Equal(HttpStatusCode.TooManyRequests, await Get(anon, "/api/blogs"));

        await Task.Delay(TimeSpan.FromSeconds(2.5));

        Assert.NotEqual(HttpStatusCode.TooManyRequests, await Get(anon, "/api/blogs"));
    }
}
