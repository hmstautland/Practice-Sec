using System.Net;
using System.Text.Json;
using Xunit;

namespace SecLab.Gateway.Tests;

// Step 17 – a backend-for-frontend (BFF) in the gateway. Contract: docs/17-extras.md.
//
// Configuration keys (the tests set them as environment variables):
//   Bff:Authority  Bff:ClientId  Bff:ClientSecret  Bff:PublicOrigin  Bff:IdleTimeout  Bff:SessionLifetime  Bff:RefreshSkew
// HTTP surface:  GET /bff/login?returnUrl=…   GET /bff/user   POST /bff/logout   and the existing /api/** route.
// The browser only ever holds one opaque, HttpOnly cookie. The CSRF header is "X-CSRF: 1". Time comes from the registered TimeProvider.
[Trait("Step", "17")]
public class Step17BffTests
{
    static readonly (string, string) Csrf = Browser.Csrf;
    static JsonElement Json(string s) => JsonDocument.Parse(s).RootElement;

    static async Task<string> Authorization(BffRig rig, string path = "/api/me")
    {
        var before = rig.Api.Requests.Count;
        var res = await rig.Browser.Get(path);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal(before + 1, rig.Api.Requests.Count);
        return rig.Api.Requests[^1].Headers.Authorization?.ToString() ?? "";
    }

    static async Task<BffRig> SignedIn(params (string, string)[] overrides)
    {
        var rig = await BffRig.Start(overrides: overrides);
        var cb = await rig.Browser.SignIn(rig.Idp);
        Assert.True(cb.StatusCode is HttpStatusCode.Found or HttpStatusCode.Redirect, $"the callback should end in a redirect, was {(int)cb.StatusCode}");
        return rig;
    }

    // ---------------- login: Authorization Code + PKCE, confidential client ----------------

    [Fact]
    public async Task Login_redirects_to_the_idp_with_code_flow_pkce_state_and_nonce_and_no_secret_in_the_url()
    {
        await using var rig = await BffRig.Start();
        var res = await rig.Browser.StartLogin();

        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        var location = res.Headers.Location!;
        Assert.StartsWith(rig.Idp.Authority + "/protocol/openid-connect/auth", location.ToString());
        var q = System.Web.HttpUtility.ParseQueryString(location.Query);
        Assert.Equal("code", q["response_type"]);
        Assert.Equal(FakeIdp.ClientId, q["client_id"]);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.True(q["code_challenge"]!.Length >= 43);
        Assert.True(q["state"]!.Length >= 8);
        Assert.True(q["nonce"]!.Length >= 8);
        Assert.Contains("openid", q["scope"]!.Split(' '));
        Assert.StartsWith("https://localhost/", q["redirect_uri"]);              // Bff:PublicOrigin, not whatever Host header arrived
        Assert.DoesNotContain(FakeIdp.ClientSecret, location.ToString());
        Assert.Null(q["client_secret"]);
    }

    [Fact]
    public async Task The_redirect_uri_comes_from_configuration_not_from_the_host_header()
    {
        await using var rig = await BffRig.Start();
        var res = await rig.Browser.Get("/bff/login", ("Host", "seclab.example"));                  // an allowed host name, but not the public origin
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        var redirectUri = System.Web.HttpUtility.ParseQueryString(res.Headers.Location!.Query)["redirect_uri"];
        Assert.StartsWith("https://localhost/", redirectUri);
    }

    [Fact]
    public async Task Complete_login_uses_pkce_and_the_client_secret_at_the_token_endpoint_only()
    {
        await using var rig = await SignedIn();
        Assert.Empty(rig.Idp.Problems);            // the IdP records every protocol violation: missing PKCE, wrong secret, wrong redirect_uri ...
        Assert.Single(rig.Idp.IssuedAccessTokens);
        Assert.DoesNotContain(FakeIdp.ClientSecret, rig.Browser.Transcript);
    }

    [Theory]
    [InlineData("https://evil.example/phish")]
    [InlineData("//evil.example/phish")]
    [InlineData("/\\evil.example")]
    [InlineData("javascript:alert(1)")]
    public async Task Login_never_redirects_to_a_foreign_return_url(string returnUrl)
    {
        await using var rig = await BffRig.Start();
        var cb = await rig.Browser.SignIn(rig.Idp, returnUrl);

        Assert.Equal(HttpStatusCode.Found, cb.StatusCode);
        var target = cb.Headers.Location!.OriginalString;
        Assert.StartsWith("/", target);
        Assert.False(target.StartsWith("//") || target.StartsWith("/\\"), "protocol-relative redirect: " + target);
        Assert.DoesNotContain("evil.example", target);
        Assert.DoesNotContain("javascript", target, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_local_return_url_is_kept()
    {
        await using var rig = await BffRig.Start();
        var cb = await rig.Browser.SignIn(rig.Idp, "/timeline");
        Assert.Equal("/timeline", cb.Headers.Location!.OriginalString);
    }

    [Theory]
    [InlineData(IdTokenFault.WrongNonce)]
    [InlineData(IdTokenFault.WrongAudience)]
    [InlineData(IdTokenFault.WrongIssuer)]
    [InlineData(IdTokenFault.BadSignature)]
    public async Task An_id_token_that_does_not_check_out_creates_no_session(IdTokenFault fault)
    {
        await using var rig = await BffRig.Start();
        rig.Idp.Fault = fault;
        await rig.Browser.SignIn(rig.Idp);

        Assert.DoesNotContain(rig.Browser.Cookies.Keys, n => n.StartsWith("__Host-"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/bff/user")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/api/me")).StatusCode);
        Assert.Empty(rig.Api.Requests);
    }

    [Fact]
    public async Task A_callback_with_a_forged_state_or_a_replayed_code_creates_no_session()
    {
        await using var rig = await BffRig.Start();
        await rig.Browser.SignIn(rig.Idp, tamperCallback: c => System.Text.RegularExpressions.Regex.Replace(c, "state=[^&]+", "state=forged"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/bff/user")).StatusCode);

        // a good login, then the very same callback again (a stolen or logged URL): the code is single-use, the correlation cookie is gone
        var fresh = new Browser(rig.RawClient);
        await fresh.SignIn(rig.Idp);
        var callback = fresh.LastCallbackPathAndQuery!;
        var replay = new Browser(rig.RawClient);
        await replay.Get(callback);
        Assert.Equal(HttpStatusCode.Unauthorized, (await replay.Get("/bff/user")).StatusCode);
    }

    [Fact]
    public async Task Login_works_against_nothing_but_https_in_production()
    {
        // the IdP of this test is plain HTTP: outside Development the gateway must refuse to talk to it
        await using var rig = await BffRig.Start(environment: "Production");
        HttpResponseMessage? res = null;
        try { res = await rig.Browser.StartLogin(); } catch (Exception) { /* a host that does not start is also a refusal */ }
        if (res is not null)
        {
            Assert.True((int)res.StatusCode >= 500 || res.StatusCode == HttpStatusCode.Unauthorized, $"expected a refusal, got {(int)res.StatusCode}");
            Assert.Null(res.Headers.Location);
        }
        Assert.Empty(rig.Idp.AuthorizeRequests);
    }

    // ---------------- the cookie ----------------

    [Fact]
    public async Task The_only_cookie_that_survives_the_login_is_one_hardened_session_cookie()
    {
        await using var rig = await SignedIn();

        var cookie = Assert.Single(rig.Browser.Cookies);
        Assert.StartsWith("__Host-", cookie.Key);                              // host-locked: Secure, Path=/, no Domain – enforced by the browser

        foreach (var sc in rig.Browser.SetCookies)                              // every cookie of the flow, including the short-lived OIDC ones
        {
            var lower = sc.ToLowerInvariant();
            Assert.Contains("httponly", lower);
            Assert.Contains("secure", lower);
            Assert.True(lower.Contains("samesite=strict") || lower.Contains("samesite=lax"), "SameSite must be Strict or Lax: " + sc);
            Assert.DoesNotContain("domain=", lower);
        }
        var session = rig.Browser.SetCookies.Single(c => c.StartsWith(cookie.Key + "=", StringComparison.Ordinal)).ToLowerInvariant();
        Assert.Matches(@"(^|; )path=/(;|$)", session);
        Assert.DoesNotContain("expires=", session);                             // a browser-session cookie; the server decides how long the session lives
    }

    [Fact]
    public async Task The_cookie_is_a_reference_to_a_server_side_session_not_a_container_for_tokens()
    {
        await using var rig = await SignedIn();
        var value = rig.Browser.Cookies.Single().Value;

        Assert.True(value.Length < 512, $"the cookie is {value.Length} characters; a token-carrying cookie would be several KB (the test tokens are > 2 KB)");
        Assert.DoesNotContain(rig.Browser.Cookies.Keys, n => n.Contains(".C1") || n.Contains(".C2"));   // no chunked cookies
        foreach (var token in rig.Idp.IssuedAccessTokens.Concat(rig.Idp.IssuedRefreshTokens).Concat(rig.Idp.IssuedIdTokens))
            Assert.DoesNotContain(token[..40], value);
    }

    [Fact]
    public async Task Tokens_never_reach_the_browser_in_any_response_body_header_or_redirect()
    {
        await using var rig = await SignedIn();
        await rig.Browser.Get("/bff/user");
        await rig.Browser.Get("/api/me");
        await rig.Browser.Send(HttpMethod.Post, "/api/blogs/1/like", Csrf);
        await rig.Browser.Get("/api/me", ("Authorization", "Bearer " + new string('a', 40)));   // even a request the gateway rewrites
        await rig.Browser.Get("/api/does-not-exist");

        var seen = rig.Browser.Transcript;
        foreach (var token in rig.Idp.IssuedAccessTokens.Concat(rig.Idp.IssuedRefreshTokens).Concat(rig.Idp.IssuedIdTokens))
            Assert.DoesNotContain(token, seen);
        foreach (var word in new[] { "access_token", "refresh_token", "id_token", "client_secret" })
            Assert.DoesNotContain(word, seen, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Visitors_without_a_session_get_no_cookie_at_all()
    {
        await using var rig = await BffRig.Start();
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/bff/user")).StatusCode);
        await rig.Browser.Get("/api/me");
        await rig.Browser.Get("/avatars/x.png");
        Assert.Empty(rig.Browser.SetCookies);
        Assert.Empty(rig.Browser.Cookies);
    }

    [Fact]
    public async Task A_second_login_gets_a_new_session_identifier()
    {
        await using var rig = await SignedIn();
        var first = rig.Browser.Cookies.Single();
        await rig.Browser.SignIn(rig.Idp);
        var second = rig.Browser.Cookies.Single(c => c.Key == first.Key);
        Assert.NotEqual(first.Value, second.Value);
    }

    // ---------------- /bff/user ----------------

    [Fact]
    public async Task User_endpoint_returns_a_few_claims_for_the_page_and_nothing_cacheable_for_anonymous_callers()
    {
        await using var rig = await BffRig.Start();
        var anonymous = await rig.Browser.Get("/bff/user");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        await rig.Browser.SignIn(rig.Idp);
        var res = await rig.Browser.Get("/bff/user");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Contains("no-store", res.Headers.CacheControl?.ToString());
        var body = Json(await res.Content.ReadAsStringAsync());
        Assert.Equal("carol", body.GetProperty("username").GetString());
        Assert.True(body.EnumerateObject().Count() <= 5, "an allow-list of claims, not a dump of the principal");
    }

    // ---------------- what the API sees ----------------

    [Fact]
    public async Task Api_calls_carry_the_sessions_access_token_and_never_the_cookie_and_cannot_be_given_another_token()
    {
        await using var rig = await SignedIn();
        var token = rig.Idp.LatestAccessToken;

        var res = await rig.Browser.Get("/api/me", ("Authorization", "Bearer attacker-supplied-token"), ("X-Forwarded-For", "10.9.9.9"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var seen = Assert.Single(rig.Api.Requests);
        Assert.Equal("Bearer " + token, seen.Headers.Authorization!.ToString());
        Assert.False(seen.Headers.Contains("Cookie"), "the API must never see the session cookie");
        Assert.False(res.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task The_api_cannot_set_cookies_on_the_applications_origin()
    {
        await using var rig = await BffRig.Start(api: _ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
            r.Headers.TryAddWithoutValidation("Set-Cookie", "evil=1; Path=/");
            return r;
        });
        var scripts = new Browser(rig.RawClient);
        var res = await scripts.Get("/api/me", ("Authorization", "Bearer some.opaque.token"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.False(res.Headers.Contains("Set-Cookie"), "the only cookie on this origin is the session cookie, and only /bff sets it");

        await rig.Browser.SignIn(rig.Idp);
        Assert.False((await rig.Browser.Get("/api/me")).Headers.Contains("Set-Cookie"));
        Assert.DoesNotContain("evil", rig.Browser.Cookies.Keys);
    }

    [Fact]
    public async Task Without_a_cookie_the_edge_behaves_as_in_step_14()
    {
        await using var rig = await SignedIn();
        var scripts = new Browser(rig.RawClient);                               // no cookie
        Assert.Equal(HttpStatusCode.Unauthorized, (await scripts.Get("/api/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await scripts.Get("/api/me", ("Authorization", "Bearer some.opaque.token"))).StatusCode);
        Assert.Equal("Bearer some.opaque.token", rig.Api.Requests[^1].Headers.Authorization!.ToString());   // other clients keep sending their own token
        Assert.Equal(HttpStatusCode.OK, (await scripts.Get("/api/me", ("X-Api-Key", "slk_abc"))).StatusCode);
    }

    [Fact]
    public async Task A_forged_or_foreign_session_cookie_is_treated_as_anonymous()
    {
        await using var rig = await SignedIn();
        var name = rig.Browser.Cookies.Keys.Single();
        var attacker = new Browser(rig.RawClient);
        attacker.SetCookie(name, "CfDJ8-this-is-not-a-cookie-this-gateway-issued");
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.Get("/api/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.Get("/bff/user")).StatusCode);
        Assert.Empty(rig.Api.Requests);
    }

    // ---------------- CSRF ----------------

    [Fact]
    public async Task Requests_that_change_state_need_the_custom_header_when_authenticated_by_cookie()
    {
        await using var rig = await SignedIn();
        foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put, HttpMethod.Delete })
        {
            var res = await rig.Browser.Send(method, "/api/blogs/1");
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
            Assert.Contains("problem+json", res.Content.Headers.ContentType?.MediaType);
            Assert.Equal(HttpStatusCode.Forbidden, (await rig.Browser.Send(method, "/api/blogs/1", ("X-CSRF", "0"))).StatusCode);   // not just "any value"
        }
        Assert.Empty(rig.Api.Requests);                                         // refused before the API spent a cycle

        Assert.Equal(HttpStatusCode.OK, (await rig.Browser.Send(HttpMethod.Post, "/api/blogs/1/like", Csrf)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await rig.Browser.Get("/api/me")).StatusCode);                          // reads do not need it
        Assert.Equal(2, rig.Api.Requests.Count);
    }

    [Theory]
    [InlineData("cross-site", false)]
    [InlineData("same-site", false)]            // another subdomain of the same site is not our SPA
    [InlineData("same-origin", true)]
    [InlineData("none", true)]                  // typed into the address bar / not a browser fetch
    public async Task Fetch_metadata_from_other_sites_is_refused_even_with_the_header(string site, bool allowed)
    {
        await using var rig = await SignedIn();
        var res = await rig.Browser.Send(HttpMethod.Post, "/api/blogs/1/like", Csrf, ("Sec-Fetch-Site", site));
        Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task A_bearer_client_without_cookie_does_not_need_the_csrf_header()
    {
        await using var rig = await BffRig.Start();
        var scripts = new Browser(rig.RawClient);
        Assert.Equal(HttpStatusCode.OK, (await scripts.Send(HttpMethod.Post, "/api/blogs/1/like", ("Authorization", "Bearer some.opaque.token"))).StatusCode);
    }

    // ---------------- logout ----------------

    [Fact]
    public async Task Logout_is_a_post_with_the_csrf_header_and_a_get_does_nothing()
    {
        await using var rig = await SignedIn();
        var get = await rig.Browser.Get("/bff/logout");
        Assert.True(get.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed, $"GET /bff/logout answered {(int)get.StatusCode}");
        Assert.Equal(HttpStatusCode.Forbidden, (await rig.Browser.Send(HttpMethod.Post, "/bff/logout")).StatusCode);
        Assert.Empty(rig.Idp.EndSessionRequests);
        Assert.Equal(HttpStatusCode.OK, (await rig.Browser.Get("/bff/user")).StatusCode);        // the session is untouched: a link on another site cannot log you out
    }

    [Fact]
    public async Task Logout_destroys_the_server_side_session_and_hands_the_page_the_idp_end_session_url()
    {
        await using var rig = await SignedIn();
        var (name, value) = rig.Browser.Cookies.Single();

        var res = await rig.Browser.Send(HttpMethod.Post, "/bff/logout", Csrf);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var url = new Uri(Json(await res.Content.ReadAsStringAsync()).GetProperty("endSessionUrl").GetString()!);
        Assert.StartsWith(rig.Idp.Authority + "/protocol/openid-connect/logout", url.ToString());
        var q = System.Web.HttpUtility.ParseQueryString(url.Query);
        Assert.Equal(rig.Idp.LatestIdToken, q["id_token_hint"]);                                  // the IdP must know *which* session to end
        Assert.StartsWith("https://localhost/", q["post_logout_redirect_uri"]);
        Assert.DoesNotContain(rig.Browser.Cookies.Keys, n => n == name);                          // the cookie is cleared in the browser ...

        // ... but a stolen copy of it must be worthless too: the session is gone on the server
        var thief = new Browser(rig.RawClient);
        thief.SetCookie(name, value);
        var before = rig.Api.Requests.Count;
        Assert.Equal(HttpStatusCode.Unauthorized, (await thief.Get("/bff/user")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await thief.Get("/api/me")).StatusCode);
        Assert.Equal(before, rig.Api.Requests.Count);
    }

    // ---------------- session lifetime ----------------

    [Fact]
    public async Task An_idle_session_expires_and_activity_keeps_it_alive()
    {
        await using var rig = await SignedIn();                                 // idle timeout 30 minutes (Bff:IdleTimeout)
        rig.Advance(TimeSpan.FromMinutes(20));
        Assert.Equal(HttpStatusCode.OK, (await rig.Browser.Get("/bff/user")).StatusCode);
        rig.Advance(TimeSpan.FromMinutes(20));                                  // 40 minutes after login, 20 after the last request
        Assert.Equal(HttpStatusCode.OK, (await rig.Browser.Get("/bff/user")).StatusCode);
        rig.Advance(TimeSpan.FromMinutes(31));                                  // idle for longer than the timeout
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/bff/user")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/api/me")).StatusCode);
    }

    [Fact]
    public async Task A_session_ends_after_its_absolute_lifetime_however_active_the_user_is()
    {
        await using var rig = await SignedIn();                                 // lifetime 8 hours (Bff:SessionLifetime)
        var issued = rig.Browser.SetCookies.Count;
        for (var minutes = 20; minutes < 8 * 60; minutes += 20)
        {
            rig.Advance(TimeSpan.FromMinutes(20));
            Assert.Equal(HttpStatusCode.OK, (await rig.Browser.Get("/bff/user")).StatusCode);
        }
        Assert.Equal(issued, rig.Browser.SetCookies.Count);                     // the cookie is never re-issued ("sliding"): activity extends nothing but the idle timer
        rig.Advance(TimeSpan.FromMinutes(25));                                  // 8 h 05 min after login, active the whole time
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/bff/user")).StatusCode);
    }

    [Fact]
    public async Task An_expired_session_is_removed_from_the_browser_too()
    {
        await using var rig = await SignedIn();
        rig.Advance(TimeSpan.FromHours(1));
        var res = await rig.Browser.Get("/bff/user");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Empty(rig.Browser.Cookies);
    }

    // ---------------- refresh tokens, server side ----------------

    [Fact]
    public async Task The_access_token_is_refreshed_by_the_gateway_shortly_before_it_expires()
    {
        await using var rig = await SignedIn();                                 // access token: 5 minutes, refresh skew: 1 minute
        var first = await Authorization(rig);
        Assert.Equal("Bearer " + rig.Idp.IssuedAccessTokens.First(), first);

        rig.Advance(TimeSpan.FromMinutes(3));
        Assert.Equal(first, await Authorization(rig));                          // still comfortably valid: no refresh
        Assert.Equal(0, rig.Idp.RefreshCalls);

        rig.Advance(TimeSpan.FromSeconds(110));                                 // 4:50 after login: inside the skew
        var second = await Authorization(rig);
        Assert.NotEqual(first, second);
        Assert.Equal("Bearer " + rig.Idp.LatestAccessToken, second);
        Assert.Equal(1, rig.Idp.RefreshCalls);
        Assert.Equal(second, await Authorization(rig));                         // and the next call reuses it
        Assert.Equal(1, rig.Idp.RefreshCalls);
        Assert.Single(rig.Browser.Cookies);                                     // the browser noticed nothing
    }

    [Fact]
    public async Task Refresh_tokens_are_rotated_and_each_one_is_used_exactly_once()
    {
        await using var rig = await SignedIn();
        for (var i = 0; i < 4; i++)
        {
            rig.Advance(TimeSpan.FromMinutes(5));
            var sent = await Authorization(rig);
            Assert.Equal("Bearer " + rig.Idp.LatestAccessToken, sent);
        }
        Assert.Equal(4, rig.Idp.RefreshCalls);
        Assert.Equal(0, rig.Idp.ReuseDetections);                               // always the newest refresh token, never an old one
        Assert.Empty(rig.Idp.Problems);
        Assert.Equal(5, rig.Idp.IssuedRefreshTokens.Distinct().Count());
    }

    [Fact]
    public async Task Concurrent_requests_with_an_expired_token_cause_one_refresh_not_a_reuse()
    {
        await using var rig = await SignedIn();
        rig.Idp.RefreshLatency = TimeSpan.FromMilliseconds(250);                // a slow IdP widens the race window
        rig.Advance(TimeSpan.FromMinutes(6));

        var responses = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => rig.Browser.Get("/api/me")));

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.Equal(1, rig.Idp.RefreshCalls);
        Assert.Equal(0, rig.Idp.ReuseDetections);
        Assert.All(rig.Api.Requests, r => Assert.Equal("Bearer " + rig.Idp.LatestAccessToken, r.Headers.Authorization!.ToString()));
        Assert.Equal(10, rig.Api.Requests.Count);
    }

    [Fact]
    public async Task When_the_idp_refuses_the_refresh_the_session_ends_and_nothing_expired_reaches_the_api()
    {
        await using var rig = await SignedIn();
        var (name, value) = rig.Browser.Cookies.Single();
        rig.Idp.RevokeEverything();                                             // the user was logged out at the IdP / reuse was detected there
        rig.Advance(TimeSpan.FromMinutes(6));

        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/api/me")).StatusCode);
        Assert.Empty(rig.Api.Requests);
        Assert.Equal(HttpStatusCode.Unauthorized, (await rig.Browser.Get("/bff/user")).StatusCode);   // the session is gone, not retried forever
        var copy = new Browser(rig.RawClient);                                  // ... on the server, not just in this browser
        copy.SetCookie(name, value);
        Assert.Equal(HttpStatusCode.Unauthorized, (await copy.Get("/bff/user")).StatusCode);
        Assert.Equal(1, rig.Idp.RefreshCalls);
    }

    // ---------------- secrets ----------------

    [Fact]
    public void No_client_secret_is_committed()
    {
        var root = RepoRoot.Find();
        foreach (var file in Directory.GetFiles(Path.Combine(root, "backend", "src", "SecLab.Gateway"), "appsettings*.json"))
        {
            var doc = JsonDocument.Parse(File.ReadAllText(file));
            if (doc.RootElement.TryGetProperty("Bff", out var bff) && bff.TryGetProperty("ClientSecret", out var secret))
                Assert.True(string.IsNullOrEmpty(secret.GetString()), $"{Path.GetFileName(file)} contains a client secret");
        }
        foreach (var file in Directory.GetFiles(Path.Combine(root, "infra", "keycloak"), "*.json"))
        {
            // the realm may declare the confidential client, but the secret is generated by Keycloak (read it with docs/init-bff-secret.sh)
            foreach (var secret in System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(file), "\"secret\"\\s*:\\s*\"([^\"]*)\"").Select(m => m.Groups[1].Value))
                Assert.True(secret.Length == 0 || secret.StartsWith("${"), $"{Path.GetFileName(file)} contains a literal client secret");
        }
        var realm = File.ReadAllText(Path.Combine(root, "infra", "keycloak", "seclab-realm.json"));
        Assert.Contains("\"seclab-bff\"", realm);                              // shipped infrastructure: the confidential client exists
    }
}
