using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace SecLab.Gateway.Tests;

// Shipped test infrastructure for step 17 (not part of the solution): a real OpenID Provider on a loopback socket, a "browser" with a
// cookie jar, and a clock the tests can move. Nothing here knows how the gateway is implemented – it only speaks HTTP, OIDC and cookies.

/// <summary>A clock that runs with the real one but can be moved forward. The gateway must take its time from the registered <see cref="TimeProvider"/>.</summary>
public sealed class TestClock : TimeProvider
{
    long _offsetTicks;
    public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow() + TimeSpan.FromTicks(Interlocked.Read(ref _offsetTicks));
    public void Advance(TimeSpan by) => Interlocked.Add(ref _offsetTicks, by.Ticks);
}

public enum IdTokenFault { None, WrongNonce, WrongAudience, WrongIssuer, BadSignature }

/// <summary>
/// A tiny but strict identity provider: discovery, JWKS, authorization endpoint (auto-approves <see cref="User"/>), token endpoint
/// (authorization_code with PKCE and a confidential client, refresh_token **with rotation and reuse detection**, like Keycloak with
/// "Revoke Refresh Token" on) and an end-session endpoint. Everything that looks wrong is written to <see cref="Problems"/>.
/// </summary>
public sealed class FakeIdp : IAsyncDisposable
{
    public const string ClientId = "seclab-bff";
    public const string ClientSecret = "test-secret-not-a-real-credential";

    readonly WebApplication _app;
    readonly RSA _key = RSA.Create(2048);
    readonly RSA _otherKey = RSA.Create(2048);
    readonly string _kid = Guid.NewGuid().ToString("N");
    readonly ConcurrentDictionary<string, Code> _codes = new();
    readonly ConcurrentDictionary<string, RefreshToken> _refresh = new();
    readonly ConcurrentDictionary<string, bool> _revokedFamilies = new();
    readonly object _gate = new();
    int _refreshCalls, _reuse, _codeReplays;

    sealed record Code(string Challenge, string RedirectUri, string Nonce, string User) { public bool Used; }
    sealed record RefreshToken(string Family, string User) { public bool Used; }

    public string Origin { get; private set; } = "";
    public string Authority => Origin + "/realms/seclab";
    public string User { get; set; } = "carol";
    public int AccessTokenSeconds { get; set; } = 300;
    public TimeSpan RefreshLatency { get; set; } = TimeSpan.Zero;
    public IdTokenFault Fault { get; set; }

    public ConcurrentQueue<string> Problems { get; } = new();
    public ConcurrentQueue<string> IssuedAccessTokens { get; } = new();
    public ConcurrentQueue<string> IssuedRefreshTokens { get; } = new();
    public ConcurrentQueue<string> IssuedIdTokens { get; } = new();
    public ConcurrentQueue<Dictionary<string, string>> AuthorizeRequests { get; } = new();
    public ConcurrentQueue<Dictionary<string, string>> EndSessionRequests { get; } = new();
    public int RefreshCalls => _refreshCalls;
    /// <summary>How often an already-used refresh token was presented (a real IdP then revokes the whole token family).</summary>
    public int ReuseDetections => _reuse;
    public int CodeReplays => _codeReplays;
    public string LatestAccessToken => IssuedAccessTokens.Last();
    public string LatestIdToken => IssuedIdTokens.Last();

    /// <summary>The IdP session ends (admin logout, SSO max lifespan, reuse detected): no refresh token works any more.</summary>
    public void RevokeEverything() { foreach (var t in _refresh.Values) _revokedFamilies[t.Family] = true; }

    public static async Task<FakeIdp> StartAsync()
    {
        var idp = new FakeIdp();
        await idp.RunAsync();
        return idp;
    }

    FakeIdp()
    {
        var b = WebApplication.CreateSlimBuilder();
        b.Logging.ClearProviders();
        b.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["AllowedHosts"] = "*" });   // the gateway's appsettings.json is copied next to the tests: ignore its host filter
        b.WebHost.UseUrls("http://127.0.0.1:0");
        _app = b.Build();
    }

    async Task RunAsync()
    {
        const string realm = "/realms/seclab";
        _app.MapGet(realm + "/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = Authority,
            authorization_endpoint = Authority + "/protocol/openid-connect/auth",
            token_endpoint = Authority + "/protocol/openid-connect/token",
            jwks_uri = Authority + "/protocol/openid-connect/certs",
            end_session_endpoint = Authority + "/protocol/openid-connect/logout",
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            code_challenge_methods_supported = new[] { "S256" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
            grant_types_supported = new[] { "authorization_code", "refresh_token" },
            scopes_supported = new[] { "openid", "profile", "email" },
        }));
        _app.MapGet(realm + "/protocol/openid-connect/certs", () =>
        {
            var p = _key.ExportParameters(false);
            return Results.Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = _kid, n = B64(p.Modulus!), e = B64(p.Exponent!) } } });
        });
        _app.MapGet(realm + "/protocol/openid-connect/auth", Authorize);
        _app.MapPost(realm + "/protocol/openid-connect/token", (Delegate)Token);
        _app.MapGet(realm + "/protocol/openid-connect/logout", (HttpContext ctx) =>
        {
            var q = ctx.Request.Query.ToDictionary(k => k.Key, k => k.Value.ToString());
            EndSessionRequests.Enqueue(q);
            return q.TryGetValue("post_logout_redirect_uri", out var back) ? Results.Redirect(back) : Results.Ok();
        });

        await _app.StartAsync();
        Origin = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
    }

    IResult Authorize(HttpContext ctx)
    {
        var q = ctx.Request.Query.ToDictionary(k => k.Key, k => k.Value.ToString());
        AuthorizeRequests.Enqueue(q);
        string Get(string n) => q.TryGetValue(n, out var v) ? v : "";
        if (Get("response_type") != "code") Problems.Enqueue($"authorize: response_type must be 'code', was '{Get("response_type")}'");
        if (Get("client_id") != ClientId) Problems.Enqueue($"authorize: unknown client_id '{Get("client_id")}'");
        if (Get("code_challenge_method") != "S256" || Get("code_challenge").Length < 43) Problems.Enqueue("authorize: PKCE (S256 code_challenge) is required");
        if (Get("state").Length < 8) Problems.Enqueue("authorize: no state");
        if (Get("nonce").Length < 8) Problems.Enqueue("authorize: no nonce");
        if (!Get("scope").Split(' ').Contains("openid")) Problems.Enqueue("authorize: scope must contain openid");
        if (Get("client_secret") != "") Problems.Enqueue("authorize: the client secret must never travel through the browser");
        var redirect = Get("redirect_uri");
        if (redirect == "") return Results.BadRequest("redirect_uri missing");

        var code = B64(RandomNumberGenerator.GetBytes(24));
        _codes[code] = new Code(Get("code_challenge"), redirect, Get("nonce"), User);
        return Results.Redirect(redirect + (redirect.Contains('?') ? "&" : "?") + "code=" + code + "&state=" + Uri.EscapeDataString(Get("state")));
    }

    async Task<IResult> Token(HttpContext ctx)
    {
        var form = await ctx.Request.ReadFormAsync();
        string F(string n) => form.TryGetValue(n, out var v) ? v.ToString() : "";

        // client authentication: client_secret_basic or client_secret_post
        string id = F("client_id"), secret = F("client_secret");
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var pair = Encoding.UTF8.GetString(Convert.FromBase64String(auth[6..])).Split(':', 2);
            id = Uri.UnescapeDataString(pair[0]); secret = Uri.UnescapeDataString(pair.ElementAtOrDefault(1) ?? "");
        }
        if (id != ClientId || secret != ClientSecret) { Problems.Enqueue("token: client authentication failed"); return Error(401, "invalid_client"); }

        switch (F("grant_type"))
        {
            case "authorization_code":
            {
                if (!_codes.TryGetValue(F("code"), out var code)) return Error(400, "invalid_grant");
                lock (_gate) { if (code.Used) { Interlocked.Increment(ref _codeReplays); return Error(400, "invalid_grant"); } code.Used = true; }
                if (F("redirect_uri") != code.RedirectUri) { Problems.Enqueue("token: redirect_uri differs from the authorization request"); return Error(400, "invalid_grant"); }
                var verifier = F("code_verifier");
                if (verifier.Length < 43 || B64(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))) != code.Challenge) { Problems.Enqueue("token: PKCE verification failed"); return Error(400, "invalid_grant"); }
                return Results.Json(Issue(code.User, Guid.NewGuid().ToString("N"), code.Nonce, withIdToken: true));
            }
            case "refresh_token":
            {
                Interlocked.Increment(ref _refreshCalls);
                if (!_refresh.TryGetValue(F("refresh_token"), out var rt)) return Error(400, "invalid_grant");
                lock (_gate)
                {
                    if (_revokedFamilies.ContainsKey(rt.Family)) return Error(400, "invalid_grant");
                    if (rt.Used) { Interlocked.Increment(ref _reuse); _revokedFamilies[rt.Family] = true; Problems.Enqueue("token: an already used refresh token was presented (reuse)"); return Error(400, "invalid_grant"); }
                    rt.Used = true;                                   // rotation: every refresh token works exactly once
                }
                if (RefreshLatency > TimeSpan.Zero) await Task.Delay(RefreshLatency);
                return Results.Json(Issue(rt.User, rt.Family, nonce: null, withIdToken: false));
            }
            default: return Error(400, "unsupported_grant_type");
        }
    }

    static IResult Error(int status, string error) => Results.Json(new { error }, statusCode: status);

    Dictionary<string, object> Issue(string user, string family, string? nonce, bool withIdToken)
    {
        var now = DateTimeOffset.UtcNow;
        var access = Jwt(_key, new Dictionary<string, object>
        {
            ["iss"] = Authority, ["sub"] = Sub(user), ["aud"] = new[] { "seclab-api", "account" }, ["azp"] = ClientId,
            ["preferred_username"] = user, ["scope"] = "openid profile email", ["jti"] = Guid.NewGuid().ToString(),
            ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.AddSeconds(AccessTokenSeconds).ToUnixTimeSeconds(),
            ["padding"] = B64(RandomNumberGenerator.GetBytes(1400)),   // real access tokens are 1-2 KB: a cookie that carried one would be huge
        });
        var refresh = "rt-" + B64(RandomNumberGenerator.GetBytes(32));
        _refresh[refresh] = new RefreshToken(family, user);
        IssuedAccessTokens.Enqueue(access); IssuedRefreshTokens.Enqueue(refresh);
        var body = new Dictionary<string, object>
        {
            ["access_token"] = access, ["token_type"] = "Bearer", ["expires_in"] = AccessTokenSeconds,
            ["refresh_token"] = refresh, ["refresh_expires_in"] = 1800, ["scope"] = "openid profile email",
        };
        if (withIdToken)
        {
            var claims = new Dictionary<string, object>
            {
                ["iss"] = Fault == IdTokenFault.WrongIssuer ? "https://evil.example/realms/seclab" : Authority,
                ["sub"] = Sub(user), ["aud"] = Fault == IdTokenFault.WrongAudience ? "some-other-client" : ClientId, ["azp"] = ClientId,
                ["nonce"] = Fault == IdTokenFault.WrongNonce ? "an-attacker-chosen-nonce" : nonce ?? "",
                ["preferred_username"] = user, ["name"] = char.ToUpper(user[0]) + user[1..], ["sid"] = family,
                ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = now.AddSeconds(300).ToUnixTimeSeconds(),
            };
            var idToken = Jwt(Fault == IdTokenFault.BadSignature ? _otherKey : _key, claims);
            IssuedIdTokens.Enqueue(idToken);
            body["id_token"] = idToken;
        }
        return body;
    }

    static string Sub(string user) => new Guid(MD5.HashData(Encoding.UTF8.GetBytes(user))).ToString();

    string Jwt(RSA key, Dictionary<string, object> claims)
    {
        var header = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "JWT", kid = _kid }));
        var payload = B64(JsonSerializer.SerializeToUtf8Bytes(claims));
        var sig = key.SignData(Encoding.ASCII.GetBytes(header + "." + payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return header + "." + payload + "." + B64(sig);
    }

    static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public async ValueTask DisposeAsync() { await _app.StopAsync(); await _app.DisposeAsync(); _key.Dispose(); _otherKey.Dispose(); }
}

/// <summary>A browser as far as this step cares: it keeps cookies, follows the OIDC redirects by hand and records everything it sees.</summary>
public sealed class Browser
{
    readonly HttpClient _gateway;
    readonly HttpClient _idp = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
    readonly Dictionary<string, string> _jar = new(StringComparer.Ordinal);
    readonly StringBuilder _transcript = new();

    public Browser(HttpClient gateway) => _gateway = gateway;

    public IReadOnlyDictionary<string, string> Cookies { get { lock (_jar) return new Dictionary<string, string>(_jar); } }
    /// <summary>Every raw Set-Cookie header the gateway has sent.</summary>
    public List<string> SetCookies { get; } = [];
    /// <summary>Status line, headers and body of every response, as text: what a script in the page could possibly get hold of.</summary>
    public string Transcript { get { lock (_transcript) return _transcript.ToString(); } }
    public string? LastCallbackPathAndQuery { get; private set; }

    public void SetCookie(string name, string value) { lock (_jar) _jar[name] = value; }
    public void ClearCookies() { lock (_jar) _jar.Clear(); }

    public async Task<HttpResponseMessage> Send(HttpMethod method, string path, params (string Name, string Value)[] headers)
    {
        var req = new HttpRequestMessage(method, path);
        foreach (var (n, v) in headers) req.Headers.TryAddWithoutValidation(n, v);
        if (method != HttpMethod.Get && method != HttpMethod.Head && req.Content is null) req.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        string cookie;
        lock (_jar) cookie = string.Join("; ", _jar.Select(c => $"{c.Key}={c.Value}"));
        if (cookie.Length > 0) req.Headers.TryAddWithoutValidation("Cookie", cookie);

        var res = await _gateway.SendAsync(req);
        var body = await res.Content.ReadAsStringAsync();
        if (res.Headers.TryGetValues("Set-Cookie", out var cookies))
            foreach (var sc in cookies) Absorb(sc);
        lock (_transcript)
        {
            _transcript.AppendLine($"--- {method} {path} -> {(int)res.StatusCode}");
            foreach (var h in res.Headers) _transcript.AppendLine($"{h.Key}: {string.Join(", ", h.Value)}");
            foreach (var h in res.Content.Headers) _transcript.AppendLine($"{h.Key}: {string.Join(", ", h.Value)}");
            _transcript.AppendLine(body);
        }
        return res;
    }

    public Task<HttpResponseMessage> Get(string path, params (string, string)[] headers) => Send(HttpMethod.Get, path, headers);

    public static readonly (string, string) Csrf = ("X-CSRF", "1");

    void Absorb(string setCookie)
    {
        lock (SetCookies) SetCookies.Add(setCookie);
        var parts = setCookie.Split(';', StringSplitOptions.TrimEntries);
        var nv = parts[0].Split('=', 2);
        var removes = nv.Length < 2 || nv[1] == "";
        foreach (var attr in parts.Skip(1))
        {
            if (attr.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase) && int.TryParse(attr[8..], out var age) && age <= 0) removes = true;
            if (attr.StartsWith("expires=", StringComparison.OrdinalIgnoreCase) && DateTimeOffset.TryParse(attr[8..], out var exp) && exp < DateTimeOffset.UtcNow.AddYears(-1)) removes = true;
        }
        lock (_jar) { if (removes) _jar.Remove(nv[0]); else _jar[nv[0]] = nv[1]; }
    }

    /// <summary>The first leg of a login: GET /bff/login. Returns the redirect to the IdP.</summary>
    public Task<HttpResponseMessage> StartLogin(string returnUrl = "/profile") => Get("/bff/login?returnUrl=" + Uri.EscapeDataString(returnUrl));

    /// <summary>A complete login: gateway -> IdP (auto-approves) -> gateway callback. Returns the callback response (normally a redirect to the return URL).</summary>
    public async Task<HttpResponseMessage> SignIn(FakeIdp idp, string returnUrl = "/profile", Func<string, string>? tamperCallback = null)
    {
        var start = await StartLogin(returnUrl);
        if (start.Headers.Location is null) return start;                               // the gateway refused to start a login
        var authorize = await _idp.GetAsync(start.Headers.Location);
        var back = authorize.Headers.Location ?? throw new InvalidOperationException("the IdP did not redirect back: " + await authorize.Content.ReadAsStringAsync());
        var callback = back.IsAbsoluteUri ? back.PathAndQuery : back.OriginalString;
        if (tamperCallback is not null) callback = tamperCallback(callback);
        LastCallbackPathAndQuery = callback;
        return await Get(callback);
    }
}

/// <summary>A gateway wired to a FakeApi, a FakeIdp, a movable clock and a browser. The Bff__* settings are the configuration keys of the step.</summary>
public sealed class BffRig : IAsyncDisposable
{
    public FakeIdp Idp { get; private init; } = null!;
    public Gw Gateway { get; private init; } = null!;
    public TestClock Clock { get; private init; } = null!;
    public Browser Browser { get; private init; } = null!;
    public FakeApi Api => Gateway.Api;
    public HttpClient RawClient { get; private init; } = null!;

    public static async Task<BffRig> Start(Func<HttpRequestMessage, HttpResponseMessage>? api = null, string environment = "Development", params (string, string)[] overrides)
    {
        var idp = await FakeIdp.StartAsync();
        var settings = new Dictionary<string, string>
        {
            ["Bff__Authority"] = idp.Authority,
            ["Bff__ClientId"] = FakeIdp.ClientId,
            ["Bff__ClientSecret"] = FakeIdp.ClientSecret,
            ["Bff__PublicOrigin"] = "https://localhost",
            ["Bff__IdleTimeout"] = "00:30:00",
            ["Bff__SessionLifetime"] = "08:00:00",
            ["Bff__RefreshSkew"] = "00:01:00",
        };
        foreach (var (k, v) in overrides) settings[k] = v;
        var clock = new TestClock();
        var gw = new Gw(api, environment, settings.Select(s => (s.Key, s.Value)).ToArray());
        gw.ConfigureServices = s => { s.RemoveAll<TimeProvider>(); s.AddSingleton<TimeProvider>(clock); };
        var client = gw.Client();
        return new BffRig { Idp = idp, Gateway = gw, Clock = clock, Browser = new Browser(client), RawClient = client };
    }

    public void Advance(TimeSpan by) => Clock.Advance(by);

    public async ValueTask DisposeAsync() { Gateway.Dispose(); await Idp.DisposeAsync(); }
}

public static class RepoRoot
{
    public static string Find()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "CLAUDE.md")) && Directory.Exists(Path.Combine(d.FullName, "backend"))) return d.FullName;
        throw new DirectoryNotFoundException("repository root not found");
    }
}
