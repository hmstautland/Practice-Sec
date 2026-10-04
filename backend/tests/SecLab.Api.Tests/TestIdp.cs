using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SecLab.Api.Tests;

/// <summary>
/// A stand-in identity provider for tests: it owns a signing key, mints tokens, and wires the API's standard
/// JwtBearer handler to trust that key *without* touching the API's own issuer/audience/lifetime rules.
/// The API must read its settings from configuration keys Auth:Authority and Auth:Audience.
/// </summary>
public sealed class TestIdp : IDisposable
{
    public const string Issuer = "https://idp.test/realms/seclab";
    public const string Audience = "seclab-api";

    readonly RsaSecurityKey _key = new(RSA.Create(2048)) { KeyId = "test-key-1" };
    readonly Dictionary<string, string?> _previousEnv = new();

    public TestIdp()
    {
        // Set as environment variables so they are visible even if Program.cs reads configuration eagerly.
        Set("Auth__Authority", Issuer);
        Set("Auth__Audience", Audience);
    }

    void Set(string name, string value)
    {
        _previousEnv[name] = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
    }

    public void Dispose()
    {
        foreach (var (k, v) in _previousEnv) Environment.SetEnvironmentVariable(k, v);
        foreach (var host in _hosts.Values) host.Dispose();
    }

    readonly Dictionary<WebApplicationFactory<Program>, WebApplicationFactory<Program>> _hosts = new();

    /// <summary>Extra test-only service registrations for the host (set before the first client is created).</summary>
    public Action<IServiceCollection>? ExtraServices { get; set; }

    /// <summary>TestServer has no sockets. This filter gives every request a client address: 127.0.0.1, or whatever the test puts in X-Test-Remote-Ip.</summary>
    sealed class FakeRemoteIp : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((ctx, n) =>
            {
                ctx.Connection.RemoteIpAddress = ctx.Request.Headers.TryGetValue("X-Test-Remote-Ip", out var ip) ? IPAddress.Parse(ip.ToString()) : IPAddress.Loopback;
                return n();
            });
            next(app);
        };
    }

    /// <summary>
    /// One test host per TestIdp: its JwtBearer handler trusts this IdP's key instead of downloading discovery metadata.
    /// All clients created from the same base factory share that host (and so its in-memory state, e.g. rate limiters).
    /// </summary>
    public WebApplicationFactory<Program> Host(WebApplicationFactory<Program> factory)
    {
        lock (_hosts)
        {
            if (_hosts.TryGetValue(factory, out var existing)) return existing;
            var config = new OpenIdConnectConfiguration { Issuer = Issuer };
            config.SigningKeys.Add(_key);
            return _hosts[factory] = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
            {
                s.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme,
                    o => o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(config));
                s.AddTransient<IStartupFilter, FakeRemoteIp>();
                ExtraServices?.Invoke(s);
                Mutants.Apply(s);                 // step 16: fault injection, only when SECLAB_MUTANT is set
            }));
        }
    }

    public HttpClient CreateClient(WebApplicationFactory<Program> factory) =>
        Host(factory).CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });

    public string Token(string username = "alice", string? issuer = null, string? audience = null,
        TimeSpan? expiresIn = null, SecurityKey? signWith = null)
    {
        var now = DateTime.UtcNow;
        var expires = now + (expiresIn ?? TimeSpan.FromMinutes(5));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer ?? Issuer,
            Audience = audience ?? Audience,
            NotBefore = expires < now ? expires.AddHours(-1) : now.AddSeconds(-1),
            IssuedAt = expires < now ? expires.AddHours(-1) : now.AddSeconds(-1),
            Expires = expires,
            Claims = new Dictionary<string, object> { ["sub"] = Guid.NewGuid().ToString(), ["preferred_username"] = username },
            SigningCredentials = new SigningCredentials(signWith ?? _key, SecurityAlgorithms.RsaSha256),
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    public static RsaSecurityKey AttackerKey() => new(RSA.Create(2048)) { KeyId = "test-key-1" };   // same kid, different key

    /// <summary>A token whose header says alg=none and which carries no signature.</summary>
    public static string UnsignedToken(string username = "alice")
    {
        static string B64(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        return $"{B64("{\"alg\":\"none\",\"typ\":\"JWT\"}")}.{B64($"{{\"iss\":\"{Issuer}\",\"aud\":\"{Audience}\",\"exp\":{exp},\"preferred_username\":\"{username}\"}}")}.";
    }
}
