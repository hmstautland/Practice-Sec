using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecLab.Api.Data;
using SecLab.Api.Models;
using Xunit;

namespace SecLab.Api.Tests;

// Step 04 – WebAuthn / passkeys as step-up authentication. Red on the previous step's code, green when done.
// Contract: docs/04-webauthn.md. Requires SQL Server; does not need Keycloak (TestIdp mints tokens).
[Trait("Step", "04")]
public class Step04PasskeyTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly TestIdp _idp = new();
    public void Dispose() => _idp.Dispose();

    sealed class Session(HttpClient http, string username)
    {
        public HttpClient Http { get; } = http;
        public string Username { get; } = username;
        public SoftAuthenticator Passkey { get; } = new();

        public async Task<(HttpResponseMessage Res, JsonElement Body)> Post(string url, object? body = null, string? stepUp = null)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body ?? new { }) };
            if (stepUp is not null) req.Headers.Add("X-StepUp", stepUp);
            var res = await Http.SendAsync(req);
            return (res, await ReadJson(res));
        }

        public async Task<HttpResponseMessage> Delete(string url, string? stepUp = null)
        {
            var req = new HttpRequestMessage(HttpMethod.Delete, url);
            if (stepUp is not null) req.Headers.Add("X-StepUp", stepUp);
            return await Http.SendAsync(req);
        }

        static async Task<JsonElement> ReadJson(HttpResponseMessage res)
        {
            var text = await res.Content.ReadAsStringAsync();
            try { return JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text).RootElement.Clone(); }
            catch (JsonException) { return JsonDocument.Parse("{}").RootElement.Clone(); }
        }
    }

    Session NewUser()
    {
        var name = "pk" + Guid.NewGuid().ToString("N")[..10];
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Users.Add(new User { Username = name, DisplayName = name, Email = $"{name}@example.com", Password = "x" });
            db.SaveChanges();
        }
        var http = _idp.CreateClient(factory);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _idp.Token(name));
        return new Session(http, name);
    }

    bool UserExists(string username)
    {
        using var scope = factory.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.Any(u => u.Username == username);
    }

    static async Task<string> RegistrationChallenge(Session s)
    {
        var (res, body) = await s.Post("/api/passkeys/register/options");
        Assert.True(res.IsSuccessStatusCode, $"register/options returned {(int)res.StatusCode}");
        return body.GetProperty("challenge").GetString()!;
    }

    static async Task<HttpResponseMessage> RegisterPasskey(Session s, Func<string, object>? build = null)
    {
        var challenge = await RegistrationChallenge(s);
        Func<string, object> make = build ?? (c => s.Passkey.Register(c));
        var (res, _) = await s.Post("/api/passkeys/register/complete", make(challenge));
        return res;
    }

    static async Task<string> AssertionChallenge(Session s)
    {
        var (res, body) = await s.Post("/api/passkeys/assert/options");
        Assert.True(res.IsSuccessStatusCode, $"assert/options returned {(int)res.StatusCode}");
        return body.GetProperty("challenge").GetString()!;
    }

    static async Task<(HttpResponseMessage Res, string? Token)> StepUp(Session s, Func<string, object>? build = null)
    {
        var challenge = await AssertionChallenge(s);
        Func<string, object> make = build ?? (c => s.Passkey.Assert(c));
        var (res, body) = await s.Post("/api/passkeys/assert/complete", make(challenge));
        return (res, res.IsSuccessStatusCode ? body.GetProperty("stepUpToken").GetString() : null);
    }

    // ---- registration ----

    [Fact]
    public async Task Registration_requires_a_signed_in_user()
    {
        var anonymous = _idp.CreateClient(factory);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/passkeys/register/options", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/passkeys/register/complete", new { })).StatusCode);
    }

    [Fact]
    public async Task Registration_options_name_the_relying_party_and_demand_user_verification()
    {
        var s = NewUser();
        var (res, body) = await s.Post("/api/passkeys/register/options");

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("localhost", body.GetProperty("rp").GetProperty("id").GetString());
        Assert.True(body.GetProperty("challenge").GetString()!.Length >= 22, "challenge should carry at least 16 random bytes");
        Assert.Equal("required", body.GetProperty("authenticatorSelection").GetProperty("userVerification").GetString(), ignoreCase: true);
    }

    [Fact]
    public async Task A_valid_registration_succeeds()
    {
        var s = NewUser();
        Assert.Equal(HttpStatusCode.OK, (await RegisterPasskey(s)).StatusCode);
    }

    [Fact]
    public async Task Registration_from_a_foreign_origin_is_rejected()
    {
        var s = NewUser();
        var res = await RegisterPasskey(s, c => s.Passkey.Register(c, origin: "https://evil.example"));
        Assert.False(res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Registration_for_a_different_relying_party_is_rejected()
    {
        var s = NewUser();
        var res = await RegisterPasskey(s, c => s.Passkey.Register(c, rpId: "evil.example"));
        Assert.False(res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Registration_with_a_challenge_the_server_never_issued_is_rejected()
    {
        var s = NewUser();
        await RegistrationChallenge(s);
        var res = await RegisterPasskey(s, _ => s.Passkey.Register(SoftAuthenticator.B64(RandomNumberGenerator.GetBytes(32))));
        Assert.False(res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Registration_without_user_verification_is_rejected()
    {
        var s = NewUser();
        var res = await RegisterPasskey(s, c => s.Passkey.Register(c, userVerified: false));
        Assert.False(res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task A_challenge_can_only_be_used_once()
    {
        var s = NewUser();
        var challenge = await RegistrationChallenge(s);
        var payload = s.Passkey.Register(challenge);

        Assert.Equal(HttpStatusCode.OK, (await s.Post("/api/passkeys/register/complete", payload)).Res.StatusCode);
        Assert.False((await s.Post("/api/passkeys/register/complete", payload)).Res.IsSuccessStatusCode, "replayed registration must fail");
    }

    // ---- step-up assertion ----

    [Fact]
    public async Task Assertion_options_are_refused_when_the_user_has_no_passkey()
    {
        var s = NewUser();
        await RegistrationChallenge(s);    // precondition: the passkey endpoints exist and this user may use them
        var (res, _) = await s.Post("/api/passkeys/assert/options");
        Assert.False(res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Sensitive_action_needs_step_up_and_a_passkey_assertion_provides_it()
    {
        var s = NewUser();
        await RegisterPasskey(s);

        Assert.Equal(HttpStatusCode.Forbidden, (await s.Delete("/api/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await s.Delete("/api/me", stepUp: "not-a-real-token")).StatusCode);
        Assert.True(UserExists(s.Username));

        var (res, token) = await StepUp(s);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.False(string.IsNullOrEmpty(token));

        Assert.Equal(HttpStatusCode.NoContent, (await s.Delete("/api/me", token)).StatusCode);
        Assert.False(UserExists(s.Username));
    }

    [Fact]
    public async Task Assertion_signed_with_a_different_key_is_rejected()
    {
        var s = NewUser();
        await RegisterPasskey(s);
        var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var (res, token) = await StepUp(s, c => s.Passkey.Assert(c, signWith: attacker));

        Assert.False(res.IsSuccessStatusCode);
        Assert.Null(token);
    }

    [Fact]
    public async Task Assertion_from_a_foreign_origin_is_rejected()
    {
        var s = NewUser();
        await RegisterPasskey(s);
        Assert.False((await StepUp(s, c => s.Passkey.Assert(c, origin: "https://evil.example"))).Res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task Assertion_without_user_verification_is_rejected()
    {
        var s = NewUser();
        await RegisterPasskey(s);
        Assert.False((await StepUp(s, c => s.Passkey.Assert(c, userVerified: false))).Res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task A_signature_counter_that_does_not_increase_is_rejected_as_a_possible_clone()
    {
        var s = NewUser();
        await RegisterPasskey(s);

        Assert.True((await StepUp(s, c => s.Passkey.Assert(c, counter: 5))).Res.IsSuccessStatusCode);
        Assert.False((await StepUp(s, c => s.Passkey.Assert(c, counter: 5))).Res.IsSuccessStatusCode);
    }

    [Fact]
    public async Task A_step_up_token_only_works_for_the_user_who_earned_it()
    {
        var alice = NewUser(); var mallory = NewUser();
        await RegisterPasskey(alice);
        var (_, token) = await StepUp(alice);
        Assert.NotNull(token);

        Assert.Equal(HttpStatusCode.Forbidden, (await mallory.Delete("/api/me", token)).StatusCode);
        Assert.True(UserExists(mallory.Username));
        Assert.True(UserExists(alice.Username));
    }

    [Fact]
    public async Task A_step_up_token_is_single_use()
    {
        var s = NewUser();
        await RegisterPasskey(s);
        var (_, token) = await StepUp(s);

        Assert.Equal(HttpStatusCode.NoContent, (await s.Delete("/api/me", token)).StatusCode);
        // the user is gone, but the token must not be accepted a second time by anyone either
        var other = NewUser();
        Assert.Equal(HttpStatusCode.Forbidden, (await other.Delete("/api/me", token)).StatusCode);
    }
}
