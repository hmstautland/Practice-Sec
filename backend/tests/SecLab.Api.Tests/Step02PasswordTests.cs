using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecLab.Api.Data;
using SecLab.Api.Models;
using Xunit;

namespace SecLab.Api.Tests;

// Step 02 – Password storage & login hardening. Red on the starter, green when done.
// Requires the SQL Server container: docker compose up -d sqlserver
[Trait("Step", "02")]
public class Step02PasswordTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    const string GoodPassword = "correct-horse-battery-staple";

    HttpClient NewClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = new Uri("https://localhost"),
    });

    static async Task RegisterOrFail(HttpClient c, string name, string password)
    {
        var res = await Register(c, name, password);
        Assert.True(res.IsSuccessStatusCode, $"precondition: register returned {(int)res.StatusCode}");
    }

    /// <summary>Error bodies may carry a per-request trace id (step 11); everything else must be identical.</summary>
    static string WithoutTrace(string body) => System.Text.RegularExpressions.Regex.Replace(body, "\"traceId\":\"[^\"]*\"", "");

    static string NewName() => "t" + Guid.NewGuid().ToString("N")[..10];

    static Task<HttpResponseMessage> Register(HttpClient c, string name, string password) =>
        c.PostAsJsonAsync("/api/auth/register", new { username = name, password, displayName = name, email = $"{name}@example.com" });

    static Task<HttpResponseMessage> Login(HttpClient c, string name, string password) =>
        c.PostAsJsonAsync("/api/auth/login", new { username = name, password });

    string StoredPassword(string username)
    {
        using var scope = factory.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.Single(u => u.Username == username).Password;
    }

    [Fact]
    public async Task Registration_stores_a_hash_not_the_password()
    {
        var c = NewClient(); var name = NewName();

        var res = await Register(c, name, GoodPassword);

        Assert.True(res.IsSuccessStatusCode, $"register returned {(int)res.StatusCode}");
        var stored = StoredPassword(name);
        Assert.NotEqual(GoodPassword, stored);
        Assert.DoesNotContain(GoodPassword, stored);
        Assert.True(stored.Length >= 40, "a salted, slow hash is much longer than a plain password");
    }

    [Fact]
    public async Task Registration_rejects_short_passwords()
    {
        var res = await Register(NewClient(), NewName(), "short");
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Registered_user_can_log_in_and_response_does_not_leak_the_password_or_hash()
    {
        var c = NewClient(); var name = NewName();
        await RegisterOrFail(c, name, GoodPassword);

        var res = await Login(c, name, GoodPassword);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadAsStringAsync();
        Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(StoredPassword(name), body);
    }

    [Fact]
    public async Task Seeded_users_can_still_log_in()
    {
        // Note: this fails while alice is locked out (e.g. right after running 00-baseline.sh with the lockout in place).
        var res = await Login(NewClient(), "alice", "password123");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Legacy_plaintext_passwords_are_upgraded_after_a_successful_login()
    {
        var name = NewName(); const string legacy = "legacy-plaintext-pw";
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Users.Add(new User { Username = name, Password = legacy, DisplayName = name });   // as the starter stored them
            db.SaveChanges();
        }

        var res = await Login(NewClient(), name, legacy);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.NotEqual(legacy, StoredPassword(name));
        Assert.Equal(HttpStatusCode.OK, (await Login(NewClient(), name, legacy)).StatusCode);   // still works after the upgrade
    }

    [Fact]
    public async Task Unknown_user_and_wrong_password_are_indistinguishable()
    {
        var c = NewClient(); var name = NewName();
        await RegisterOrFail(c, name, GoodPassword);

        var wrongPassword = await Login(c, name, "not-the-password-at-all");
        var unknownUser = await Login(c, NewName(), "not-the-password-at-all");

        Assert.Equal(wrongPassword.StatusCode, unknownUser.StatusCode);
        Assert.Equal(WithoutTrace(await wrongPassword.Content.ReadAsStringAsync()), WithoutTrace(await unknownUser.Content.ReadAsStringAsync()));
    }

    [Fact]
    public async Task Account_is_locked_after_five_failed_attempts_even_for_the_right_password()
    {
        var c = NewClient(); var name = NewName();
        await RegisterOrFail(c, name, GoodPassword);
        for (var i = 0; i < 5; i++) await Login(c, name, "wrong-password-" + i);

        var res = await Login(c, name, GoodPassword);

        Assert.NotEqual(HttpStatusCode.OK, res.StatusCode);
    }
}
