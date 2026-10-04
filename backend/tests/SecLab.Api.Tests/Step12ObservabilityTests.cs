using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace SecLab.Api.Tests;

// Step 12 – Logging, observability & monitoring. Contract: docs/12-logging-observability.md.
// Audit events are logged under the category "SecLab.Audit" with structured properties:
//   Event (e.g. "login.failed"), ClientIp, and per event Username / UserId / KeyId / Endpoint / Level ...
[Trait("Step", "12")]
public class Step12ObservabilityTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly List<IDisposable> _disposables = [];
    public void Dispose() { foreach (var d in _disposables) d.Dispose(); }

    (Harness H, LogCapture Logs, MetricCapture Metrics) Start(params (string, string)[] settings)
    {
        if (settings.Length > 0) _disposables.Add(new EnvScope(settings));
        var logs = new LogCapture(); var metrics = new MetricCapture();
        _disposables.Add(metrics);
        var h = new Harness(factory, s => s.AddSingleton<ILoggerProvider>(logs));
        _disposables.Add(h);
        return (h, logs, metrics);
    }

    static Task<HttpResponseMessage> Post(HttpClient c, string url, object body, string? ip = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body) };
        if (ip is not null) req.Headers.Add("X-Test-Remote-Ip", ip);
        return c.SendAsync(req);
    }

    static string Unique(string p) => p + Guid.NewGuid().ToString("N")[..10];

    static async Task<string> Register(HttpClient c, string name, string password)
    {
        var res = await Post(c, "/api/auth/register", new { username = name, password, displayName = name, email = name + "@example.com" });
        Assert.True(res.IsSuccessStatusCode, $"register returned {(int)res.StatusCode}");
        return name;
    }

    // ---------- security events ----------

    [Fact]
    public async Task A_failed_login_is_an_audit_warning_with_who_and_from_where_but_never_the_password()
    {
        var (h, logs, _) = Start();
        var name = Unique("ghost"); var password = "S3cret-" + Guid.NewGuid().ToString("N");

        await Post(h.Anonymous(), "/api/auth/login", new { username = name, password }, ip: "203.0.113.5");

        var e = logs.AuditEvent("login.failed");
        Assert.NotNull(e);
        Assert.Equal(LogLevel.Warning, e!.Level);
        Assert.Equal("203.0.113.5", e.Str("ClientIp"));
        Assert.Equal(name, e.Str("Username"));
        Assert.DoesNotContain(logs.Entries, x => x.AllText().Any(t => t.Contains(password)));
    }

    [Fact]
    public async Task Registration_login_and_lockout_are_recorded_with_the_user_id()
    {
        var (h, logs, _) = Start();
        var anon = h.Anonymous(); var name = Unique("audit"); const string pw = "correct-horse-battery-staple";
        await Register(anon, name, pw);
        var userId = h.InDb(db => db.Users.Single(u => u.Username == name).Id).ToString();

        Assert.Equal(userId, logs.AuditEvent("user.registered")?.Str("UserId"));

        await Post(anon, "/api/auth/login", new { username = name, password = pw });
        Assert.Equal(userId, logs.AuditEvent("login.succeeded")?.Str("UserId"));

        for (var i = 0; i < 5; i++) await Post(anon, "/api/auth/login", new { username = name, password = "wrong-" + i });
        var locked = logs.AuditEvent("login.locked");
        Assert.NotNull(locked);
        Assert.Equal(userId, locked!.Str("UserId"));
        Assert.Equal(1, logs.Audit.Count(x => x.Str("Event") == "login.locked"));
    }

    [Fact]
    public async Task Authorization_denials_and_rate_limit_rejections_are_recorded()
    {
        var (h, logs, _) = Start(("RateLimiting__Anonymous", "2"), ("RateLimiting__WindowSeconds", "600"), ("RateLimiting__User", "100"), ("RateLimiting__Login", "100"));
        var user = h.NewPerson();

        Assert.Equal(HttpStatusCode.Forbidden, (await user.Http.GetAsync("/api/admin/users")).StatusCode);
        var denied = logs.AuditEvent("authz.denied");
        Assert.NotNull(denied);
        Assert.Equal(LogLevel.Warning, denied!.Level);
        Assert.Equal(user.Id.ToString(), denied.Str("UserId"));
        Assert.Contains("admin", denied.Str("Endpoint") ?? "", StringComparison.OrdinalIgnoreCase);

        var anon = h.Anonymous();
        for (var i = 0; i < 3; i++) await anon.GetAsync("/api/blogs");
        var limited = logs.AuditEvent("ratelimit.rejected");
        Assert.NotNull(limited);
        Assert.False(string.IsNullOrEmpty(limited!.Str("ClientIp")));
    }

    [Fact]
    public async Task Api_key_lifecycle_and_misuse_are_recorded_without_the_key()
    {
        var (h, logs, _) = Start();
        var owner = h.NewPerson();
        var created = await (await owner.Http.PostAsJsonAsync("/api/keys", new { name = "k", level = "read" })).Content.ReadFromJsonAsync<JsonElement>();
        var key = created.GetProperty("apiKey").GetString()!; var id = created.GetProperty("id").GetInt32().ToString();

        var made = logs.AuditEvent("apikey.created");
        Assert.Equal(id, made?.Str("KeyId")); Assert.Equal(owner.Id.ToString(), made?.Str("UserId")); Assert.Equal("read", made?.Str("Level"));

        var bad = new HttpRequestMessage(HttpMethod.Get, "/api/partner/blogs"); bad.Headers.Add("X-Api-Key", key[..^3] + "zzz"); bad.Headers.Add("X-Test-Remote-Ip", "198.51.100.9");
        await h.Anonymous().SendAsync(bad);
        var rejected = logs.AuditEvent("apikey.rejected");
        Assert.NotNull(rejected);
        Assert.Equal("198.51.100.9", rejected!.Str("ClientIp"));

        var secret = key.Split('_')[2];
        Assert.DoesNotContain(logs.Entries, x => x.AllText().Any(t => t.Contains(secret)));
    }

    [Fact]
    public async Task Administrative_changes_are_recorded_with_actor_and_target()
    {
        var (h, logs, _) = Start();
        var admin = h.NewPerson("Admin"); var target = h.NewPerson();

        await admin.Http.PutAsJsonAsync($"/api/admin/users/{target.Id}/role", new { role = "Admin" });

        var e = logs.AuditEvent("role.changed");
        Assert.NotNull(e);
        Assert.Equal(admin.Id.ToString(), e!.Str("UserId"));
        Assert.Equal(target.Id.ToString(), e.Str("TargetUserId"));
        Assert.Equal("Admin", e.Str("NewRole"));
    }

    // ---------- what must never be in a log ----------

    [Fact]
    public async Task No_credential_of_any_kind_ever_reaches_the_log()
    {
        var (h, logs, _) = Start();
        var anon = h.Anonymous(); var name = Unique("sec"); var password = "Pa55-" + Guid.NewGuid().ToString("N");
        await Register(anon, name, password);
        await Post(anon, "/api/auth/login", new { username = name, password = "wrong-" + password });
        await Post(anon, "/api/auth/login", new { username = name, password });

        var person = h.NewPerson();
        var bearer = person.Http.DefaultRequestHeaders.Authorization!.Parameter!;
        var created = await (await person.Http.PostAsJsonAsync("/api/keys", new { name = "k", level = "write" })).Content.ReadFromJsonAsync<JsonElement>();
        var key = created.GetProperty("apiKey").GetString()!;
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/partner/blogs"); req.Headers.Add("X-Api-Key", key);
        await anon.SendAsync(req);
        await person.Http.GetAsync("/api/me");
        var hash = h.InDb(db => db.Users.Single(u => u.Username == name).Password);

        var secrets = new[] { password, "wrong-" + password, bearer, key, key.Split('_')[2], hash };
        foreach (var e in logs.Entries)
            foreach (var text in e.AllText())
                foreach (var s in secrets)
                    Assert.False(text.Contains(s), $"a secret ended up in a log entry from '{e.Category}': {text[..Math.Min(text.Length, 120)]}");
    }

    [Fact]
    public async Task User_supplied_text_cannot_forge_or_split_log_lines()
    {
        var (h, logs, _) = Start();
        var hostile = "bob\r\n2026-01-01T00:00:00Z info: admin logged in from 10.0.0.1\u001b[31m";

        await Post(h.Anonymous(), "/api/auth/login", new { username = hostile, password = "whatever-pass" });

        Assert.NotNull(logs.AuditEvent("login.failed"));
        foreach (var e in logs.Entries)
            foreach (var text in e.AllText().Where(t => e.Exception is null || t != e.Exception.ToString()))
                Assert.True(text.All(c => !char.IsControl(c) || c == '\t'), $"control character in log text: {text.Replace("\r", "\\r").Replace("\n", "\\n")}");
        Assert.True((logs.AuditEvent("login.failed")!.Str("Username") ?? "").Length <= 64, "user-supplied values are truncated");
    }

    // ---------- correlation ----------

    [Fact]
    public async Task The_trace_id_in_an_error_response_finds_the_log_entry_and_incoming_trace_context_is_honoured()
    {
        var (h, logs, _) = Start();
        var admin = h.NewPerson("Admin");
        const string incoming = "4bf92f3577b34da6a3ce929d0e0e4736";
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/debug/crash");
        req.Headers.Add("traceparent", $"00-{incoming}-00f067aa0ba902b7-01");

        var res = await admin.Http.SendAsync(req);
        var traceId = JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.GetProperty("traceId").GetString()!;

        Assert.Contains(incoming, traceId);                                         // W3C trace context propagated, not replaced
        var failure = logs.Entries.LastOrDefault(e => e.Level == LogLevel.Error && e.Exception is not null);
        Assert.NotNull(failure);
        Assert.Contains(failure!.Scopes, s => s.TryGetValue("TraceId", out var t) && t?.ToString() == incoming);
    }

    // ---------- metrics ----------

    [Fact]
    public async Task Security_counters_move_and_never_carry_user_identifying_tags()
    {
        var (h, _, metrics) = Start(("RateLimiting__Anonymous", "2"), ("RateLimiting__WindowSeconds", "600"), ("RateLimiting__Login", "100"), ("RateLimiting__User", "100"));
        var user = h.NewPerson(); var admin = h.NewPerson("Admin");
        var anon = h.Anonymous();

        await Post(anon, "/api/auth/login", new { username = Unique("nobody"), password = "wrong-password-1" }, ip: "203.0.113.77");
        await user.Http.GetAsync("/api/admin/users");
        await admin.Http.GetAsync("/api/debug/crash");
        for (var i = 0; i < 4; i++) await anon.GetAsync("/api/blogs");

        Assert.True(metrics.Sum("seclab.auth.login.failures") >= 1, "seclab.auth.login.failures");
        Assert.True(metrics.Sum("seclab.authz.denied") >= 1, "seclab.authz.denied");
        Assert.True(metrics.Sum("seclab.errors.unhandled") >= 1, "seclab.errors.unhandled");
        Assert.True(metrics.Sum("seclab.ratelimit.rejected") >= 1, "seclab.ratelimit.rejected");

        var forbiddenTagKeys = new[] { "username", "user", "userid", "ip", "clientip", "email", "key", "keyid", "path" };
        foreach (var m in metrics.Measurements)
            Assert.DoesNotContain(m.Tags.Keys, k => forbiddenTagKeys.Contains(k.ToLowerInvariant().Replace(".", "").Replace("_", "")));
        Assert.All(metrics.Measurements, m => Assert.True(m.Tags.Count <= 2, "few tags with a small value set"));
    }

    // ---------- health ----------

    [Fact]
    public async Task Liveness_and_readiness_probes_are_anonymous_and_reveal_nothing()
    {
        var anon = Start().H.Anonymous();
        foreach (var url in new[] { "/health/live", "/health/ready" })
        {
            var res = await anon.GetAsync(url);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Equal("Healthy", await res.Content.ReadAsStringAsync());
        }
    }
}
