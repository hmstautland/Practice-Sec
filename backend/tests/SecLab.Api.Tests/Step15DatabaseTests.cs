using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecLab.Api.Models;
using Xunit;

namespace SecLab.Api.Tests;

// Step 15 – Database & SQL security. Contract: docs/15-database-security.md.
// Needs the environment from `.env` (ConnectionStrings__Default = the app login, ConnectionStrings__Migrator = the schema owner).
[Trait("Step", "15")]
public class Step15DatabaseTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly Harness _h = new(factory);
    public void Dispose() => _h.Dispose();

    IConfiguration Config => factory.Services.GetRequiredService<IConfiguration>();
    string AppConnection => Config.GetConnectionString("Default") ?? throw new InvalidOperationException("ConnectionStrings:Default missing");
    string MigratorConnection => Config.GetConnectionString("Migrator") ?? throw new InvalidOperationException("ConnectionStrings:Migrator missing (needed for schema changes)");

    static T Scalar<T>(string connectionString, string sql)
    {
        using var c = new SqlConnection(connectionString); c.Open();
        using var cmd = c.CreateCommand(); cmd.CommandText = sql;
        return (T)Convert.ChangeType(cmd.ExecuteScalar()!, typeof(T));
    }

    static void Exec(string connectionString, string sql)
    {
        using var c = new SqlConnection(connectionString); c.Open();
        using var cmd = c.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery();
    }

    // ================= SQL injection =================

    async Task<HttpResponseMessage> Search(Harness.Person p, string q) => await p.Http.GetAsync("/api/blogs/search?q=" + Uri.EscapeDataString(q));

    int NewBlog(Harness.Person author, string title, string body = "<p>x</p>")
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecLab.Api.Data.AppDbContext>();
        var b = new Blog { AuthorId = author.Id, Title = title, Body = body };
        db.Blogs.Add(b); db.SaveChanges(); return b.Id;
    }

    [Theory]
    [InlineData("zzz' OR 1=1 --")]
    [InlineData("zzz' OR '1'='1")]
    [InlineData("zzz'; DROP TABLE Blogs; --")]
    [InlineData("zzz' UNION SELECT 1,2,'x','y',GETDATE() --")]
    [InlineData("zzz'/**/OR/**/1=1--")]
    [InlineData("zzz%' AND 1=(SELECT COUNT(*) FROM Users) --")]
    [InlineData("zzz'; WAITFOR DELAY '0:0:5'; --")]
    [InlineData("zzz\" OR \"\"=\"")]
    public async Task Injection_payloads_are_just_text_nothing_matches_and_nothing_breaks(string payload)
    {
        var p = _h.NewPerson();
        NewBlog(p, "An ordinary post " + Guid.NewGuid().ToString("N"));
        var blogsBefore = _h.InDb(db => db.Blogs.Count());
        var started = DateTime.UtcNow;

        var res = await Search(p, payload);

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);                                            // not a 500 from a syntax error
        var items = await res.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(0, items.GetArrayLength());                                                     // the payload is a search term, not a query
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(4), "a WAITFOR payload must not run");
        Assert.Equal(blogsBefore, _h.InDb(db => db.Blogs.Count()));                                  // and nothing was dropped or changed
    }

    [Fact]
    public async Task Normal_searches_still_work_including_quotes_and_like_wildcards_as_literal_characters()
    {
        var p = _h.NewPerson(); var tag = Guid.NewGuid().ToString("N")[..8];
        var quote = NewBlog(p, $"O'Reilly and {tag}");
        var percent = NewBlog(p, $"Growth of 100% in {tag}");
        var underscore = NewBlog(p, $"snake_case {tag}");
        NewBlog(p, $"Plain title {tag}");

        async Task<List<int>> Ids(string q) =>
            (await (await Search(p, q)).Content.ReadFromJsonAsync<JsonElement>()).EnumerateArray().Select(e => e.GetProperty("id").GetInt32()).ToList();

        Assert.Contains(quote, await Ids("O'Reilly"));
        Assert.Contains(percent, await Ids("100% in"));
        Assert.Equal([percent], (await Ids("%")).Intersect([quote, percent, underscore]).ToList());   // '%' is a character, not "match everything"
        Assert.Equal([underscore], (await Ids("e_c")).Intersect([quote, percent, underscore]).ToList());
        Assert.Equal(4, (await Ids(tag)).Count);
    }

    // ================= who the application connects as =================

    [Fact]
    public void The_application_connects_as_a_dedicated_least_privilege_login_never_sa()
    {
        var b = new SqlConnectionStringBuilder(AppConnection);
        Assert.NotEqual("sa", b.UserID.ToLowerInvariant());
        Assert.False(b.IntegratedSecurity);
        Assert.Equal("seclab_app", Scalar<string>(AppConnection, "SELECT SUSER_NAME()"));
        Assert.Equal(0, Scalar<int>(AppConnection, "SELECT IS_SRVROLEMEMBER('sysadmin')"));
        Assert.Equal(0, Scalar<int>(AppConnection, "SELECT IS_MEMBER('db_owner')"));
        Assert.Equal(0, Scalar<int>(AppConnection, "SELECT IS_MEMBER('db_ddladmin')"));
        Assert.Equal("seclab_app", _h.InDb(db => { var c = db.Database.GetDbConnection(); c.Open(); try { using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT SUSER_NAME()"; return (string)cmd.ExecuteScalar()!; } finally { c.Close(); } }));   // the running API really uses it
    }

    [Fact]
    public void The_application_login_can_do_its_job_and_nothing_else()
    {
        // allowed: normal data access
        Assert.True(Scalar<int>(AppConnection, "SELECT COUNT(*) FROM dbo.Blogs") >= 0);
        var tag = "priv-" + Guid.NewGuid().ToString("N")[..8];
        Exec(AppConnection, $"INSERT INTO dbo.Blogs (AuthorId, Title, Body, CreatedAt) SELECT TOP 1 Id, '{tag}', 'x', GETUTCDATE() FROM dbo.Users");
        Exec(AppConnection, $"DELETE FROM dbo.Blogs WHERE Title = '{tag}'");

        // denied: schema changes, server/other-database access, code execution
        foreach (var forbidden in new[]
        {
            "CREATE TABLE dbo.evil (id int)",
            "DROP TABLE dbo.BlogLikes",
            "ALTER TABLE dbo.Users ADD hacked int",
            "TRUNCATE TABLE dbo.Blogs",
            "CREATE LOGIN evil WITH PASSWORD = 'Sup3r-Secret-Passw0rd!'",
            "CREATE USER evil WITHOUT LOGIN",
            "SELECT TOP 1 * FROM msdb.dbo.sysjobs",                    // another database
            "SELECT TOP 1 * FROM sys.dm_exec_connections",             // server-wide state (VIEW SERVER PERFORMANCE STATE)
            "EXEC sp_configure 'show advanced options', 1",
            "EXEC xp_cmdshell 'whoami'",
            "EXEC sp_addlinkedserver 'evil', 'SQL Server'",
            "BACKUP DATABASE SecLab TO DISK = '/tmp/x.bak'",
            "ALTER ROLE db_owner ADD MEMBER seclab_app",                // no self-service privilege escalation
        })
        {
            var ex = Assert.ThrowsAny<SqlException>(() => Exec(AppConnection, forbidden));
            Assert.True(ex.Number is 229 or 262 or 15247 or 15151 or 15288 or 916 or 208 or 102 or 15007 or 4060 or 2760 or 3701 or 300 or 371 or 1088 or 15517 or 5011 or 5012 or 15406,
                $"'{forbidden}' failed, but with an unexpected error {ex.Number}: {ex.Message}");
        }
    }

    [Fact]
    public void Schema_changes_belong_to_a_separate_migration_identity_that_the_running_app_does_not_use()
    {
        var m = new SqlConnectionStringBuilder(MigratorConnection); var a = new SqlConnectionStringBuilder(AppConnection);
        Assert.NotEqual(a.UserID.ToLowerInvariant(), m.UserID.ToLowerInvariant());
        Assert.NotEqual("sa", m.UserID.ToLowerInvariant());
        Assert.Equal("seclab_migrator", Scalar<string>(MigratorConnection, "SELECT SUSER_NAME()"));
        Assert.Equal(1, Scalar<int>(MigratorConnection, "SELECT CASE WHEN IS_MEMBER('db_owner') = 1 OR IS_MEMBER('db_ddladmin') = 1 THEN 1 ELSE 0 END"));
        Assert.Equal(0, Scalar<int>(MigratorConnection, "SELECT IS_SRVROLEMEMBER('sysadmin')"));

        Exec(MigratorConnection, "CREATE TABLE dbo.migrator_probe (id int)");     // it can change the schema ...
        Exec(MigratorConnection, "DROP TABLE dbo.migrator_probe");
    }

    // ================= transport and secrets =================

    [Fact]
    public void The_database_connection_is_encrypted_and_the_server_certificate_is_verified()
    {
        foreach (var conn in new[] { AppConnection, MigratorConnection })
        {
            var b = new SqlConnectionStringBuilder(conn);
            Assert.True(b.Encrypt == SqlConnectionEncryptOption.Mandatory || b.Encrypt == SqlConnectionEncryptOption.Strict, "Encrypt must be True/Strict");
            Assert.False(b.TrustServerCertificate, "TrustServerCertificate=True switches certificate validation off");
            // Opening succeeds only if the TLS handshake did and the certificate was accepted by validation (not by TrustServerCertificate).
            // (sys.dm_exec_connections.encrypt_option would show it server-side, but reading it needs a server-level right the app must not have.)
            Assert.Equal(1, Scalar<int>(conn, "SELECT 1"));
        }
    }

    static string RepoFile(string relative) => File.ReadAllText(Repo.Path_(relative));

    [Fact]
    public void No_database_password_is_committed()
    {
        foreach (var f in Directory.GetFiles(Repo.Path_("backend/src/SecLab.Api"), "appsettings*.json"))
            Assert.DoesNotMatch(new Regex(@"(?i)(password|pwd)\s*=\s*[^;""\s$]{3,}"), File.ReadAllText(f));

        var compose = RepoFile("docker-compose.yml");
        Assert.DoesNotMatch(new Regex(@"MSSQL_SA_PASSWORD:\s*[""']?(?!\$\{)[^\s""'$]"), compose);        // must be ${...} from .env
        Assert.DoesNotContain("Passw0rd", compose); Assert.DoesNotContain("Passw0rd", RepoFile("docs/reset-database.sh"));

        var gitignore = RepoFile(".gitignore");
        Assert.Matches(new Regex(@"(?m)^\.env\s*$"), gitignore);
        Assert.True(File.Exists(Repo.Path_(".env.example")), ".env.example documents the variables without values");
        Assert.DoesNotMatch(new Regex(@"=\s*\S*(?:Passw0rd|password123)"), RepoFile(".env.example"));
    }

    [Fact]
    public void Risky_raw_sql_is_a_build_error_from_now_on()
    {
        var editorconfig = Repo.Path_(".editorconfig");
        Assert.True(File.Exists(editorconfig), ".editorconfig at the repository root is missing");
        var text = File.ReadAllText(editorconfig);
        Assert.Matches(new Regex(@"(?im)^dotnet_diagnostic\.EF1002\.severity\s*=\s*error\s*$"), text);   // interpolated strings in FromSqlRaw/ExecuteSqlRaw
        Assert.Matches(new Regex(@"(?im)^dotnet_diagnostic\.EF1003\.severity\s*=\s*error\s*$"), text);   // concatenated strings - the form the starter's search used
    }

    // ================= sensitive columns =================

    [Fact]
    public async Task Phone_and_address_are_encrypted_in_the_database_but_the_owner_still_sees_them()
    {
        var p = _h.NewPerson();
        var phone = "+47 " + Random.Shared.Next(100, 999) + " " + Random.Shared.Next(10, 99) + " " + Random.Shared.Next(100, 999);
        var address = "Hemmelig gate " + Guid.NewGuid().ToString("N")[..6];
        var res = await p.Http.PutAsJsonAsync($"/api/users/{p.Id}", new { phone, address });
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        // through the API the owner gets the plaintext back ...
        var me = await (await p.Http.GetAsync("/api/me")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(phone, me.GetProperty("phone").GetString());
        Assert.Equal(address, me.GetProperty("address").GetString());

        // ... but the stored bytes are not the plaintext, whoever reads the table
        foreach (var conn in new[] { AppConnection, MigratorConnection })
        {
            var rawPhone = Scalar<string>(conn, $"SELECT CONVERT(nvarchar(max), Phone) FROM dbo.Users WHERE Id = {p.Id}");
            var rawAddress = Scalar<string>(conn, $"SELECT CONVERT(nvarchar(max), Address) FROM dbo.Users WHERE Id = {p.Id}");
            Assert.DoesNotContain(phone.Replace(" ", ""), rawPhone.Replace(" ", ""));
            Assert.DoesNotContain(address, rawAddress);
            Assert.True(rawPhone.Length > phone.Length && rawAddress.Length > address.Length, "ciphertext carries a header, IV and MAC");
        }
        Assert.False(_h.DatabaseContains(address));
    }

    [Fact]
    public async Task Equal_plaintexts_produce_different_ciphertexts()
    {
        var a = _h.NewPerson(); var b = _h.NewPerson();
        const string phone = "+47 111 22 333";
        await a.Http.PutAsJsonAsync($"/api/users/{a.Id}", new { phone });
        await b.Http.PutAsJsonAsync($"/api/users/{b.Id}", new { phone });

        var ca = Scalar<string>(MigratorConnection, $"SELECT CONVERT(nvarchar(max), Phone) FROM dbo.Users WHERE Id = {a.Id}");
        var cb = Scalar<string>(MigratorConnection, $"SELECT CONVERT(nvarchar(max), Phone) FROM dbo.Users WHERE Id = {b.Id}");
        Assert.NotEqual(ca, cb);         // randomised: equality of ciphertexts would leak equality of values
    }
}
