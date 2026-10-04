using System.Data.Common;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecLab.Api.Data;
using SecLab.Api.Models;
using Xunit;

namespace SecLab.Api.Tests;

/// <summary>Shared test scaffolding (used from step 06 on): users with tokens, direct DB access, "does the DB contain this text?".</summary>
public sealed class Harness : IDisposable
{
    readonly WebApplicationFactory<Program> factory;
    readonly TestIdp _idp = new();

    public Harness(WebApplicationFactory<Program> factory, Action<IServiceCollection>? extraServices = null)
    {
        this.factory = factory;
        _idp.ExtraServices = extraServices;
    }
    public void Dispose() => _idp.Dispose();

    public sealed record Person(int Id, string Username, HttpClient Http);

    /// <summary>A brand-new local user plus an HttpClient that carries a valid bearer token for it.</summary>
    public Person NewPerson(string role = "User")
    {
        var name = "u" + Guid.NewGuid().ToString("N")[..10];
        int id;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var u = new User
            {
                Username = name, DisplayName = "Name " + name, Email = $"{name}@example.com", Phone = "+47 111 11 111",
                Address = "Secret Street 1", Bio = "bio", Role = role, Password = "x",
            };
            db.Users.Add(u); db.SaveChanges(); id = u.Id;
        }
        var http = _idp.CreateClient(factory);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _idp.Token(name));
        return new Person(id, name, http);
    }

    /// <summary>A client with no credentials at all (callers add headers per request).</summary>
    public HttpClient Anonymous() => _idp.CreateClient(factory);

    public string BearerFor(string username) => _idp.Token(username);

    /// <summary>The services of the host the clients of this harness talk to (step 16: inspect what the running app really contains, e.g. its endpoints).
    /// Not <c>factory.Services</c>: that is a different, unmodified host.</summary>
    public IServiceProvider Services => _idp.Host(factory).Services;

    public T InDb<T>(Func<AppDbContext, T> f)
    {
        using var scope = factory.Services.CreateScope();
        return f(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    /// <summary>True if any text-like column in any table contains <paramref name="text"/> (as string, UTF-8 or UTF-16 bytes).</summary>
    public bool DatabaseContains(string text)
    {
        using var scope = factory.Services.CreateScope();
        var conn = scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.GetDbConnection();
        conn.Open();
        try
        {
            var columns = new List<(string Schema, string Table, string Column, string Type)>();
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS c " +
                                  "JOIN INFORMATION_SCHEMA.TABLES t ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_TYPE = 'BASE TABLE' " +
                                  "WHERE c.DATA_TYPE IN ('nvarchar','varchar','nchar','char','ntext','text','varbinary','binary')";
                using var r = cmd.ExecuteReader();
                while (r.Read()) columns.Add((r.GetString(0), r.GetString(1), r.GetString(2), r.GetString(3)));
            }
            foreach (var (schema, table, column, type) in columns)
            {
                using var cmd = conn.CreateCommand();
                var target = $"[{schema}].[{table}]"; var col = $"[{column}]";
                if (type.Contains("binary"))
                {
                    cmd.CommandText = $"SELECT COUNT(*) FROM {target} WHERE CHARINDEX(@utf8, {col}) > 0 OR CHARINDEX(@utf16, {col}) > 0";
                    AddParam(cmd, "@utf8", Encoding.UTF8.GetBytes(text)); AddParam(cmd, "@utf16", Encoding.Unicode.GetBytes(text));
                }
                else
                {
                    cmd.CommandText = $"SELECT COUNT(*) FROM {target} WHERE CONVERT(nvarchar(max), {col}) LIKE @p";
                    AddParam(cmd, "@p", "%" + text + "%");
                }
                if (Convert.ToInt32(cmd.ExecuteScalar()) > 0) return true;
            }
            return false;
        }
        finally { conn.Close(); }
    }

    static void AddParam(DbCommand cmd, string name, object value)
    {
        var p = cmd.CreateParameter(); p.ParameterName = name; p.Value = value; cmd.Parameters.Add(p);
    }
}
