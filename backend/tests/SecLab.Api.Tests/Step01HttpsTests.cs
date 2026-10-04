using Microsoft.AspNetCore.Hosting;
using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecLab.Api.Tests;

// Step 01 – HTTPS. These fail on the starter (red) and must pass once you have fixed it (green).
// Requires the SQL Server container: docker compose up -d sqlserver
[Trait("Step", "01")]
public class Step01HttpsTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    [Fact]
    public async Task Plain_http_requests_are_redirected_to_https()
    {
        var client = factory
            .WithWebHostBuilder(b => b.UseSetting("https_port", "5443"))
            .CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = new Uri("http://localhost"),
            });

        var res = await client.GetAsync("/api/blogs");

        Assert.True(res.StatusCode is HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect,
            $"expected 307/308 but got {(int)res.StatusCode}");
        Assert.Equal("https", res.Headers.Location?.Scheme);
    }

    [Fact]
    public async Task Https_responses_carry_a_strict_transport_security_header_outside_development()
    {
        var client = factory
            .WithWebHostBuilder(b => b.UseEnvironment("Production"))
            .CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = new Uri("https://seclab.example"),
            });

        var res = await client.GetAsync("/api/blogs");

        Assert.True(res.Headers.TryGetValues("Strict-Transport-Security", out var values), "no HSTS header");
        var hsts = string.Join(";", values!);
        var maxAge = hsts.Split(';').Select(p => p.Trim()).First(p => p.StartsWith("max-age=")).Split('=')[1];
        Assert.True(long.Parse(maxAge) >= 15_552_000, $"max-age too short: {hsts}");
    }
}
