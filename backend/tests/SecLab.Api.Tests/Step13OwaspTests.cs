using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecLab.Api.Tests;

// Step 13 – OWASP review: headers, endpoint inventory, supply-chain settings, disclosure policy and the filled-in mapping matrix.
// Contract: docs/13-owasp-review.md.
[Trait("Step", "13")]
public class Step13OwaspTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    readonly Harness _h = new(factory);
    public void Dispose() => _h.Dispose();

    // ================= response headers =================

    static string Header(HttpResponseMessage r, string name) =>
        r.Headers.TryGetValues(name, out var v) ? string.Join(",", v)
        : r.Content.Headers.TryGetValues(name, out var c) ? string.Join(",", c) : "";

    async Task<List<(string What, HttpResponseMessage Res)>> SampleResponses()
    {
        var p = _h.NewPerson(); var admin = _h.NewPerson("Admin");
        return
        [
            ("200 authenticated JSON", await p.Http.GetAsync("/api/me")),
            ("401 anonymous", await _h.Anonymous().GetAsync("/api/me")),
            ("403 forbidden", await p.Http.GetAsync("/api/admin/users")),
            ("404 unknown route", await p.Http.GetAsync("/api/nope")),
            ("400 validation", await p.Http.PostAsJsonAsync("/api/blogs", new { title = "", body = "" })),
            ("500 crash", await admin.Http.GetAsync("/api/debug/crash")),
            ("health", await _h.Anonymous().GetAsync("/health/live")),
        ];
    }

    [Fact]
    public async Task Every_response_carries_the_hardening_headers()
    {
        foreach (var (what, res) in await SampleResponses())
        {
            Assert.Equal("nosniff", Header(res, "X-Content-Type-Options"));
            Assert.Contains("frame-ancestors 'none'", Header(res, "Content-Security-Policy"));
            Assert.Contains("default-src 'none'", Header(res, "Content-Security-Policy"));
            Assert.Equal("DENY", Header(res, "X-Frame-Options"), ignoreCase: true);
            Assert.Equal("no-referrer", Header(res, "Referrer-Policy"));
            var permissions = Header(res, "Permissions-Policy");
            foreach (var feature in new[] { "camera=()", "microphone=()", "geolocation=()" }) Assert.Contains(feature, permissions);
            Assert.Equal("same-site", Header(res, "Cross-Origin-Resource-Policy"));
            Assert.True(!string.IsNullOrEmpty(Header(res, "X-Content-Type-Options")), what);
        }
    }

    [Fact]
    public async Task Api_data_is_never_cached_and_no_cookie_or_stack_disclosure_ever_appears()
    {
        foreach (var (what, res) in await SampleResponses())
        {
            if (what != "health") Assert.Contains("no-store", res.Headers.CacheControl?.ToString() ?? "");
            Assert.False(res.Headers.Contains("Set-Cookie"), $"{what}: session cookies would reopen CSRF - this API uses bearer tokens only");
            foreach (var leaky in new[] { "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version" })
                Assert.False(res.Headers.Contains(leaky), $"{what}: {leaky} header");
        }
    }

    // ================= inventory =================

    static readonly string[] AnonymousByDesign = ["/api/auth/login", "/api/auth/register", "/health/live", "/health/ready"];

    [Fact]
    public void Exactly_the_intended_endpoints_are_anonymous_nothing_is_forgotten_and_nothing_is_a_shadow_api()
    {
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();
        string Route(RouteEndpoint e) => "/" + (e.RoutePattern.RawText ?? "").TrimStart('/');

        var anonymous = endpoints.Where(e => e.Metadata.GetMetadata<IAllowAnonymous>() is not null).Select(Route).Distinct().Order().ToList();
        Assert.Equal(AnonymousByDesign.Order().ToList(), anonymous);

        var api = endpoints.Where(e => Route(e).StartsWith("/api/")).ToList();
        Assert.NotEmpty(api);
        Assert.All(api, e => Assert.True(e.Metadata.Any(m => m.GetType().Name == "ApiVersionMetadata"), $"{Route(e)} is outside the API version set (inventory!)"));

        // nothing unexpected is exposed outside /api and /health (no swagger, actuator-style or debug UIs by accident)
        var others = endpoints.Select(Route).Where(r => !r.StartsWith("/api/") && !r.StartsWith("/health/")).Distinct().ToList();
        Assert.Empty(others);
    }

    // ================= supply chain settings =================

    static XElement Props()
    {
        var path = Repo.Path_("backend/Directory.Build.props");
        Assert.True(File.Exists(path), "backend/Directory.Build.props is missing");
        return XDocument.Load(path).Root!;
    }

    static string Prop(XElement root, string name) =>
        root.Descendants(name).Select(e => e.Value.Trim()).FirstOrDefault() ?? "";

    [Fact]
    public void The_build_audits_dependencies_and_fails_on_known_vulnerabilities()
    {
        var p = Props();
        Assert.Equal("true", Prop(p, "NuGetAudit"), ignoreCase: true);
        Assert.Equal("all", Prop(p, "NuGetAuditMode"), ignoreCase: true);          // direct AND transitive
        Assert.Contains(Prop(p, "NuGetAuditLevel").ToLowerInvariant(), new[] { "low", "moderate" });
        var asErrors = Prop(p, "WarningsAsErrors") + ";" + Prop(p, "TreatWarningsAsErrors");
        foreach (var code in new[] { "NU1901", "NU1902", "NU1903", "NU1904" }) Assert.Contains(code, asErrors);
    }

    [Fact]
    public void Restores_are_reproducible_lock_files_are_used_and_enforced_in_ci()
    {
        var p = Props();
        Assert.Equal("true", Prop(p, "RestorePackagesWithLockFile"), ignoreCase: true);
        Assert.True(p.Descendants("RestoreLockedMode").Any(), "RestoreLockedMode should be set (at least when building in CI)");
        Assert.True(File.Exists(Repo.Path_("backend/src/SecLab.Api/packages.lock.json")), "run a restore so packages.lock.json is generated and committed");
        Assert.True(File.Exists(Repo.Path_("frontend/package-lock.json")));
    }

    [Fact]
    public void There_is_a_vulnerability_disclosure_policy()
    {
        var path = Repo.Path_("SECURITY.md");
        Assert.True(File.Exists(path), "SECURITY.md is missing");
        var text = File.ReadAllText(path);
        Assert.Matches(new Regex(@"(?im)^#+\s*.*(report|disclos)"), text);
        Assert.Matches(new Regex(@"[\w.+-]+@[\w-]+\.[\w.-]+|https?://"), text);                 // a way to reach someone
        Assert.Matches(new Regex(@"(?i)\b(\d+\s*(business\s*)?(day|hour)s?|within)\b"), text);   // a response expectation
        Assert.Contains("supported", text, StringComparison.OrdinalIgnoreCase);
    }

    // ================= the mapping matrix =================

    static readonly string[] Ids = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10",
        "API1", "API2", "API3", "API4", "API5", "API6", "API7", "API8", "API9", "API10"];
    static readonly string[] Statuses = ["Mitigated", "Partial", "Accepted risk", "Not applicable"];

    static Dictionary<string, string[]> MatrixRows()
    {
        var path = Repo.Path_("docs/owasp-matrix.md");
        Assert.True(File.Exists(path), "docs/owasp-matrix.md is missing");
        var rows = new Dictionary<string, string[]>();
        foreach (var line in File.ReadAllLines(path))
        {
            if (!line.TrimStart().StartsWith('|')) continue;
            var cells = line.Trim().Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (cells.Length == 6 && Ids.Contains(cells[0])) rows[cells[0]] = cells;
        }
        return rows;
    }

    [Fact]
    public void The_owasp_matrix_covers_all_twenty_categories_with_a_real_status()
    {
        var rows = MatrixRows();
        Assert.Equal(Ids.Order(), rows.Keys.Order());
        foreach (var (id, c) in rows)
        {
            Assert.Contains(c[5], Statuses);
            Assert.True(c[2].Length >= 20 && c[2] != "?", $"{id}: describe where the risk exists in SecLab");
            Assert.DoesNotContain("TODO", string.Join(" ", c), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("?", string.Join(" ", c.Skip(1)));
        }
    }

    [Fact]
    public void Claims_in_the_matrix_are_backed_by_evidence_and_exceptions_have_owners()
    {
        var stepsWithTests = Directory.GetFiles(Repo.Path_("backend/tests/SecLab.Api.Tests"), "Step*.cs")
            .SelectMany(f => Regex.Matches(File.ReadAllText(f), @"Trait\(""Step"",\s*""(\d+)""\)").Select(m => m.Groups[1].Value)).ToHashSet();

        foreach (var (id, c) in MatrixRows())
        {
            var (mitigation, evidence, status) = (c[3], c[4], c[5]);
            if (status is "Mitigated" or "Partial")
            {
                var refs = Regex.Matches(evidence, @"Step=(\d+)").Select(m => m.Groups[1].Value)
                    .Concat(Regex.Matches(evidence, @"`?((?:docs|backend|frontend|solutions)/[\w./-]+)`?").Select(m => m.Groups[1].Value)).ToList();
                Assert.True(refs.Count > 0, $"{id}: evidence must name a Step=NN test filter or an existing file");
                foreach (var r in refs)
                {
                    if (Regex.IsMatch(r, @"^\d+$")) Assert.Contains(r.PadLeft(2, '0'), stepsWithTests.Select(s => s.PadLeft(2, '0')));
                    else Assert.True(File.Exists(Repo.Path_(r)) || Directory.Exists(Repo.Path_(r)), $"{id}: evidence path '{r}' does not exist");
                }
            }
            else
            {
                Assert.True(mitigation.Length >= 20, $"{id}: justify '{status}' (at least 20 characters)");
                if (status == "Accepted risk") Assert.Contains("owner:", mitigation, StringComparison.OrdinalIgnoreCase);
            }
        }
    }
}
