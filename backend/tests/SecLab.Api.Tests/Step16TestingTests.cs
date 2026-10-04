using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecLab.Api.Tests;

// Step 16 - Testing (unit, integration, contract). Contract: docs/16-testing.md.
//
// These are META tests: they do not test the API, they test YOUR tests. You write the real tests in
// backend/tests/SecLab.Api.Tests/Learner/ (namespace SecLab.Api.Tests.Learner); these checks fail until that suite exists, is
// complete enough, follows the conventions and is wired for mutation testing. Whether your tests are any GOOD is decided by two
// other things: the mutants (docs/attack-scripts/16-mutants.sh) and Stryker.NET (docs/attack-scripts/16-mutation.sh).
[Trait("Step", "16")]
[Trait("Kind", "Meta")]
public class Step16TestingTests
{
    const string LearnerNamespace = "SecLab.Api.Tests.Learner";
    static readonly string[] Kinds = ["Matrix", "Negative", "Unit", "Contract", "Integration"];

    // ---------------- discovery of the learner's tests ----------------
    sealed record TestMethod(Type Class, MethodInfo Method, string? Step, string? Kind, bool Skipped, string[] Owasp);

    static string? Trait(IEnumerable<CustomAttributeData> data, string name) =>
        data.Where(d => d.AttributeType.Name == nameof(TraitAttribute) && d.ConstructorArguments is [{ Value: string n }, { Value: string v }] && n == name)
            .Select(d => (string)d.ConstructorArguments[1].Value!).FirstOrDefault();

    static readonly List<TestMethod> Learner = typeof(Step16TestingTests).Assembly.GetTypes()
        .Where(t => t.Namespace == LearnerNamespace && t.IsClass)
        .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes<FactAttribute>().Any())
            .Select(m =>
            {
                var data = m.GetCustomAttributesData().Concat(t.GetCustomAttributesData()).ToList();
                var fact = m.GetCustomAttributes<FactAttribute>().First();
                return new TestMethod(t, m, Trait(data, "Step"), Trait(data, "Kind"), !string.IsNullOrEmpty(fact.Skip), m.GetCustomAttributes<OwaspApiAttribute>().Select(a => a.Id).ToArray());
            }))
        .ToList();

    static IEnumerable<string> LearnerSources()
    {
        var dir = Repo.Path_("backend/tests/SecLab.Api.Tests/Learner");
        return Directory.Exists(dir) ? Directory.GetFiles(dir, "*.cs", SearchOption.AllDirectories) : [];
    }

    static string Describe(IEnumerable<TestMethod> t) => string.Join(", ", t.Select(x => $"{x.Class.Name}.{x.Method.Name}"));

    // ---------------- 1. the suite exists, is complete enough and runs in the gate ----------------
    static readonly Dictionary<string, int> Minimum = new() { ["Matrix"] = 3, ["Negative"] = 8, ["Unit"] = 10, ["Contract"] = 4, ["Integration"] = 4 };

    [Fact]
    public void Your_suite_covers_every_kind_of_test_and_every_test_is_part_of_the_Step_16_gate()
    {
        Assert.True(Learner.Count > 0, $"no tests found in namespace {LearnerNamespace} (put your files in backend/tests/SecLab.Api.Tests/Learner/)");
        var untagged = Learner.Where(t => t.Step != "16").ToList();
        Assert.True(untagged.Count == 0, $"missing [Trait(\"Step\", \"16\")]: {Describe(untagged)}");
        var badKind = Learner.Where(t => !Kinds.Contains(t.Kind ?? "")).ToList();
        Assert.True(badKind.Count == 0, $"missing or unknown [Trait(\"Kind\", ...)] (one of {string.Join(", ", Kinds)}): {Describe(badKind)}");
        var skipped = Learner.Where(t => t.Skipped).ToList();
        Assert.True(skipped.Count == 0, $"a skipped test protects nothing: {Describe(skipped)}");

        foreach (var (kind, min) in Minimum)
            Assert.True(Learner.Count(t => t.Kind == kind) >= min, $"Kind={kind}: at least {min} test methods (theories count once), found {Learner.Count(t => t.Kind == kind)}");
        Assert.True(Learner.Any(t => t.Kind == "Matrix" && t.Method.GetCustomAttributes<TheoryAttribute>().Any()), "the matrix needs a [Theory]: one case per route x caller");
    }

    // ---------------- 2. unit tests are really unit tests ----------------
    [Fact]
    public void Unit_tests_need_neither_the_web_host_nor_the_database()
    {
        foreach (var c in Learner.Where(t => t.Kind == "Unit").Select(t => t.Class).Distinct())
        {
            var needs = c.GetConstructors().SelectMany(k => k.GetParameters()).Select(p => p.ParameterType)
                .Concat(c.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).Select(f => f.FieldType))
                .Where(t => t == typeof(Harness) || t == typeof(EnvScope) || (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(WebApplicationFactory<>)));
            Assert.True(!needs.Any(), $"{c.Name} is tagged Kind=Unit but depends on {string.Join(", ", needs.Select(n => n.Name))}: unit tests must run without SQL Server (CI runs them first, in seconds)");
        }
        foreach (var f in LearnerSources().Where(f => Path.GetFileName(f).Contains("Unit", StringComparison.OrdinalIgnoreCase)))
            Assert.DoesNotMatch(new Regex(@"\b(Harness|WebApplicationFactory|AppDbContext|HttpClient)\b"), File.ReadAllText(f));
    }

    // ---------------- 3. every OWASP API risk that applies has a negative test ----------------
    static readonly string[] RisksInScope = ["API1", "API2", "API3", "API4", "API5", "API7", "API8", "API9"];   // API6 and API10 are optional here

    [Fact]
    public void Every_OWASP_API_risk_in_scope_has_at_least_one_negative_test()
    {
        var negative = Learner.Where(t => t.Kind == "Negative").ToList();
        var covered = negative.SelectMany(t => t.Owasp).ToHashSet();
        var missing = RisksInScope.Where(r => !covered.Contains(r)).ToList();
        Assert.True(missing.Count == 0, $"no [OwaspApi(\"..\")] negative test for: {string.Join(", ", missing)}");
        var unknown = covered.Where(c => !Regex.IsMatch(c, "^API([1-9]|10)$")).ToList();
        Assert.True(unknown.Count == 0, $"not an OWASP API Security Top 10 (2023) id: {string.Join(", ", unknown)}");
        var untagged = negative.Where(t => t.Owasp.Length == 0).ToList();
        Assert.True(untagged.Count == 0, $"every negative test says which risk it checks: {Describe(untagged)}");
    }

    // ---------------- 4. the matrix is discovered, not typed in ----------------
    [Fact]
    public void The_authorization_matrix_is_discovered_from_the_running_application()
    {
        var matrixFiles = LearnerSources().Where(f => Regex.IsMatch(File.ReadAllText(f), @"Trait\(""Kind"",\s*""Matrix""\)")).ToList();
        Assert.True(matrixFiles.Count > 0, "no file with [Trait(\"Kind\", \"Matrix\")]");
        var text = string.Join("\n", matrixFiles.Select(File.ReadAllText));
        Assert.True(text.Contains("EndpointDataSource"), "enumerate the endpoints from EndpointDataSource: a route added tomorrow must appear in the test without anyone remembering to add it");
        Assert.True(text.Contains("IAllowAnonymous") && text.Contains("IAuthorizeData"), "compare the declared access with the endpoint metadata (IAllowAnonymous / IAuthorizeData), not only with behaviour");
        Assert.True(text.Contains("GetFallbackPolicyAsync"), "the default-deny fallback policy is part of the matrix: assert that it exists");
    }

    // ---------------- 5. contract snapshots ----------------
    static readonly Regex NeverInAResponse = new(@"(?i)(pass(word|wd)?|hash|salt|lockout|failedlogin|publickey|credentialid|userhandle|signcount|secret)");

    [Fact]
    public void Contract_snapshots_are_committed_and_none_of_them_contains_a_secret_looking_property()
    {
        var dir = Repo.Path_("backend/tests/SecLab.Api.Tests/Learner/Snapshots");
        Assert.True(Directory.Exists(dir), "Learner/Snapshots/ is missing: record the response shapes (see docs/16-testing.md)");
        var files = Directory.GetFiles(dir, "*.json");
        Assert.True(files.Length >= 8, $"at least 8 snapshots (me, the three profile views, blogs v1/v2, admin users, keys ...), found {files.Length}");
        foreach (var f in files)
        {
            var shape = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(f));
            Assert.True(shape is { Count: > 0 }, $"{Path.GetFileName(f)}: empty or not a flat path -> type object");
            var leaks = shape!.Keys.Where(k => NeverInAResponse.IsMatch(k[(k.LastIndexOfAny(['.', ']']) + 1)..])).ToList();
            Assert.True(leaks.Count == 0, $"{Path.GetFileName(f)} records a property that must never be serialised: {string.Join(", ", leaks)}");
        }
    }

    // ---------------- 6. integration tests are real ----------------
    [Fact]
    public void Integration_tests_use_the_real_database_and_include_a_concurrency_test()
    {
        foreach (var f in LearnerSources())
            Assert.DoesNotMatch(new Regex(@"UseInMemoryDatabase|UseSqlite|Microsoft\.EntityFrameworkCore\.(InMemory|Sqlite)"), File.ReadAllText(f));   // no engine that is not the production engine
        var concurrent = Learner.Where(t => t.Kind == "Integration" && t.Method.Name.Contains("oncurren", StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.True(concurrent.Count >= 2, "write at least two integration tests whose name contains 'Concurrent': fire identical requests at the same moment and ask the database what happened");
        foreach (var t in concurrent)
        {
            var source = File.ReadAllText(LearnerSources().First(f => File.ReadAllText(f).Contains(t.Method.Name)));
            Assert.Contains("Task.WhenAll", source);
        }
    }

    // ---------------- 7. hygiene ----------------
    [Fact]
    public void Tests_contain_no_secrets_no_sleeps_and_do_not_switch_certificate_validation_off()
    {
        foreach (var f in LearnerSources())
        {
            var text = File.ReadAllText(f);
            var name = Path.GetFileName(f);
            Assert.False(Regex.IsMatch(text, @"Passw0rd|User Id\s*=\s*sa\b|Password\s*=\s*[^;""\s]{6,};"), $"{name}: a password or the sa login in test code");
            Assert.False(Regex.IsMatch(text, @"Thread\.Sleep|Task\.Delay"), $"{name}: sleeping makes tests slow and flaky - wait for a condition, or use a fake clock");
            Assert.DoesNotContain("TrustServerCertificate=True", text, StringComparison.OrdinalIgnoreCase);
            Assert.False(Regex.IsMatch(text, @"ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator"), $"{name}: certificate validation disabled in a test");
        }
    }

    // ---------------- 8. mutation testing is wired ----------------
    static readonly string[] SecurityCritical = ["OutboundUrlPolicy", "AdminNetwork", "ContentSanitizer", "ColumnEncryption"];

    [Fact]
    public void Stryker_is_configured_with_a_threshold_for_the_security_critical_classes()
    {
        var path = Repo.Path_("backend/tests/SecLab.Api.Tests/stryker-config.json");
        Assert.True(File.Exists(path), "backend/tests/SecLab.Api.Tests/stryker-config.json is missing");
        var root = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }).RootElement.GetProperty("stryker-config");

        Assert.Contains("SecLab.Api", root.GetProperty("project").GetString());
        Assert.Contains("Kind=Unit", root.GetProperty("test-case-filter").GetString());       // mutation testing runs the fast unit tests only
        var mutate = root.GetProperty("mutate").EnumerateArray().Select(e => e.GetString()!).ToList();
        foreach (var cls in SecurityCritical) Assert.True(mutate.Any(m => m.Contains(cls) && !m.StartsWith('!')), $"mutate must include {cls}");
        foreach (var m in mutate.Where(m => !m.StartsWith('!')))      // every target must exist (a typo silently mutates nothing)
        {
            var file = Regex.Replace(m, @"\{.*\}$", "");
            var found = Directory.GetFiles(Repo.Path_("backend/src/SecLab.Api"), Path.GetFileName(file), SearchOption.AllDirectories);
            Assert.True(found.Length > 0, $"mutate target does not exist: {m}");
        }
        var t = root.GetProperty("thresholds");
        int High = t.GetProperty("high").GetInt32(), Low = t.GetProperty("low").GetInt32(), Break = t.GetProperty("break").GetInt32();
        Assert.True(Break >= 75, $"break threshold {Break}: below 75 the gate is decoration");
        Assert.True(Break <= Low && Low <= High && High <= 100, "thresholds must satisfy break <= low <= high <= 100");
        Assert.Contains("json", root.GetProperty("reporters").EnumerateArray().Select(e => e.GetString()));

        var tools = File.ReadAllText(Repo.Path_("dotnet-tools.json"));
        Assert.Contains("dotnet-stryker", tools);                                              // pinned in the tool manifest like dotnet-ef
        Assert.Contains("StrykerOutput", File.ReadAllText(Repo.Path_(".gitignore")));          // reports are build output
    }

    // ---------------- 9. the test code itself is part of the supply chain ----------------
    [Fact]
    public void Every_project_has_a_lock_file_that_matches_its_package_references()
    {
        var projects = Directory.GetFiles(Repo.Path_("backend"), "*.csproj", SearchOption.AllDirectories).Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")).ToList();
        Assert.True(projects.Count >= 4);
        foreach (var proj in projects)
        {
            var lockFile = Path.Combine(Path.GetDirectoryName(proj)!, "packages.lock.json");
            Assert.True(File.Exists(lockFile), $"{Path.GetFileName(proj)}: no packages.lock.json (dotnet restore, then commit it)");
            var locked = JsonDocument.Parse(File.ReadAllText(lockFile)).RootElement.GetProperty("dependencies").EnumerateObject()
                .SelectMany(fw => fw.Value.EnumerateObject()).Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var pkg in XDocument.Load(proj).Descendants("PackageReference").Select(e => (string?)e.Attribute("Include")).Where(n => n is not null))
                Assert.True(locked.Contains(pkg!), $"{Path.GetFileName(proj)}: {pkg} is not in packages.lock.json - restore again and commit the lock file (CI restores in locked mode and would fail)");
        }
        Assert.True(File.Exists(Repo.Path_("frontend/package-lock.json")));
    }
}
