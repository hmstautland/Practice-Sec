using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using SecLab.Api.Security;

namespace SecLab.Api.Tests;

// Shared scaffolding for step 16 (Testing). Shipped with the step; nothing in here is a solution.
// Read it - the mutants are a catalogue of "security controls that silently stop working".

/// <summary>Tag a negative test with the OWASP API Security Top 10 (2023) risk it checks: <c>[OwaspApi("API1")]</c>.
/// <c>Step16TestingTests</c> uses it to see which risks have at least one negative test.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class OwaspApiAttribute(string id) : Attribute
{
    public string Id { get; } = id;
}

/// <summary>
/// Fault injection for the TEST host. When the environment variable <c>SECLAB_MUTANT</c> names a mutant, every host that
/// <see cref="TestIdp"/> creates (i.e. every <see cref="Harness"/> client) is changed so that one security control silently
/// stops working - or one contract is silently broken. Your tests must notice. <c>docs/attack-scripts/16-mutants.sh</c> runs your
/// suite once per mutant and expects every run to FAIL. Without the variable nothing changes.
/// Only the test host is touched; the production code is never modified.
/// </summary>
public static class Mutants
{
    public const string EnvironmentVariable = "SECLAB_MUTANT";

    /// <summary>name -> what silently breaks</summary>
    public static readonly IReadOnlyDictionary<string, string> Catalogue = new Dictionary<string, string>
    {
        ["admin-open"] = "the Admin role / admin-network requirement is no longer checked (any signed-in user passes the Admin policy)",
        ["ownership-skip"] = "resource-based checks (owner, author, ...) always succeed",
        ["fallback-off"] = "the default-deny fallback policy is gone: an endpoint without explicit metadata is public",
        ["phantom-route"] = "a new endpoint appears (GET /api/phantom/{id}) that nobody classified",
        ["password-leak"] = "successful JSON responses gain a 'passwordHash' property",
        ["error-shape"] = "error responses are no longer problem details and carry a stack trace",
        ["strip-headers"] = "the defensive response headers (nosniff, CSP, no-store ...) are removed on the way out",
        ["no-rate-limit"] = "the global rate limiter is switched off",
    };

    public static string? Active => Environment.GetEnvironmentVariable(EnvironmentVariable) is { Length: > 0 } m ? m : null;

    /// <summary>Called by TestIdp for every test host.</summary>
    public static void Apply(IServiceCollection services)
    {
        switch (Active)
        {
            case null: return;
            case "admin-open":
                Decorate<IAuthorizationService>(services, (inner, _) => new Authz(inner, (user, reqs) =>
                {
                    var rest = reqs.Where(r => r is not RolesAuthorizationRequirement and not AdminNetworkRequirement).ToList();
                    return rest.Count == reqs.Count ? null : rest.Count == 0 ? user.Identity?.IsAuthenticated == true ? Ok : No : rest;
                }));
                break;
            case "ownership-skip":
                Decorate<IAuthorizationService>(services, (inner, _) => new Authz(inner, (_, reqs) => reqs.Any(r => r is OperationAuthorizationRequirement) ? Ok : null));
                break;
            case "fallback-off":
                Decorate<IAuthorizationPolicyProvider>(services, (inner, _) => new NoFallback(inner));
                break;
            case "phantom-route":
                Decorate<EndpointDataSource>(services, (inner, _) => new CompositeEndpointDataSource([inner, new Phantom()]));
                break;
            case "password-leak":
                Pipeline(services, app => app.Use(Rewrite((ctx, body) =>
                {
                    if (ctx.Response.StatusCode != 200 || ctx.Response.ContentType?.StartsWith("application/json") != true) return null;
                    var node = JsonNode.Parse(body);
                    switch (node)
                    {
                        case JsonObject o: o["passwordHash"] = "AQAAAAIAAYagAAAAEPlaceholder"; break;
                        case JsonArray a: foreach (var o in a.OfType<JsonObject>()) o["passwordHash"] = "AQAAAAIAAYagAAAAEPlaceholder"; break;
                        default: return null;
                    }
                    return Encoding.UTF8.GetBytes(node!.ToJsonString());
                })));
                break;
            case "error-shape":
                Pipeline(services, app => app.Use(Rewrite((ctx, body) =>
                {
                    if (ctx.Response.StatusCode < 400 || ctx.Response.ContentType?.Contains("problem+json") != true) return null;
                    ctx.Response.ContentType = "application/json";
                    return Encoding.UTF8.GetBytes("{\"error\":\"failed\",\"stackTrace\":\"System.InvalidOperationException: at SecLab.Api.Endpoints.Api.Map\"}");
                })));
                break;
            case "strip-headers":
                Pipeline(services, app => app.Use((ctx, next) =>
                {
                    ctx.Response.OnStarting(() =>   // callbacks run last-registered-first: this outermost one runs last and sees the final headers
                    {
                        foreach (var h in new[] { "X-Content-Type-Options", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "Cache-Control" }) ctx.Response.Headers.Remove(h);
                        return Task.CompletedTask;
                    });
                    return next();
                }));
                break;
            case "no-rate-limit":
                services.PostConfigure<RateLimiterOptions>(o => o.GlobalLimiter = null);
                break;
            default:
                throw new InvalidOperationException($"unknown mutant '{Active}'. Known: {string.Join(", ", Catalogue.Keys)}");
        }
    }

    // ---------- plumbing ----------
    static readonly AuthorizationResult Ok = AuthorizationResult.Success();
    static readonly AuthorizationResult No = AuthorizationResult.Failed();

    static void Decorate<T>(IServiceCollection services, Func<T, IServiceProvider, T> wrap) where T : class
    {
        var original = services.Last(d => d.ServiceType == typeof(T));
        services.Remove(original);
        services.Add(ServiceDescriptor.Describe(typeof(T), sp =>
        {
            var inner = original.ImplementationFactory is { } f ? (T)f(sp)
                : original.ImplementationInstance is { } i ? (T)i
                : (T)ActivatorUtilities.CreateInstance(sp, original.ImplementationType!);
            return wrap(inner, sp);
        }, original.Lifetime));
    }

    sealed class Filter(Action<IApplicationBuilder> add) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app => { add(app); next(app); };
    }
    static void Pipeline(IServiceCollection s, Action<IApplicationBuilder> add) => s.AddTransient<IStartupFilter>(_ => new Filter(add));

    /// <summary>Buffers the response of /api/** and lets <paramref name="change"/> replace the body (null = leave as is).</summary>
    static Func<HttpContext, RequestDelegate, Task> Rewrite(Func<HttpContext, byte[], byte[]?> change) => async (ctx, next) =>
    {
        if (!ctx.Request.Path.StartsWithSegments("/api")) { await next(ctx); return; }
        var real = ctx.Response.Body;
        using var buffer = new MemoryStream();
        ctx.Response.Body = buffer;
        try { await next(ctx); } finally { ctx.Response.Body = real; }
        var bytes = buffer.ToArray();
        if (bytes.Length > 0) bytes = change(ctx, bytes) ?? bytes;
        if (!ctx.Response.HasStarted) ctx.Response.ContentLength = bytes.Length;
        await real.WriteAsync(bytes);
    };

    sealed class Authz(IAuthorizationService inner, Func<ClaimsPrincipal, IReadOnlyList<IAuthorizationRequirement>, object?> intercept) : IAuthorizationService
    {
        public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements)
        {
            var list = requirements.ToList();
            return intercept(user, list) switch
            {
                AuthorizationResult r => Task.FromResult(r),
                IReadOnlyList<IAuthorizationRequirement> changed => inner.AuthorizeAsync(user, resource, changed),
                _ => inner.AuthorizeAsync(user, resource, list),
            };
        }
        public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName) => inner.AuthorizeAsync(user, resource, policyName);
    }

    sealed class NoFallback(IAuthorizationPolicyProvider inner) : IAuthorizationPolicyProvider
    {
        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => inner.GetDefaultPolicyAsync();
        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => Task.FromResult<AuthorizationPolicy?>(null);
        public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName) => inner.GetPolicyAsync(policyName);
    }

    sealed class Phantom : EndpointDataSource
    {
        readonly List<Endpoint> _endpoints =
        [
            new RouteEndpointBuilder(_ => Task.CompletedTask, RoutePatternFactory.Parse("/api/phantom/{id:int}"), 0)
            { Metadata = { new HttpMethodMetadata(["GET"]) } }.Build(),
        ];
        public override IReadOnlyList<Endpoint> Endpoints => _endpoints;
        public override IChangeToken GetChangeToken() => new CancellationChangeToken(CancellationToken.None);
    }
}
