using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Yarp.ReverseProxy.Forwarder;

namespace SecLab.Gateway.Tests;

/// <summary>Stands in for the API behind the gateway and records every request that actually reaches it.</summary>
public sealed class FakeApi(Func<HttpRequestMessage, HttpResponseMessage>? respond = null) : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        // Copy what matters (the original message is disposed after the call).
        var copy = new HttpRequestMessage(request.Method, request.RequestUri);
        foreach (var h in request.Headers) copy.Headers.TryAddWithoutValidation(h.Key, h.Value);
        if (request.Content is not null) { copy.Content = new ByteArrayContent(await request.Content.ReadAsByteArrayAsync(ct)); }
        lock (Requests) Requests.Add(copy);
        return respond?.Invoke(request) ?? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"from\":\"api\"}", System.Text.Encoding.UTF8, "application/json") };
    }
}

sealed class FakeForwarderClients(HttpMessageHandler handler) : IForwarderHttpClientFactory
{
    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => new(handler, disposeHandler: false);
}

/// <summary>TestServer has no sockets: give each request a client address (127.0.0.1 unless X-Test-Remote-Ip says otherwise).</summary>
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

public sealed class EnvScope : IDisposable
{
    readonly Dictionary<string, string?> _previous = new();
    public EnvScope(params (string Name, string Value)[] settings)
    {
        foreach (var (n, v) in settings) { _previous[n] = Environment.GetEnvironmentVariable(n); Environment.SetEnvironmentVariable(n, v); }
    }
    public void Dispose() { foreach (var (n, v) in _previous) Environment.SetEnvironmentVariable(n, v); }
}

/// <summary>A gateway test host wired to a FakeApi. Settings are passed as environment variables (visible to eager reads in Program.cs).</summary>
public sealed class Gw : IDisposable
{
    readonly EnvScope _env;
    readonly WebApplicationFactory<Program> _factory;
    public FakeApi Api { get; }
    /// <summary>Step 17: lets a test replace services (for instance the <see cref="TimeProvider"/>) before the host is built. Set it before the first request.</summary>
    public Action<IServiceCollection>? ConfigureServices { get; set; }

    public Gw(Func<HttpRequestMessage, HttpResponseMessage>? respond = null, string environment = "Development", params (string, string)[] settings)
    {
        _env = new EnvScope(settings);
        Api = new FakeApi(respond);
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment(environment);
            b.UseSetting("https_port", "5443");
            b.ConfigureTestServices(s =>
            {
                s.RemoveAll<IForwarderHttpClientFactory>();
                s.AddSingleton<IForwarderHttpClientFactory>(new FakeForwarderClients(Api));
                s.AddTransient<IStartupFilter, FakeRemoteIp>();
                ConfigureServices?.Invoke(s);
            });
        });
    }

    public HttpClient Client(string baseAddress = "https://localhost") =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false, BaseAddress = new Uri(baseAddress) });

    public void Dispose() { _factory.Dispose(); _env.Dispose(); }
}
