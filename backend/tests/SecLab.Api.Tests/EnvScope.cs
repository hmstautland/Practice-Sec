namespace SecLab.Api.Tests;

/// <summary>Sets environment variables (e.g. RateLimiting__Anonymous=5) for the lifetime of a test and restores them afterwards.
/// Must be created BEFORE the test host is built (hosts are built lazily on the first CreateClient call).</summary>
public sealed class EnvScope : IDisposable
{
    readonly Dictionary<string, string?> _previous = new();

    public EnvScope(params (string Name, string Value)[] settings)
    {
        foreach (var (name, value) in settings)
        {
            _previous[name] = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }
    }

    public void Dispose()
    {
        foreach (var (name, value) in _previous) Environment.SetEnvironmentVariable(name, value);
    }
}
