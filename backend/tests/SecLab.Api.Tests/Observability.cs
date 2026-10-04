using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SecLab.Api.Tests;

/// <summary>Everything the app logs while a test runs: category, level, structured state, scopes, exception.</summary>
public sealed class LogCapture : ILoggerProvider, ISupportExternalScope
{
    public sealed record Entry(string Category, LogLevel Level, EventId EventId, string Message,
        IReadOnlyDictionary<string, object?> State, IReadOnlyList<IReadOnlyDictionary<string, object?>> Scopes, Exception? Exception)
    {
        public string? Str(string key) => State.TryGetValue(key, out var v) ? v?.ToString() : null;
        public IEnumerable<string> AllText()
        {
            yield return Message;
            foreach (var v in State.Values) if (v is not null) yield return v.ToString()!;
            foreach (var s in Scopes) foreach (var v in s.Values) if (v is not null) yield return v.ToString()!;
            if (Exception is not null) yield return Exception.ToString();
        }
    }

    readonly List<Entry> _entries = [];
    IExternalScopeProvider _scopes = new LoggerExternalScopeProvider();

    public IReadOnlyList<Entry> Entries { get { lock (_entries) return _entries.ToList(); } }
    public IEnumerable<Entry> Audit => Entries.Where(e => e.Category == "SecLab.Audit");
    public Entry? AuditEvent(string name) => Audit.LastOrDefault(e => e.Str("Event") == name);

    public ILogger CreateLogger(string categoryName) => new CaptureLogger(this, categoryName);
    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopes = scopeProvider;
    public void Dispose() { }

    sealed class CaptureLogger(LogCapture owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => owner._scopes.Push(state);
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var scopes = new List<IReadOnlyDictionary<string, object?>>();
            owner._scopes.ForEachScope((scope, list) => list.Add(ToDict(scope)), scopes);
            var entry = new LogCapture.Entry(category, level, eventId, formatter(state, exception), ToDict(state), scopes, exception);
            lock (owner._entries) owner._entries.Add(entry);
        }

        static IReadOnlyDictionary<string, object?> ToDict(object? state) =>
            state is IEnumerable<KeyValuePair<string, object?>> kvs
                ? kvs.GroupBy(k => k.Key).ToDictionary(g => g.Key, g => g.Last().Value)
                : new Dictionary<string, object?> { ["scope"] = state?.ToString() };
    }
}

/// <summary>Records measurements of the app's security meter ("SecLab.Security") so tests can assert on counters and their tags.</summary>
public sealed class MetricCapture : IDisposable
{
    public sealed record Measurement(string Instrument, long Value, IReadOnlyDictionary<string, object?> Tags);

    readonly MeterListener _listener = new();
    readonly List<Measurement> _measurements = [];

    public MetricCapture()
    {
        _listener.InstrumentPublished = (instrument, listener) => { if (instrument.Meter.Name == "SecLab.Security") listener.EnableMeasurementEvents(instrument); };
        _listener.SetMeasurementEventCallback<long>((inst, value, tags, _) =>
        {
            var dict = new Dictionary<string, object?>();
            foreach (var t in tags) dict[t.Key] = t.Value;
            lock (_measurements) _measurements.Add(new Measurement(inst.Name, value, dict));
        });
        _listener.SetMeasurementEventCallback<int>((inst, value, tags, _) =>
        {
            var dict = new Dictionary<string, object?>();
            foreach (var t in tags) dict[t.Key] = t.Value;
            lock (_measurements) _measurements.Add(new Measurement(inst.Name, value, dict));
        });
        _listener.Start();
    }

    public IReadOnlyList<Measurement> Measurements { get { lock (_measurements) return _measurements.ToList(); } }
    public long Sum(string instrument) => Measurements.Where(m => m.Instrument == instrument).Sum(m => m.Value);
    public void Dispose() => _listener.Dispose();
}
