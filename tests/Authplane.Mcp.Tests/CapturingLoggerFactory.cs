using Microsoft.Extensions.Logging;

namespace Authplane.Mcp.Tests;

/// <summary>
/// Records what the middleware logs, so a test can assert that the cause the
/// response deliberately withholds reached the operator instead of being
/// dropped. <paramref name="minimumLevel"/> drives <see cref="ILogger.IsEnabled"/>:
/// the middleware guards its Debug call with it, and a test that left it at
/// the default would be asserting on a record production never writes.
/// </summary>
internal sealed class CapturingLoggerFactory(LogLevel minimumLevel = LogLevel.Trace) : ILoggerFactory
{
    private readonly CapturingLogger _logger = new(minimumLevel);

    public IReadOnlyList<CapturingLogger.Record> Records => _logger.Records;

    public string? Category { get; private set; }

    public ILogger CreateLogger(string categoryName)
    {
        Category = categoryName;
        return _logger;
    }

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public void Dispose()
    {
    }
}

internal sealed class CapturingLogger(LogLevel minimumLevel) : ILogger
{
    private readonly List<Record> _records = [];

    internal sealed record Record(LogLevel Level, EventId EventId, Exception? Exception, string Message);

    public IReadOnlyList<Record> Records => _records;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= minimumLevel;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        _records.Add(new Record(logLevel, eventId, exception, formatter(state, exception)));
    }
}
