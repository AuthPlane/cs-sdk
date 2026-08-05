using System.Collections.Concurrent;

namespace Authplane.Conformance;

public sealed record ConformanceCoverage(string Level, IReadOnlyList<string> Gaps, string Note = "");

public sealed record ConformanceFailure(string Message, string? Stack);

public sealed class ConformanceResult
{
    public string CaseId { get; init; } = "";
    public string TestName { get; init; } = "";
    public string Status { get; init; } = "passed"; // passed | failed | skipped
    public ConformanceCoverage Coverage { get; init; } = new("full", Array.Empty<string>());
    public ConformanceFailure? Failure { get; init; }
}

/// <summary>
/// In-memory aggregator that conformance test runners write into. Cleared per test run via
/// <see cref="ResetForRun"/>; <see cref="WaitForCompletionAsync"/> blocks until every
/// expected case has reported (or the timeout elapses).
/// </summary>
public static class ConformanceRegistry
{
    private static readonly ConcurrentDictionary<string, ConformanceResult> Results = new();

    private static int ExpectedTotal;
    private static int Completed;
    private static TaskCompletionSource<bool>? DoneSource;

    public static void ResetForRun()
    {
        Results.Clear();
        ExpectedTotal = 0;
        Completed = 0;
        DoneSource = null;
    }

    public static void SetExpectedTotal(int total)
    {
        ExpectedTotal = total;
        DoneSource ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    public static IReadOnlyDictionary<string, ConformanceResult> Snapshot() => Results;

    public static void RecordPassed(string caseId, string testName, ConformanceCoverage coverage)
    {
        Results[caseId] = new ConformanceResult
        {
            CaseId = caseId,
            TestName = testName,
            Status = "passed",
            Coverage = coverage,
        };
        MarkCompleted();
    }

    public static void RecordFailed(string caseId, string testName, ConformanceCoverage coverage, Exception ex)
    {
        Results[caseId] = new ConformanceResult
        {
            CaseId = caseId,
            TestName = testName,
            Status = "failed",
            Coverage = coverage,
            Failure = new ConformanceFailure(ex.Message, ex.StackTrace),
        };
        MarkCompleted();
    }

    public static void RecordSkipped(string caseId, string testName, ConformanceCoverage coverage)
    {
        Results[caseId] = new ConformanceResult
        {
            CaseId = caseId,
            TestName = testName,
            Status = "skipped",
            Coverage = coverage,
        };
        MarkCompleted();
    }

    private static void MarkCompleted()
    {
        var completed = Interlocked.Increment(ref Completed);
        if (ExpectedTotal > 0 && completed >= ExpectedTotal)
        {
            DoneSource?.TrySetResult(true);
        }
    }

    public static async Task WaitForCompletionAsync(TimeSpan timeout)
    {
        var source = DoneSource;
        if (source is null)
        {
            // No cases were registered to wait for.
            return;
        }

        await Task.WhenAny(source.Task, Task.Delay(timeout)).ConfigureAwait(false);
    }
}
