namespace Authplane.Conformance;

/// <summary>
/// Executes a single conformance case body, recording the result against
/// <see cref="ConformanceRegistry"/>. Re-throws on failure so the underlying xUnit
/// theory case still fails the run.
/// </summary>
public static class ConformanceCaseRunner
{
    private static readonly ConformanceCoverage FullCoverage = new("full", Array.Empty<string>());

    public static async Task RunAsync(
        string caseId,
        string testName,
        Func<Task> fn,
        ConformanceCoverage? coverage = null)
    {
        var effectiveCoverage = coverage ?? FullCoverage;
        try
        {
            await fn().ConfigureAwait(false);
            ConformanceRegistry.RecordPassed(caseId, testName, effectiveCoverage);
        }
        catch (Exception ex)
        {
            ConformanceRegistry.RecordFailed(caseId, testName, effectiveCoverage, ex);
            throw;
        }
    }
}
