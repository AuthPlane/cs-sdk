namespace Authplane.Conformance;

/// <summary>
/// Marks a test method as exercising one or more conformance catalog cases.
/// </summary>
/// <remarks>
/// Carries the case id plus optional level / gaps / note metadata.
/// The test method is picked up by the catalog-alignment guard, which checks
/// coverage by case id and not test pass/fail. <see cref="ConformanceTracker.RunAsync"/>
/// would record an outcome per case, but nothing calls it today and nothing consumes
/// what it would write — see <see cref="ConformanceReportWriter"/>.
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class ConformanceAttribute : Attribute
{
    public string CaseId { get; }

    /// <summary>
    /// Coverage level. <c>"full"</c> when the test exercises the case end-to-end;
    /// <c>"partial"</c> when only a subset is covered (use <see cref="Gaps"/> + <see cref="Note"/>
    /// to explain); <c>"none"</c> when the case is intentionally not yet covered.
    /// </summary>
    public string Level { get; init; } = "full";

    /// <summary>
    /// Comma-separated list of catalog assertion subfields not covered by this test
    /// (e.g. <c>"expected.error_hint"</c>). Empty when <c>Level == "full"</c>.
    /// </summary>
    public string Gaps { get; init; } = "";

    /// <summary>
    /// Free-text note explaining the gap, the deviation, or the rationale. Intended for
    /// the conformance report, which is not generated today — nothing reads this, or
    /// <see cref="Level"/>, or <see cref="Gaps"/>.
    /// </summary>
    public string Note { get; init; } = "";

    public ConformanceAttribute(string caseId)
    {
        if (string.IsNullOrWhiteSpace(caseId))
        {
            throw new ArgumentException("caseId must not be empty.", nameof(caseId));
        }

        CaseId = caseId;
    }

    /// <summary>
    /// Convert <see cref="Gaps"/> from comma-separated form into a list.
    /// </summary>
    public IReadOnlyList<string> ParsedGaps()
    {
        if (string.IsNullOrWhiteSpace(Gaps))
        {
            return Array.Empty<string>();
        }

        var parts = Gaps.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts;
    }
}
