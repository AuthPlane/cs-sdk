namespace Authplane.Conformance;

/// <summary>
/// Marks a test method as exercising one or more conformance catalog cases.
/// </summary>
/// <remarks>
/// Carries the case id plus optional level / gaps / note metadata.
/// The test method is expected to either (a) run real assertions and call
/// <see cref="ConformanceTracker.RunAsync"/> to record the outcome, or (b) be picked up
/// by the catalog-alignment guard which only checks coverage by case id, not test pass/fail.
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
    /// Free-text note explaining the gap, the deviation, or the rationale. Surfaced in
    /// the conformance report.
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
