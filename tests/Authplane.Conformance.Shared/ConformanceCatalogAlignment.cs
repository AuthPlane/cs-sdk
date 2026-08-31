using System.Reflection;

namespace Authplane.Conformance;

/// <summary>
/// Reusable catalog-alignment guard. Test projects expose an xUnit Fact that calls
/// <see cref="AssertCatalogAndMarkersAgree"/> against their own assembly.
/// </summary>
/// <remarks>
/// The catalog and the <see cref="ConformanceAttribute"/> markers must agree in both
/// directions; see <see cref="AssertCatalogAndMarkersAgree"/> for why one direction is
/// not enough.
/// </remarks>
public static class ConformanceCatalogAlignment
{
    /// <summary>
    /// Prefix on every drift failure message. The scheduled drift workflow greps the test
    /// log for it to tell real catalog drift apart from a build or harness failure, which
    /// fails the same step with a different cause.
    /// </summary>
    public const string DriftMarker = "Conformance-catalog drift:";

    /// <summary>
    /// Asserts that the resolved catalog and the <see cref="ConformanceAttribute"/> markers in
    /// <paramref name="testAssembly"/> agree in both directions:
    /// <list type="bullet">
    /// <item>every catalog case id carries at least one marker, so no catalog case is left
    /// silently uncovered;</item>
    /// <item>every marked case id exists in the catalog, so no marker claims coverage of a case
    /// the catalog does not carry.</item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// <para>
    /// This checks the marker-to-catalog mapping and nothing else. No conformance report is
    /// produced today — <see cref="ConformanceReportWriter"/> has no callers — so a mismatch
    /// currently affects no artifact. It is asserted because the mapping is the input a report
    /// would be built from: were the writer wired, an uncovered case would render as
    /// <c>not_run</c> and a marker naming an absent id would be dropped entirely, and neither
    /// would fail the run. Keeping the mapping honest now is what leaves wiring the writer a
    /// change to reporting alone.
    /// </para>
    /// <para>
    /// Cases explicitly deferred via <c>Level = "none"</c> still count as covered: the marker is
    /// present, which is all this check looks at.
    /// </para>
    /// <para>
    /// This runs against whichever catalog <see cref="ConformanceCatalog"/> resolves: the SHA
    /// pinned in <c>.conformance-catalog-ref</c> in PR and release CI, and the catalog's unpinned
    /// tip in the scheduled drift job (which points <c>CONFORMANCE_CATALOG_PATH</c> at its own
    /// clone). Asserting it at PR time is what makes a bump of <c>.conformance-catalog-ref</c>
    /// safe: a bump that adds cases without SDK-side coverage turns the PR red instead of merging
    /// green and publishing a report full of silent <c>not_run</c> entries.
    /// </para>
    /// </remarks>
    public static void AssertCatalogAndMarkersAgree(Assembly testAssembly)
    {
        ArgumentNullException.ThrowIfNull(testAssembly);

        var catalogIds = new SortedSet<string>(
            ConformanceCatalog.LoadCases().Select(c => c.Id),
            StringComparer.Ordinal);

        // A catalog that parsed to nothing would report every marker as unknown and every case as
        // covered — the opposite of drift, and silently green on the direction that matters.
        if (catalogIds.Count == 0)
        {
            throw new InvalidOperationException(
                "The resolved conformance catalog contains no cases. The catalog failed to parse " +
                "or the wrong file was resolved — this is not catalog drift.");
        }

        var markedIds = ScanMarkers(testAssembly);

        var uncovered = catalogIds.Except(markedIds, StringComparer.Ordinal)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();
        if (uncovered.Count > 0)
        {
            throw new InvalidOperationException(
                $"{DriftMarker} {uncovered.Count} catalog case(s) have no [Conformance] marker in " +
                $"{testAssembly.GetName().Name}. Add SDK-side coverage for each, then bump " +
                ".conformance-catalog-ref:" + Environment.NewLine + "  - " +
                string.Join(Environment.NewLine + "  - ", uncovered));
        }

        var unknown = markedIds.Except(catalogIds, StringComparer.Ordinal)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();
        if (unknown.Count > 0)
        {
            throw new InvalidOperationException(
                $"{DriftMarker} {unknown.Count} test(s) in {testAssembly.GetName().Name} declare " +
                "case id(s) absent from the catalog, so they claim coverage that maps to nothing. " +
                "Correct the id or drop the [Conformance] attribute:" + Environment.NewLine + "  - " +
                string.Join(Environment.NewLine + "  - ", unknown));
        }
    }

    /// <summary>
    /// Asserts only that every <see cref="ConformanceAttribute"/> in <paramref name="testAssembly"/>
    /// names a case that exists in the catalog. For assemblies that are not expected to cover the
    /// catalog themselves — the coverage direction is asserted where the markers live.
    /// </summary>
    public static void AssertNoUnknownCaseIds(Assembly testAssembly)
    {
        ArgumentNullException.ThrowIfNull(testAssembly);

        var catalogIds = new SortedSet<string>(
            ConformanceCatalog.LoadCases().Select(c => c.Id),
            StringComparer.Ordinal);

        if (catalogIds.Count == 0)
        {
            throw new InvalidOperationException(
                "The resolved conformance catalog contains no cases. The catalog failed to parse " +
                "or the wrong file was resolved — this is not catalog drift.");
        }

        var unknown = ScanMarkers(testAssembly).Except(catalogIds, StringComparer.Ordinal)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();
        if (unknown.Count > 0)
        {
            throw new InvalidOperationException(
                $"{DriftMarker} {unknown.Count} test(s) in {testAssembly.GetName().Name} declare " +
                "case id(s) absent from the catalog, so they claim coverage that maps to nothing. " +
                "Correct the id or drop the [Conformance] attribute:" + Environment.NewLine + "  - " +
                string.Join(Environment.NewLine + "  - ", unknown));
        }
    }

    /// <summary>
    /// Case ids declared by <see cref="ConformanceAttribute"/> markers in the assembly.
    /// </summary>
    /// <remarks>
    /// A type that fails to load is raised rather than skipped: skipping it would silently lose
    /// every marker it declares, which then surfaces as a list of uncovered catalog cases and
    /// sends the reader hunting for coverage that already exists.
    /// </remarks>
    private static SortedSet<string> ScanMarkers(Assembly testAssembly)
    {
        Type[] types;
        try
        {
            types = testAssembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            var reasons = ex.LoaderExceptions
                .Where(e => e is not null)
                .Select(e => e!.Message)
                .Distinct(StringComparer.Ordinal);
            throw new InvalidOperationException(
                $"Conformance-marker scan incomplete: types in {testAssembly.GetName().Name} could " +
                "not be loaded, so any [Conformance] they declare is missing from this check. Fix " +
                "the scan before trusting its result:" + Environment.NewLine + "  - " +
                string.Join(Environment.NewLine + "  - ", reasons),
                ex);
        }

        var markedIds = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var type in types)
        {
            foreach (var method in type.GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic |
                BindingFlags.Instance | BindingFlags.Static))
            {
                foreach (var attr in method.GetCustomAttributes<ConformanceAttribute>())
                {
                    markedIds.Add(attr.CaseId);
                }
            }
        }

        return markedIds;
    }
}
