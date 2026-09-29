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
    /// <remarks>
    /// <c>.github/workflows/conformance-catalog-drift.yml</c> spells this value out again in
    /// its "Report drift" step — YAML cannot read a C# const — so the two are duplicated with
    /// nothing in the language tying them together. Changing it here alone leaves that grep
    /// matching nothing, and every real drift is then reclassified as "a build or harness
    /// problem": wrong, and green-looking, which is the failure shape this whole area exists
    /// to remove. <c>ConformanceDriftMarkerContractTests</c> reads the workflow and fails if
    /// the two disagree, so the duplication cannot drift silently — change both together.
    /// </remarks>
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
    /// produced today — <see cref="ConformanceReportWriter"/> has no callers, and nothing feeds
    /// <see cref="ConformanceRegistry"/>, so a report would render every case as <c>not_run</c>.
    /// It is asserted because the mapping is the input such a report would be built from: were the
    /// writer wired, an uncovered case would render as <c>not_run</c> and a marker naming an absent
    /// id would be dropped entirely, and neither would fail the run. Keeping the mapping honest now
    /// is what leaves wiring the writer a change to reporting alone.
    /// </para>
    /// <para>
    /// It is also what makes the marker scan usable as an id source. The scheduled case-body drift
    /// check scopes itself to the case ids this SDK registers, and takes them from
    /// <see cref="ScanConformanceMarkers"/>. A scan that quietly missed a marker would quietly
    /// shorten that scope; asserting the scan against the catalog in both directions, on every PR,
    /// is what makes a miss impossible to have without a red run.
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
    /// Every <see cref="ConformanceAttribute"/> marker in <paramref name="testAssembly"/>, one
    /// entry per marker occurrence, carrying the method that declares it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the same scan <see cref="AssertCatalogAndMarkersAgree"/> keys on, exposed so the
    /// repo-specific half of the case-body drift check reads the registered case ids from the
    /// scan the alignment assertion is written against rather than from a second extractor of
    /// its own. Two extractors would be free to disagree, and the one that under-reports is the
    /// one nothing would notice.
    /// </para>
    /// <para>
    /// Occurrences, not ids: a case claimed by more than one test appears once per test, and the
    /// declaring method is what points a reader at the coverage when the check names a case. The
    /// consumer deduplicates.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<ConformanceMarker> ScanConformanceMarkers(Assembly testAssembly)
    {
        ArgumentNullException.ThrowIfNull(testAssembly);

        var markers = new List<ConformanceMarker>();
        foreach (var type in LoadTypes(testAssembly))
        {
            foreach (var method in type.GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic |
                BindingFlags.Instance | BindingFlags.Static))
            {
                foreach (var attr in method.GetCustomAttributes<ConformanceAttribute>())
                {
                    markers.Add(new ConformanceMarker(
                        attr.CaseId,
                        $"{method.DeclaringType?.FullName}.{method.Name}"));
                }
            }
        }

        markers.Sort((left, right) =>
        {
            var byId = string.CompareOrdinal(left.CaseId, right.CaseId);
            return byId != 0 ? byId : string.CompareOrdinal(left.DeclaredBy, right.DeclaredBy);
        });

        return markers;
    }

    /// <summary>
    /// Case ids declared by <see cref="ConformanceAttribute"/> markers in the assembly.
    /// </summary>
    private static SortedSet<string> ScanMarkers(Assembly testAssembly)
    {
        var markedIds = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var marker in ScanConformanceMarkers(testAssembly))
        {
            markedIds.Add(marker.CaseId);
        }

        return markedIds;
    }

    /// <summary>
    /// The assembly's types.
    /// </summary>
    /// <remarks>
    /// A type that fails to load is raised rather than skipped: skipping it would silently lose
    /// every marker it declares, which then surfaces as a list of uncovered catalog cases and
    /// sends the reader hunting for coverage that already exists.
    /// </remarks>
    private static Type[] LoadTypes(Assembly testAssembly)
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

        return types;
    }
}

/// <summary>
/// One <see cref="ConformanceAttribute"/> occurrence: the case id it claims and the fully
/// qualified test method that claims it.
/// </summary>
public sealed record ConformanceMarker(string CaseId, string DeclaredBy);
