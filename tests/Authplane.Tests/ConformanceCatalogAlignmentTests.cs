using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Catalog-alignment guard for the core SDK test assembly.
/// </summary>
/// <remarks>
/// Asserted in both directions: every case in <c>oauth-sdk-conformance-catalog.yaml</c> must be
/// referenced by at least one [Conformance] attribute in this assembly, and every id referenced by
/// a [Conformance] attribute must exist in the catalog. Both failure modes surface the offending
/// case ids in the message so the gap is actionable.
///
/// This runs on every PR against the catalog SHA pinned in <c>.conformance-catalog-ref</c>, so
/// bumping that pin without the matching coverage fails here rather than merging green.
/// </remarks>
public sealed class ConformanceCatalogAlignmentTests
{
    [Fact]
    public void CatalogCasesAndConformanceMarkers_Agree()
    {
        ConformanceCatalogAlignment.AssertCatalogAndMarkersAgree(
            typeof(ConformanceCatalogAlignmentTests).Assembly);
    }
}
