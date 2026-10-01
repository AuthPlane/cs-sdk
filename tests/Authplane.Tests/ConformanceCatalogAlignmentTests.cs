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
///
/// The emitter [Fact] below calls the scan writer, which reads a process-global environment
/// variable that ConformanceMarkerScanContractTests points at a temp directory. Both classes join
/// the same collection so the two never run at once.
/// </remarks>
[Collection(ConformanceMarkerScanContractTests.ScanDirectoryCollection)]
public sealed class ConformanceCatalogAlignmentTests
{
    [Fact]
    public void CatalogCasesAndConformanceMarkers_Agree()
    {
        ConformanceCatalogAlignment.AssertCatalogAndMarkersAgree(
            typeof(ConformanceCatalogAlignmentTests).Assembly);
    }

    /// <summary>
    /// Emits the [Conformance] marker scan of this assembly for the scheduled case-body drift
    /// check, when the workflow asks for it.
    /// </summary>
    /// <remarks>
    /// It lives beside the assertion above on purpose. The drift check is only as good as the id
    /// list it is scoped to, and what makes this list trustworthy is that the same scan is
    /// asserted against the catalog in both directions one test over, in the same run and against
    /// the same catalog — a marker the scan missed shows up there as an uncovered catalog case
    /// and turns the run red, rather than quietly shortening the drift check's scope.
    ///
    /// Emission is conditional on CONFORMANCE_MARKER_SCAN_DIR, so an ordinary run writes nothing.
    /// The assertions below hold either way: they pin the extractor's own contract, which the
    /// reader script re-checks on the file it finds.
    /// </remarks>
    [Fact]
    public void ConformanceMarkerScan_IsWellFormedAndEmittedWhenRequested()
    {
        var markers = ConformanceCatalogAlignment.ScanConformanceMarkers(
            typeof(ConformanceCatalogAlignmentTests).Assembly);

        Assert.NotEmpty(markers);
        Assert.All(markers, marker =>
        {
            Assert.False(string.IsNullOrWhiteSpace(marker.CaseId));
            Assert.False(string.IsNullOrWhiteSpace(marker.DeclaredBy));
        });

        ConformanceMarkerScanWriter.WriteIfRequested(
            typeof(ConformanceCatalogAlignmentTests).Assembly);
    }
}
