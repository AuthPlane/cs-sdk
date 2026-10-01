using Authplane.Conformance;
using Xunit;

namespace Authplane.Mcp.Tests;

/// <summary>
/// Catalog-alignment guard for the MCP adapter test assembly.
/// </summary>
/// <remarks>
/// The MCP adapter (Authplane.Mcp) is a thin middleware wrapper around the core SDK (Authplane).
/// Every conformance case for core SDK behaviour (JWT verification, DPoP, OAuth protocol, metadata)
/// is exercised and marked in Authplane.Tests, and the coverage direction — every catalog case has
/// a marker — is asserted there against that assembly.
///
/// Asserting the same direction here would fail on the first catalog case, because this assembly
/// declares no markers of its own. What is asserted here is the direction that is meaningful for
/// this assembly: any [Conformance] marker it does declare must name a case that exists in the
/// catalog. Nothing else would catch a typo'd id — no conformance report is generated today, and
/// were one generated it would be built by iterating the catalog, which drops such a marker
/// without comment.
///
/// Because the assembly declares no markers, this currently asserts only that the catalog resolves
/// and parses. It is a forward-looking guard; do not read a passing run as coverage.
///
/// If the MCP adapter grows its own conformance-relevant behaviour (e.g. MCP-specific auth
/// negotiation), add the markers here and switch to AssertCatalogAndMarkersAgree.
/// </remarks>
public sealed class ConformanceCatalogAlignmentTests
{
    [Fact]
    public void ConformanceMarkers_NameCasesThatExistInTheCatalog()
    {
        ConformanceCatalogAlignment.AssertNoUnknownCaseIds(
            typeof(ConformanceCatalogAlignmentTests).Assembly);
    }

    /// <summary>
    /// Emits the [Conformance] marker scan of this assembly for the scheduled case-body drift
    /// check, when the workflow asks for it.
    /// </summary>
    /// <remarks>
    /// The scan is empty today, for the same reason the assertion above has nothing to check: this
    /// assembly declares no markers. It is emitted anyway so the reader sees a scan that ran and
    /// found nothing rather than a scan that never ran, and so markers added here later are
    /// watched by the drift check without anyone having to remember to widen it.
    ///
    /// Emptiness is therefore not asserted here. The reader requires the union across assemblies
    /// to be non-empty, which is the guard that matters: an empty id list makes the drift check
    /// vacuously green.
    /// </remarks>
    [Fact]
    public void ConformanceMarkerScan_IsWellFormedAndEmittedWhenRequested()
    {
        var markers = ConformanceCatalogAlignment.ScanConformanceMarkers(
            typeof(ConformanceCatalogAlignmentTests).Assembly);

        Assert.All(markers, marker =>
        {
            Assert.False(string.IsNullOrWhiteSpace(marker.CaseId));
            Assert.False(string.IsNullOrWhiteSpace(marker.DeclaredBy));
        });

        ConformanceMarkerScanWriter.WriteIfRequested(
            typeof(ConformanceCatalogAlignmentTests).Assembly);
    }
}
