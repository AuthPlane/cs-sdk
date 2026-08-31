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
}
