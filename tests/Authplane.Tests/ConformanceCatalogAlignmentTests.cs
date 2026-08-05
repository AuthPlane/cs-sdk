using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Catalog-alignment guard for the core SDK test assembly.
/// </summary>
/// <remarks>
/// Every
/// case in <c>oauth-sdk-conformance-catalog.yaml</c> must be referenced by at least
/// one [Conformance] attribute on a test method in this assembly. Failure mode
/// surfaces the missing case ids in the message so the gap is actionable.
/// </remarks>
public sealed class ConformanceCatalogAlignmentTests
{
    [Fact]
    public void EveryCatalogCase_HasConformanceMarker()
    {
        ConformanceCatalogAlignment.AssertEveryCaseHasMarker(typeof(ConformanceCatalogAlignmentTests).Assembly);
    }
}
