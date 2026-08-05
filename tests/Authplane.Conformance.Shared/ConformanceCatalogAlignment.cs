using System.Reflection;

namespace Authplane.Conformance;

/// <summary>
/// Reusable catalog-alignment guard. Test projects expose an xUnit Fact that calls
/// <see cref="AssertEveryCaseHasMarker"/> against their own assembly.
/// </summary>
/// <remarks>
/// Every catalog case id must be represented by at least one [Conformance] marker.
/// </remarks>
public static class ConformanceCatalogAlignment
{
    /// <summary>
    /// Throws if any catalog case lacks a <see cref="ConformanceAttribute"/> in the
    /// supplied assembly. Cases explicitly deferred via <c>level="none"</c> still count
    /// as covered (the marker is present; the report tags them).
    /// </summary>
    public static void AssertEveryCaseHasMarker(Assembly testAssembly)
    {
        ArgumentNullException.ThrowIfNull(testAssembly);

        var catalogIds = new HashSet<string>(
            ConformanceCatalog.LoadCases().Select(c => c.Id),
            StringComparer.Ordinal);

        var markedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var type in testAssembly.GetTypes())
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

        var missing = catalogIds.Except(markedIds).OrderBy(id => id, StringComparer.Ordinal).ToList();
        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                "Catalog cases without [Conformance] markers: " +
                string.Join(", ", missing));
        }
    }
}
