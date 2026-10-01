using System.Reflection;
using System.Text.Json;

namespace Authplane.Conformance;

/// <summary>
/// Writes the <see cref="ConformanceAttribute"/> scan of a test assembly to disk, for the
/// scheduled case-body drift check to read.
/// </summary>
/// <remarks>
/// <para>
/// The drift check compares the body of every case this SDK registers between the pinned catalog
/// and the catalog tip, so it needs the registered case ids. Those come from
/// <see cref="ConformanceCatalogAlignment.ScanConformanceMarkers"/> — reflection over the compiled
/// attributes, the same scan <see cref="ConformanceCatalogAlignment.AssertCatalogAndMarkersAgree"/>
/// is written against. Nothing here re-derives the ids from the test sources: a second extractor
/// reports what it matched and stays silent about what it missed, and silence is the failure the
/// drift check exists to remove.
/// </para>
/// <para>
/// Writing happens only when <see cref="DestinationDirectoryVariable"/> names a directory, so an
/// ordinary <c>dotnet test</c> run produces nothing. CI sets it, runs the alignment tests, and
/// reads the files back with <c>.github/scripts/conformance-registered-case-ids.sh</c>.
/// </para>
/// <para>
/// One file per test assembly, named after the assembly. An assembly that declares no markers
/// writes a file with an empty case list rather than no file at all: the reader must be able to
/// tell a scan that ran and found nothing from a scan that never ran, and only the first of those
/// is a legitimate state.
/// </para>
/// </remarks>
public static class ConformanceMarkerScanWriter
{
    /// <summary>
    /// Environment variable naming the directory to write scan files into. Unset means do nothing.
    /// </summary>
    /// <remarks>
    /// <c>.github/workflows/conformance-catalog-drift.yml</c> and
    /// <c>.github/scripts/conformance-registered-case-ids.sh</c> spell this name out again — YAML
    /// and shell cannot read a C# const. Change all three together, or the drift job silently
    /// collects nothing and its own empty-list guard is what reports it.
    /// </remarks>
    public const string DestinationDirectoryVariable = "CONFORMANCE_MARKER_SCAN_DIR";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>
    /// Write the marker scan of <paramref name="testAssembly"/> if
    /// <see cref="DestinationDirectoryVariable"/> is set, and return the path written; return
    /// <c>null</c> when the variable is unset.
    /// </summary>
    public static string? WriteIfRequested(Assembly testAssembly)
    {
        ArgumentNullException.ThrowIfNull(testAssembly);

        var destination = Environment.GetEnvironmentVariable(DestinationDirectoryVariable);
        if (string.IsNullOrWhiteSpace(destination))
        {
            return null;
        }

        destination = destination.Trim();

        // A relative path would resolve against the test host's working directory, which is the
        // assembly's output directory and not anything the workflow named. Writing there would
        // succeed and leave the reader looking at an empty directory — the scan-never-ran state,
        // reported as if the emitter were broken.
        if (!Path.IsPathRooted(destination))
        {
            throw new InvalidOperationException(
                $"{DestinationDirectoryVariable} must be an absolute path, got '{destination}'. A " +
                "relative path resolves against the test host's working directory, so the scan " +
                "would be written somewhere the reader never looks.");
        }

        var assemblyName = testAssembly.GetName().Name;
        if (string.IsNullOrWhiteSpace(assemblyName))
        {
            throw new InvalidOperationException(
                "The test assembly has no simple name, so its marker scan has nowhere to go " +
                "without colliding with another assembly's.");
        }

        var markers = ConformanceCatalogAlignment.ScanConformanceMarkers(testAssembly);

        var payload = new
        {
            assembly = assemblyName,
            cases = markers
                .Select(m => new { case_id = m.CaseId, declared_by = m.DeclaredBy })
                .ToList(),
        };

        Directory.CreateDirectory(destination);
        var path = Path.Combine(destination, assemblyName + ".json");
        File.WriteAllText(path, JsonSerializer.Serialize(payload, JsonOptions) + "\n");
        return path;
    }
}
