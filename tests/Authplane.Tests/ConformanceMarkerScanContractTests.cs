using System.Reflection;
using System.Text.Json;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Ties the JSON <see cref="ConformanceMarkerScanWriter"/> emits to the shape
/// <c>.github/scripts/conformance-registered-case-ids.sh</c> reads back.
/// </summary>
/// <remarks>
/// The emitter is C# and the reader is jq; nothing in either language keeps the field names equal.
/// The failure is silent in the worst direction and on the worst schedule: the reader only runs in
/// the weekly drift job, so renaming a field here leaves every test, the formatter and the build
/// green on the PR, and the break surfaces up to a week later as a step that "could not run" —
/// indistinguishable, in the report the job writes, from a case having been re-tightened.
///
/// The assertions below are deliberately written the way the reader's jq guards are written, field
/// name for field name, so the two move together or this test says so.
/// </remarks>
[Collection(ScanDirectoryCollection)]
public sealed class ConformanceMarkerScanContractTests
{
    /// <summary>
    /// xUnit collection shared by every test class that moves
    /// <see cref="ConformanceMarkerScanWriter.DestinationDirectoryVariable"/> or calls the writer
    /// that reads it.
    /// </summary>
    /// <remarks>
    /// The variable is process-global and xUnit runs test classes in parallel, so a class that
    /// points it at its own temp directory also redirects any <c>WriteIfRequested</c> call racing
    /// it — two writers on one path, which surfaces as a sharing violation rather than as a clean
    /// failure. Members of one collection never run concurrently, so joining this one removes the
    /// race.
    /// </remarks>
    public const string ScanDirectoryCollection = "conformance marker scan";

    private static Assembly TestAssembly => typeof(ConformanceMarkerScanContractTests).Assembly;

    [Fact]
    public void WriteIfRequested_EmitsTheShapeTheReaderScriptRequires()
    {
        var previous = Environment.GetEnvironmentVariable(
            ConformanceMarkerScanWriter.DestinationDirectoryVariable);
        var destination = Path.Combine(
            Path.GetTempPath(), "authplane-marker-scan-" + Guid.NewGuid().ToString("n"));

        try
        {
            Environment.SetEnvironmentVariable(
                ConformanceMarkerScanWriter.DestinationDirectoryVariable, destination);

            var path = ConformanceMarkerScanWriter.WriteIfRequested(TestAssembly);

            // The reader globs `$SCAN_DIR/*.json` and treats one file per assembly as the unit, so
            // the name is part of the contract and not an implementation detail.
            Assert.Equal(
                Path.Combine(destination, TestAssembly.GetName().Name + ".json"), path);
            Assert.True(File.Exists(path));

            using var document = JsonDocument.Parse(File.ReadAllText(path!));
            var root = document.RootElement;
            Assert.Equal(JsonValueKind.Object, root.ValueKind);

            // `(.assembly | type) == "string" and (.assembly | length) > 0`, plus the identity the
            // reader cannot check for itself: the file names the assembly it actually scanned.
            Assert.True(root.TryGetProperty("assembly", out var assembly));
            Assert.Equal(JsonValueKind.String, assembly.ValueKind);
            Assert.Equal(TestAssembly.GetName().Name, assembly.GetString());

            // `(.cases | type) == "array"`.
            Assert.True(root.TryGetProperty("cases", out var cases));
            Assert.Equal(JsonValueKind.Array, cases.ValueKind);

            // `all(.cases[]; .case_id and .declared_by are non-empty strings)`. Every entry is
            // checked rather than sampled: the reader rejects the whole file on one bad entry.
            var emitted = new List<string>();
            foreach (var entry in cases.EnumerateArray())
            {
                Assert.True(entry.TryGetProperty("case_id", out var caseId));
                Assert.Equal(JsonValueKind.String, caseId.ValueKind);
                Assert.NotEmpty(caseId.GetString()!);

                Assert.True(entry.TryGetProperty("declared_by", out var declaredBy));
                Assert.Equal(JsonValueKind.String, declaredBy.ValueKind);
                Assert.NotEmpty(declaredBy.GetString()!);

                emitted.Add(caseId.GetString()!);
            }

            // What the reader ends up with after its `sort -u` must be the scan this assembly
            // vouches for one test class over, in ConformanceCatalogAlignmentTests. Asserting the
            // sets are equal is what makes the emitted list neither short nor invented; asserting
            // it is non-empty is what stops this test from passing on a writer that emits nothing.
            var scanned = ConformanceCatalogAlignment.ScanConformanceMarkers(TestAssembly)
                .Select(marker => marker.CaseId)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToList();

            Assert.NotEmpty(scanned);
            Assert.Equal(
                scanned,
                emitted.Distinct(StringComparer.Ordinal)
                    .OrderBy(id => id, StringComparer.Ordinal)
                    .ToList());
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                ConformanceMarkerScanWriter.DestinationDirectoryVariable, previous);

            if (Directory.Exists(destination))
            {
                Directory.Delete(destination, recursive: true);
            }
        }
    }

    /// <summary>
    /// An ordinary <c>dotnet test</c> run leaves no scan behind — the emitter is opt-in, so a
    /// developer machine and PR CI never write one.
    /// </summary>
    [Fact]
    public void WriteIfRequested_WritesNothingWhenTheVariableIsUnset()
    {
        var previous = Environment.GetEnvironmentVariable(
            ConformanceMarkerScanWriter.DestinationDirectoryVariable);

        try
        {
            Environment.SetEnvironmentVariable(
                ConformanceMarkerScanWriter.DestinationDirectoryVariable, null);

            Assert.Null(ConformanceMarkerScanWriter.WriteIfRequested(TestAssembly));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                ConformanceMarkerScanWriter.DestinationDirectoryVariable, previous);
        }
    }

    /// <summary>
    /// A relative destination resolves against the test host's working directory, so the write
    /// would succeed somewhere the reader never looks and be reported as a scan that never ran.
    /// </summary>
    [Fact]
    public void WriteIfRequested_RejectsARelativeDestination()
    {
        var previous = Environment.GetEnvironmentVariable(
            ConformanceMarkerScanWriter.DestinationDirectoryVariable);

        try
        {
            Environment.SetEnvironmentVariable(
                ConformanceMarkerScanWriter.DestinationDirectoryVariable, "conformance-marker-scan");

            Assert.Throws<InvalidOperationException>(
                () => ConformanceMarkerScanWriter.WriteIfRequested(TestAssembly));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                ConformanceMarkerScanWriter.DestinationDirectoryVariable, previous);
        }
    }
}
