using System.Text.RegularExpressions;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Ties <see cref="ConformanceCatalogAlignment.DriftMarker"/> to the copy of it embedded in
/// the scheduled drift workflow.
/// </summary>
/// <remarks>
/// The workflow classifies a failed alignment step by grepping the test log for the marker:
/// present means real catalog drift, absent means a build or harness problem. YAML cannot
/// read a C# const, so the value is spelled out in both places. Nothing in the language
/// keeps them equal, and the failure is silent in the worst direction — rename the const
/// alone and the grep matches nothing, so every genuine drift is reported as infrastructure
/// noise and the scheduled job stays green-looking while the catalog moves away underneath.
/// These tests are what makes the duplication safe.
/// </remarks>
public sealed class ConformanceDriftMarkerContractTests
{
    private const string WorkflowRelativePath =
        ".github/workflows/conformance-catalog-drift.yml";

    /// <summary>
    /// Matches the workflow's classification grep, capturing the literal it searches for.
    /// </summary>
    private static readonly Regex GrepLiteralRe =
        new(@"grep\s+-qF\s+'(?<literal>[^']*)'", RegexOptions.Compiled);

    /// <summary>
    /// Matches anything shaped like a drift marker anywhere in the workflow, so a second
    /// hand-written copy is caught wherever it sits — the classification grep, a
    /// <c>::warning::</c> line, or job-summary prose. Deliberately matched by shape rather
    /// than by the current spelling: a test that looked for today's exact string could not
    /// see a stale copy of yesterday's.
    /// </summary>
    private static readonly Regex MarkerShapedRe =
        new(@"[A-Za-z][A-Za-z -]*drift:", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    [Fact]
    public void Workflow_GrepsExactlyTheMarkerTheAssertionWrites()
    {
        var workflow = ReadWorkflow();

        var literals = GrepLiteralRe.Matches(workflow)
            .Select(m => m.Groups["literal"].Value)
            .ToList();

        // Without this the assertion below passes on an empty set — the workflow could have
        // dropped the classification grep entirely and this test would not notice.
        Assert.NotEmpty(literals);

        foreach (var literal in literals)
        {
            Assert.Equal(ConformanceCatalogAlignment.DriftMarker, literal);
        }
    }

    [Fact]
    public void Workflow_CarriesNoOtherSpellingOfTheMarker()
    {
        var workflow = ReadWorkflow();

        var spellings = MarkerShapedRe.Matches(workflow)
            .Select(m => m.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(spellings);

        // Every copy, functional or prose, has to read the same as the const. A summary that
        // names a marker the assertion no longer writes sends a reader looking for the wrong
        // string in the log.
        Assert.Equal(
            new[] { ConformanceCatalogAlignment.DriftMarker },
            spellings);
    }

    /// <summary>
    /// The other half of the contract: the assertion has to actually put the marker in its
    /// message, or the workflow's grep classifies real drift as a harness problem however
    /// well the two literals agree.
    /// </summary>
    [Fact]
    public void DriftFailureMessage_StartsWithTheMarker()
    {
        // An assembly that carries no [Conformance] markers leaves every catalog case
        // uncovered, which is the drift direction the scheduled job exists to catch.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            ConformanceCatalogAlignment.AssertCatalogAndMarkersAgree(typeof(object).Assembly));

        Assert.StartsWith(ConformanceCatalogAlignment.DriftMarker, ex.Message, StringComparison.Ordinal);
    }

    private static string ReadWorkflow() => File.ReadAllText(ResolveWorkflowPath());

    /// <summary>
    /// Walks up from the test binary's working directory, matching how
    /// <c>ConformanceCatalog</c> resolves the catalog itself.
    /// </summary>
    private static string ResolveWorkflowPath()
    {
        var dir = Directory.GetCurrentDirectory();
        for (var i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, WorkflowRelativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            var parent = Directory.GetParent(dir);
            if (parent is null)
            {
                break;
            }

            dir = parent.FullName;
        }

        throw new FileNotFoundException(
            $"Could not find `{WorkflowRelativePath}` in any ancestor of " +
            $"`{Directory.GetCurrentDirectory()}`. The drift marker is duplicated between the " +
            "workflow and ConformanceCatalogAlignment.DriftMarker; this test is what keeps the " +
            "two equal, so a silently skipped lookup is itself the failure.");
    }
}
