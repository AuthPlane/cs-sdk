using System.Reflection;
using System.Runtime.CompilerServices;

namespace Authplane.Conformance;

/// <summary>
/// Helper that conformance-bound tests use to report their outcome to
/// <see cref="ConformanceRegistry"/>.
/// </summary>
/// <remarks>
/// The typical usage in a test method:
/// <code>
/// [Fact]
/// [Conformance("rfc8414-metadata-issuer-must-match-configured-issuer")]
/// public async Task IssuerMismatch_Throws()
/// {
///     await ConformanceTracker.RunAsync(this, async () =>
///     {
///         // real assertions here
///     });
/// }
/// </code>
/// The tracker uses reflection on the calling method to find the
/// <see cref="ConformanceAttribute"/>(s) and records a result for each case id.
/// </remarks>
public static class ConformanceTracker
{
    /// <summary>
    /// Run <paramref name="body"/> and record the outcome (pass/fail) for every
    /// <see cref="ConformanceAttribute"/> applied to the method that called this helper.
    /// </summary>
    public static async Task RunAsync(
        object testInstance,
        Func<Task> body,
        [CallerMemberName] string callerMemberName = "")
    {
        ArgumentNullException.ThrowIfNull(testInstance);
        ArgumentNullException.ThrowIfNull(body);

        var method = testInstance.GetType().GetMethod(
            callerMemberName,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        var attrs = method?.GetCustomAttributes<ConformanceAttribute>().ToArray() ?? Array.Empty<ConformanceAttribute>();
        var testName = method is null
            ? callerMemberName
            : $"{method.DeclaringType?.FullName}.{method.Name}";

        try
        {
            await body().ConfigureAwait(false);
            foreach (var attr in attrs)
            {
                ConformanceRegistry.RecordPassed(
                    attr.CaseId,
                    testName,
                    new ConformanceCoverage(attr.Level, attr.ParsedGaps(), attr.Note));
            }
        }
        catch (Exception ex)
        {
            foreach (var attr in attrs)
            {
                ConformanceRegistry.RecordFailed(
                    attr.CaseId,
                    testName,
                    new ConformanceCoverage(attr.Level, attr.ParsedGaps(), attr.Note),
                    ex);
            }
            throw;
        }
    }
}
