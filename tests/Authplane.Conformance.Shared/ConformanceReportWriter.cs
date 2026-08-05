using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authplane.Conformance;

/// <summary>
/// Renders <see cref="ConformanceRegistry"/> results into the JSON + Markdown report
/// files that AuthPlane SDKs share. The implementation name/version are reported from
/// the calling assembly (typically <c>Authplane</c>).
/// </summary>
public static class ConformanceReportWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static void Write(
        IReadOnlyList<ConformanceCase> cases,
        IReadOnlyDictionary<string, ConformanceResult> results,
        System.Reflection.Assembly implementationAssembly)
    {
        var meta = ConformanceCatalog.LoadMeta();
        var implName = implementationAssembly.GetName().Name ?? "authplane-csharp-sdk";
        var implVersion = implementationAssembly.GetName().Version?.ToString() ?? "";

        var jsonOptions = JsonOptions;

        var entries = cases.Select(c =>
        {
            if (!results.TryGetValue(c.Id, out var r))
            {
                return new ConformanceReportEntry(
                    case_id: c.Id,
                    status: "not_run",
                    test_name: "",
                    coverage: new ConformanceReportCoverage(level: "none", gaps: Array.Empty<string>(), note: ""),
                    failure: null);
            }

            return new ConformanceReportEntry(
                case_id: r.CaseId,
                status: r.Status,
                test_name: r.TestName,
                coverage: new ConformanceReportCoverage(level: r.Coverage.Level, gaps: r.Coverage.Gaps, note: r.Coverage.Note),
                failure: r.Failure is null
                    ? null
                    : new ConformanceReportFailure(r.Failure.Message, r.Failure.Stack));
        }).ToList();

        var failed = entries.Count(e => string.Equals(e.status, "failed", StringComparison.Ordinal));
        var passed = entries.Count(e => string.Equals(e.status, "passed", StringComparison.Ordinal));
        var skipped = entries.Count(e => string.Equals(e.status, "skipped", StringComparison.Ordinal));
        var notRun = entries.Count(e => string.Equals(e.status, "not_run", StringComparison.Ordinal));

        var payload = new
        {
            catalog_id = meta.CatalogId,
            catalog_version = meta.CatalogVersion,
            implementation = new { name = implName, version = implVersion, language = "C#" },
            runner = new { tool = "xunit", exit_status = failed > 0 ? 1 : 0 },
            summary = new { total = entries.Count, passed, failed, skipped, not_run = notRun },
            cases = entries
        };

        var json = JsonSerializer.Serialize(payload, jsonOptions);
        var jsonOut = Path.Combine(Directory.GetCurrentDirectory(), "conformance-report.json");
        var mdOut = Path.Combine(Directory.GetCurrentDirectory(), "conformance-report.md");

        File.WriteAllText(jsonOut, json + "\n");
        File.WriteAllText(mdOut, RenderMarkdown(meta, implName, implVersion, entries, passed, failed, skipped, notRun));
    }

    private static string RenderMarkdown(
        ConformanceCatalogMeta meta,
        string implName,
        string implVersion,
        IReadOnlyList<ConformanceReportEntry> entries,
        int passed,
        int failed,
        int skipped,
        int notRun)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Conformance Report");
        sb.AppendLine();
        sb.Append("- Catalog: `").Append(meta.CatalogId).Append("` `").Append(meta.CatalogVersion).AppendLine("`");
        sb.Append("- Implementation: `").Append(implName).Append("` `").Append(implVersion).AppendLine("`");
        sb.AppendLine("- Language: `C#`");
        sb.Append("- Generated: `").Append(DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture)).AppendLine("`");
        sb.Append("- Runner: `xunit` exit status `").Append(failed > 0 ? 1 : 0).AppendLine("`");
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.Append("- Total: `").Append(entries.Count).AppendLine("`");
        sb.Append("- Passed: `").Append(passed).AppendLine("`");
        sb.Append("- Failed: `").Append(failed).AppendLine("`");
        sb.Append("- Skipped: `").Append(skipped).AppendLine("`");
        sb.Append("- Not run: `").Append(notRun).AppendLine("`");
        sb.AppendLine();
        sb.AppendLine("## Cases");
        sb.AppendLine();
        sb.AppendLine("| Case ID | Status | Coverage | Note |");
        sb.AppendLine("|---|---|---|---|");
        foreach (var e in entries)
        {
            sb.Append("| `").Append(e.case_id).Append("` | `").Append(e.status).Append("` | `")
              .Append(e.coverage.level).Append("` | ").Append(e.coverage.note).AppendLine(" |");
        }
        return sb.ToString();
    }

    private sealed class ConformanceReportFailure
    {
        public ConformanceReportFailure(string message, string? stack)
        {
            this.message = message;
            this.stack = stack;
        }
        public string message { get; }
        public string? stack { get; }
    }

    private sealed class ConformanceReportCoverage
    {
        public ConformanceReportCoverage(string level, IReadOnlyList<string> gaps, string note)
        {
            this.level = level;
            this.gaps = gaps;
            this.note = note;
        }
        public string level { get; }
        public IReadOnlyList<string> gaps { get; }
        public string note { get; }
    }

    private sealed class ConformanceReportEntry
    {
        public ConformanceReportEntry(
            string case_id,
            string status,
            string test_name,
            ConformanceReportCoverage coverage,
            ConformanceReportFailure? failure)
        {
            this.case_id = case_id;
            this.status = status;
            this.test_name = test_name;
            this.coverage = coverage;
            this.failure = failure;
        }
        public string case_id { get; }
        public string status { get; }
        public string test_name { get; }
        public ConformanceReportCoverage coverage { get; }
        public ConformanceReportFailure? failure { get; }
    }
}
