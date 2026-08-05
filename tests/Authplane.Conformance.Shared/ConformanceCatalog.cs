using System.Text.RegularExpressions;

namespace Authplane.Conformance;

/// <summary>
/// Loads catalog cases (id + title) and metadata (catalog id, version) from the shared
/// AuthPlane <c>oauth-sdk-conformance-catalog.yaml</c>.
/// </summary>
public static class ConformanceCatalog
{
    private const string CatalogFileName = "oauth-sdk-conformance-catalog.yaml";

    public static IReadOnlyList<ConformanceCase> LoadCases()
    {
        var path = ResolveCatalogPath();
        var text = File.ReadAllText(path);
        return ParseCaseIdsAndTitles(text);
    }

    public static ConformanceCatalogMeta LoadMeta()
    {
        var path = ResolveCatalogPath();
        var text = File.ReadAllText(path);

        // catalog_id / catalog_version are top-level scalar YAML values.
        var idMatch = Regex.Match(
            text,
            @"(?m)^catalog_id:\s*[""']?(?<id>[^""']+)[""']?\s*$",
            RegexOptions.Compiled);

        var verMatch = Regex.Match(
            text,
            @"(?m)^catalog_version:\s*[""']?(?<v>[^""']+)[""']?\s*$",
            RegexOptions.Compiled);

        var catalogId = idMatch.Success ? idMatch.Groups["id"].Value : "oauth-sdk-conformance-catalog";
        var catalogVersion = verMatch.Success ? verMatch.Groups["v"].Value : "";

        return new ConformanceCatalogMeta(catalogId, catalogVersion);
    }

    private static string ResolveCatalogPath()
    {
        var envPath = Environment.GetEnvironmentVariable("CONFORMANCE_CATALOG_PATH");
        if (!string.IsNullOrWhiteSpace(envPath) && File.Exists(envPath))
        {
            return envPath;
        }

        // Search upwards for `conformance/oauth-sdk-conformance-catalog.yaml`,
        // matching the layout of the AuthPlane/conformance repo.
        var dir = Directory.GetCurrentDirectory();
        for (var i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, "conformance", CatalogFileName);
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
            $"Missing conformance catalog `{CatalogFileName}`. " +
            $"Set CONFORMANCE_CATALOG_PATH or ensure `conformance/{CatalogFileName}` exists in an ancestor directory.");
    }

    private static List<ConformanceCase> ParseCaseIdsAndTitles(string yamlText)
    {
        var lines = yamlText.Split('\n');
        var inCases = false;

        // Matches: - id: "some-id"   or   - id: some-id
        var idRe = new Regex(@"^\s*-\s*id:\s*[""']?(?<id>[^""'\s]+)[""']?\s*$", RegexOptions.Compiled);
        // Matches: title: "some title"
        var titleRe = new Regex(@"^\s*title:\s*[""']?(?<title>[^""']+)[""']?\s*$", RegexOptions.Compiled);

        var currentId = (string?)null;
        var currentTitle = (string?)null;
        var cases = new List<ConformanceCase>();

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');

            if (!inCases)
            {
                if (line.Trim().Equals("cases:", StringComparison.Ordinal))
                {
                    inCases = true;
                }

                continue;
            }

            var idMatch = idRe.Match(line);
            if (idMatch.Success)
            {
                if (!string.IsNullOrWhiteSpace(currentId) && currentTitle is not null)
                {
                    cases.Add(new ConformanceCase(currentId, currentTitle));
                }

                currentId = idMatch.Groups["id"].Value;
                currentTitle = null;
                continue;
            }

            var titleMatch = titleRe.Match(line);
            if (titleMatch.Success && currentId is not null)
            {
                currentTitle = titleMatch.Groups["title"].Value.Trim();
            }
        }

        if (!string.IsNullOrWhiteSpace(currentId))
        {
            cases.Add(new ConformanceCase(currentId, currentTitle ?? currentId));
        }

        return cases;
    }
}

public sealed record ConformanceCase(string Id, string Title);

public sealed record ConformanceCatalogMeta(string CatalogId, string CatalogVersion);
