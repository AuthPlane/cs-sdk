using System.Globalization;
using System.Text;
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

    // Matches a case list item's `- id:` key; the value goes through the same scalar
    // parsing as titles, so an id and a title accept exactly the same quoting.
    private static readonly Regex IdRe = new(
        @"^(?<indent>\s*)-\s*id:\s*(?<rest>.*)$", RegexOptions.Compiled);

    // Matches a top-level key (e.g. `usage_guidance:`), which ends the cases block.
    private static readonly Regex TopLevelKeyRe = new(
        @"^[A-Za-z_][\w-]*:", RegexOptions.Compiled);

    // Matches the start of any list item, so a case item whose first key is not `id`
    // is detected instead of being folded into the previous case.
    private static readonly Regex ListItemRe = new(@"^(?<indent>\s*)-(\s|$)", RegexOptions.Compiled);

    // Matches the title key of a case; the value needs scalar parsing, not a regex.
    private static readonly Regex TitleRe = new(@"^(?<indent>\s*)title:\s*(?<rest>.*)$", RegexOptions.Compiled);

    /// <summary>
    /// Parses the <c>cases:</c> block of the catalog into (id, title) pairs. Public so the
    /// parser can be exercised directly against crafted catalog shapes.
    /// </summary>
    /// <remarks>
    /// A shape this parser does not understand must never degrade to a skipped case: the
    /// alignment guard treats an absent case as nothing-to-check, so a silently dropped case
    /// leaves the guard green while it under-checks — the same failure mode the guard's own
    /// zero-case check exists to catch, one case at a time instead of all at once. Hence a
    /// case without a <c>title:</c> keeps its id as the title (in any position), and a list
    /// item or quoted scalar the parser cannot make sense of throws instead of being skipped.
    /// </remarks>
    public static IReadOnlyList<ConformanceCase> ParseCaseIdsAndTitles(string yamlText)
    {
        var lines = yamlText.Split('\n');
        var inCases = false;

        var currentId = (string?)null;
        var currentTitle = (string?)null;
        var caseIndent = (int?)null;
        var fieldIndent = (int?)null;
        var cases = new List<ConformanceCase>();

        void FlushCurrentCase()
        {
            if (!string.IsNullOrWhiteSpace(currentId))
            {
                // Title falls back to the id: the alignment guard keys on ids, and a case
                // must stay visible to it even when the title is missing or empty.
                cases.Add(new ConformanceCase(
                    currentId,
                    string.IsNullOrWhiteSpace(currentTitle) ? currentId : currentTitle));
            }

            currentId = null;
            currentTitle = null;
        }

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');

            if (!inCases)
            {
                if (line.Trim().Equals("cases:", StringComparison.Ordinal))
                {
                    inCases = true;
                }

                continue;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            // A full-line comment carries no content at any indent; in particular a
            // column-0 comment is not a top-level key and must not end the cases block.
            if (line.TrimStart().StartsWith('#'))
            {
                continue;
            }

            if (!char.IsWhiteSpace(line[0]) && line[0] != '-')
            {
                // Only a top-level key (e.g. `usage_guidance:`) or the document-end
                // marker ends the cases block. Anything else at column 0 is a shape this
                // parser does not understand, and treating it as the end of the block
                // would silently drop every remaining case.
                if (TopLevelKeyRe.IsMatch(line) || line.TrimEnd() == "...")
                {
                    break;
                }

                throw new FormatException(
                    $"Unrecognized column-0 line at line {i + 1} inside the cases block: " +
                    $"`{line.Trim()}`. Treating it as the end of the block would hide every " +
                    "remaining case from the catalog-alignment guard.");
            }

            var listItemMatch = ListItemRe.Match(line);
            if (listItemMatch.Success)
            {
                var indent = listItemMatch.Groups["indent"].Value.Length;

                // The first list item after `cases:` fixes the case-item indentation.
                // Deeper items belong to nested lists (standard_refs, variants, ...).
                caseIndent ??= indent;
                if (indent > caseIndent.Value)
                {
                    continue;
                }

                var idMatch = IdRe.Match(line);
                if (!idMatch.Success)
                {
                    throw new FormatException(
                        $"Unrecognized case list item at line {i + 1}: `{line.Trim()}`. Every " +
                        "catalog case starts with `- id:`; skipping this item would hide it from " +
                        "the catalog-alignment guard.");
                }

                FlushCurrentCase();
                fieldIndent = null;
                var id = ParseScalar(lines, ref i, idMatch.Groups["rest"].Value.Trim(), caseIndent.Value);
                if (string.IsNullOrWhiteSpace(id))
                {
                    throw new FormatException(
                        $"Empty case id at line {i + 1}; a case without an id is invisible " +
                        "to the catalog-alignment guard.");
                }

                currentId = id;
                continue;
            }

            // The first field line after a case's `- id:` fixes that case's field
            // indentation. yamllint pins two-space indents upstream, but deriving the
            // value from the file itself keeps the parser correct for any valid indent
            // width instead of assuming `caseIndent + 2`.
            var lineIndent = line.Length - line.TrimStart().Length;
            if (currentId is not null && fieldIndent is null &&
                caseIndent is not null && lineIndent > caseIndent.Value)
            {
                fieldIndent = lineIndent;
            }

            // Only a title key at the current case's own field indentation belongs to the
            // case; identically named keys nested deeper (e.g. inside `setup:`) do not.
            var titleMatch = TitleRe.Match(line);
            if (titleMatch.Success && currentId is not null && currentTitle is null &&
                caseIndent is not null && titleMatch.Groups["indent"].Value.Length == fieldIndent)
            {
                currentTitle = ParseScalar(lines, ref i, titleMatch.Groups["rest"].Value.Trim(), caseIndent.Value);
            }
        }

        FlushCurrentCase();
        return cases;
    }

    /// <summary>
    /// Parses a YAML flow scalar (double-quoted, single-quoted, or plain) starting at
    /// <paramref name="rest"/>, consuming continuation lines of a wrapped quoted scalar.
    /// </summary>
    /// <remarks>
    /// Covers the styles the catalog actually uses: double-quoted values may contain
    /// apostrophes, the JSON escape set plus <c>\ </c> and <c>\uXXXX</c>, and — as the
    /// emitter writes every long scalar in the file — wrap with an escaped line break plus
    /// an escaped leading space on the continuation line. Single-quoted values escape an
    /// apostrophe by doubling it. Plain scalars lose their inline comment. Everything else
    /// throws rather than degrading: an escape outside that set, a block scalar indicator
    /// (the emitter pins double-quoted style, so <c>|</c>/<c>&gt;</c> never legitimately
    /// arrive), a quoted scalar that never closes, and a continuation line that leaves the
    /// case item (indent at or below <paramref name="caseIndent"/> — which also covers the
    /// next `- id:` item) instead of silently swallowing the lines in between.
    /// </remarks>
    private static string ParseScalar(string[] lines, ref int i, string rest, int caseIndent)
    {
        if (rest.Length == 0)
        {
            return rest;
        }

        if (rest[0] == '|' || rest[0] == '>')
        {
            throw new FormatException(
                $"Block scalar (`{rest}`) at line {i + 1} is not supported; returning the " +
                "indicator as the value would silently corrupt it. The catalog emitter pins " +
                "double-quoted style.");
        }

        if (rest[0] != '"' && rest[0] != '\'')
        {
            // Plain scalar: a `#` at the start or preceded by whitespace begins a comment.
            for (var p = 0; p < rest.Length; p++)
            {
                if (rest[p] == '#' && (p == 0 || char.IsWhiteSpace(rest[p - 1])))
                {
                    return rest.Substring(0, p).TrimEnd();
                }
            }

            return rest;
        }

        var quote = rest[0];
        var value = new StringBuilder();
        var startLine = i + 1;
        var chunk = rest.Substring(1);

        while (true)
        {
            var closed = false;
            var joinNextWithoutSpace = false;
            for (var p = 0; p < chunk.Length; p++)
            {
                var c = chunk[p];
                if (quote == '"' && c == '\\')
                {
                    if (p == chunk.Length - 1)
                    {
                        // Escaped line break: join the continuation line directly.
                        joinNextWithoutSpace = true;
                        break;
                    }

                    var escaped = chunk[p + 1];
                    switch (escaped)
                    {
                        case '"' or '\\' or '/' or ' ':
                            value.Append(escaped);
                            break;
                        case 'n':
                            value.Append('\n');
                            break;
                        case 't':
                            value.Append('\t');
                            break;
                        case 'r':
                            value.Append('\r');
                            break;
                        case '0':
                            value.Append('\0');
                            break;
                        case 'u':
                            if (p + 6 > chunk.Length ||
                                !ushort.TryParse(
                                    chunk.AsSpan(p + 2, 4),
                                    NumberStyles.HexNumber,
                                    CultureInfo.InvariantCulture,
                                    out var codePoint))
                            {
                                throw new FormatException(
                                    $"Malformed \\uXXXX escape in double-quoted scalar at line {i + 1}.");
                            }

                            value.Append((char)codePoint);
                            p += 4;
                            break;
                        default:
                            throw new FormatException(
                                $"Unsupported escape `\\{escaped}` in double-quoted scalar at " +
                                $"line {i + 1}; passing the character through unescaped would " +
                                "silently corrupt the value.");
                    }

                    p++;
                    continue;
                }

                if (c == quote)
                {
                    if (quote == '\'' && p < chunk.Length - 1 && chunk[p + 1] == '\'')
                    {
                        // Single-quoted style escapes an apostrophe by doubling it.
                        value.Append('\'');
                        p++;
                        continue;
                    }

                    closed = true;
                    break;
                }

                value.Append(c);
            }

            if (closed)
            {
                return value.ToString();
            }

            if (i + 1 >= lines.Length)
            {
                throw new FormatException(
                    $"Unterminated {(quote == '"' ? "double" : "single")}-quoted scalar starting " +
                    $"at line {startLine}; refusing to return a truncated value.");
            }

            // A continuation line must stay inside the case item. An indent at or below
            // the case-item indent (which includes the next `- id:` item) means the quote
            // never closed; consuming lines until the next `"` in the file would swallow
            // whole cases into this value.
            var next = lines[i + 1].TrimEnd('\r');
            if (next.Length - next.TrimStart().Length <= caseIndent)
            {
                throw new FormatException(
                    $"Unterminated {(quote == '"' ? "double" : "single")}-quoted scalar starting " +
                    $"at line {startLine}: line {i + 2} leaves the case item before the closing " +
                    "quote; refusing to return a truncated value.");
            }

            if (!joinNextWithoutSpace)
            {
                // An unescaped line break inside a quoted scalar folds to a single space.
                value.Append(' ');
            }

            i++;
            chunk = lines[i].TrimEnd('\r').TrimStart();
        }
    }
}

public sealed record ConformanceCase(string Id, string Title);

public sealed record ConformanceCatalogMeta(string CatalogId, string CatalogVersion);
