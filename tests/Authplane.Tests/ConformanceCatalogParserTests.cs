using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Pins the catalog parser against case shapes that used to be dropped silently. A dropped
/// case never reaches <see cref="ConformanceCatalogAlignment.AssertCatalogAndMarkersAgree"/>,
/// so the alignment guard under-checks without turning anything red — the same failure mode
/// its zero-case guard exists to prevent, one case at a time instead of all at once.
/// </summary>
public sealed class ConformanceCatalogParserTests
{
    [Fact]
    public void CaseWithoutTitle_InNonFinalPosition_IsKeptWithIdAsTitle()
    {
        var yaml = """
            cases:
              - id: "first-case"
                title: "First"
              - id: "case-without-title"
                priority: "high"
                standard_refs:
                  - "RFC8414"
              - id: "last-case"
                title: "Last"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal(["first-case", "case-without-title", "last-case"], cases.Select(c => c.Id));
        Assert.Equal("case-without-title", cases[1].Title);
    }

    [Fact]
    public void CaseWithoutTitle_InFinalPosition_IsKeptWithIdAsTitle()
    {
        var yaml = """
            cases:
              - id: "first-case"
                title: "First"
              - id: "last-case-without-title"
                priority: "low"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal(["first-case", "last-case-without-title"], cases.Select(c => c.Id));
        Assert.Equal("last-case-without-title", cases[1].Title);
    }

    [Fact]
    public void TitleWithApostrophe_KeepsTheCaseAndTheFullTitle()
    {
        var yaml = """
            cases:
              - id: "rfc9728-well-known-url-must-preserve-the-resource-query-component"
                title: "Preserve the resource identifier's query component in the derived well-known PRM URL"
              - id: "last-case"
                title: "Last"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal(2, cases.Count);
        Assert.Equal(
            "Preserve the resource identifier's query component in the derived well-known PRM URL",
            cases[0].Title);
    }

    [Fact]
    public void TitleSingleQuoted_UnescapesTheDoubledApostrophe()
    {
        var yaml = """
            cases:
              - id: "single-quoted-case"
                title: 'Reject a proof that isn''t bound to the request'
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal("Reject a proof that isn't bound to the request", Assert.Single(cases).Title);
    }

    [Fact]
    public void TitleWithEscapedDoubleQuote_UnescapesIt()
    {
        var yaml = """
            cases:
              - id: "escaped-quote-case"
                title: "Reject the \"none\" algorithm"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal("Reject the \"none\" algorithm", Assert.Single(cases).Title);
    }

    [Fact]
    public void TitleWrappedAcrossLines_IsJoinedLikeTheEmitterWroteIt()
    {
        // The catalog's emitter wraps long double-quoted scalars with an escaped line break
        // plus an escaped leading space on the continuation line (`\` + newline + `\ `), as
        // every long requirement_summary in the real file shows. A future long title will
        // wrap the same way.
        var yaml = "cases:\n" +
            "  - id: \"wrapped-title-case\"\n" +
            "    title: \"A title long enough that the emitter wrapped it onto the\\\n" +
            "      \\ next line\"\n" +
            "  - id: \"last-case\"\n" +
            "    title: \"Last\"\n";

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal(2, cases.Count);
        Assert.Equal("A title long enough that the emitter wrapped it onto the next line", cases[0].Title);
    }

    [Fact]
    public void UnterminatedQuotedTitle_AtEndOfFile_ThrowsInsteadOfDegradingSilently()
    {
        var yaml = """
            cases:
              - id: "broken-case"
                title: "never closed
            """;

        Assert.Throws<FormatException>(() => ConformanceCatalog.ParseCaseIdsAndTitles(yaml));
    }

    [Fact]
    public void UnterminatedQuotedTitle_WithCasesAfterIt_ThrowsInsteadOfSwallowingThem()
    {
        // Without the continuation bound, the next `"` in the file (inside `- id: "b"`)
        // closes the scalar and case b is swallowed into the title of case a.
        var yaml = """
            cases:
              - id: "a"
                title: "oops unterminated
                priority: high
              - id: "b"
                title: "B"
              - id: "c"
                title: "C"
            """;

        Assert.Throws<FormatException>(() => ConformanceCatalog.ParseCaseIdsAndTitles(yaml));
    }

    [Fact]
    public void ColumnZeroComment_BetweenCases_DoesNotEndTheCasesBlock()
    {
        var yaml = """
            cases:
              - id: "a"
                title: "A"
            # regenerated section below
              - id: "b"
                title: "B"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal(["a", "b"], cases.Select(c => c.Id));
        Assert.Equal(["A", "B"], cases.Select(c => c.Title));
    }

    [Fact]
    public void UnrecognizedColumnZeroLine_ThrowsInsteadOfEndingTheCasesBlock()
    {
        var yaml = """
            cases:
              - id: "a"
                title: "A"
            *anchor-alias
              - id: "b"
                title: "B"
            """;

        Assert.Throws<FormatException>(() => ConformanceCatalog.ParseCaseIdsAndTitles(yaml));
    }

    [Fact]
    public void ParsingStops_AtTheDocumentEndMarker()
    {
        var yaml = """
            cases:
              - id: "only-case"
                title: "Only"
            ...
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal("only-case", Assert.Single(cases).Id);
    }

    [Fact]
    public void TitleEscapes_DecodeTheJsonEscapeSetAndUnicode()
    {
        var yaml = """
            cases:
              - id: "escaped-case"
                title: "R\u00e9ject the caf\u00e9\ttoken\nnow"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal("Réject the café\ttoken\nnow", Assert.Single(cases).Title);
    }

    [Fact]
    public void TitleWithUnknownEscape_ThrowsInsteadOfMangling()
    {
        var yaml = """
            cases:
              - id: "bad-escape-case"
                title: "not a real \q escape"
            """;

        Assert.Throws<FormatException>(() => ConformanceCatalog.ParseCaseIdsAndTitles(yaml));
    }

    [Fact]
    public void BlockScalarTitle_ThrowsInsteadOfYieldingTheIndicator()
    {
        var yaml = """
            cases:
              - id: "block-scalar-case"
                title: >-
                  A folded title the parser does not understand
              - id: "last-case"
                title: "Last"
            """;

        Assert.Throws<FormatException>(() => ConformanceCatalog.ParseCaseIdsAndTitles(yaml));
    }

    [Fact]
    public void IdWithApostrophe_ParsesLikeATitleWould()
    {
        var yaml = """
            cases:
              - id: "client's-id"
                title: "Apostrophes in ids and titles parse the same way"
            """;

        var only = Assert.Single(ConformanceCatalog.ParseCaseIdsAndTitles(yaml));
        Assert.Equal("client's-id", only.Id);
    }

    [Fact]
    public void PlainTitle_LosesItsInlineComment()
    {
        var yaml = """
            cases:
              - id: "plain-title-case"
                title: Some title  # trailing note
            """;

        Assert.Equal("Some title", Assert.Single(ConformanceCatalog.ParseCaseIdsAndTitles(yaml)).Title);
    }

    [Fact]
    public void WiderFieldIndent_StillBindsTheTitleToTheCase()
    {
        // yamllint pins two-space indents upstream, but the field indent is derived from
        // the file, not assumed to be caseIndent + 2.
        var yaml = """
            cases:
              -   id: "wide-indent-case"
                  title: "Wide"
              -   id: "last-case"
                  title: "Last"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal(["Wide", "Last"], cases.Select(c => c.Title));
    }

    [Fact]
    public void CaseListItemThatDoesNotStartWithId_ThrowsInsteadOfMergingIntoThePreviousCase()
    {
        var yaml = """
            cases:
              - id: "first-case"
                title: "First"
              - title: "This item does not lead with its id"
                id: "would-be-dropped"
            """;

        Assert.Throws<FormatException>(() => ConformanceCatalog.ParseCaseIdsAndTitles(yaml));
    }

    [Fact]
    public void NestedListItems_DoNotEndOrCorruptTheCurrentCase()
    {
        var yaml = """
            cases:
              - id: "case-with-nested-lists"
                title: "Nested"
                standard_refs:
                  - "RFC8414"
                  - "RFC9068"
                setup:
                  variants:
                    - configured_issuer: "https://auth.example.com"
                      expected_outcome: "reject"
              - id: "last-case"
                title: "Last"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        Assert.Equal(["case-with-nested-lists", "last-case"], cases.Select(c => c.Id));
        Assert.Equal("Nested", cases[0].Title);
    }

    [Fact]
    public void ParsingStops_AtTheNextTopLevelKey()
    {
        var yaml = """
            cases:
              - id: "only-case"
                title: "Only"
            usage_guidance:
              notes:
                - "not a case"
              title: "not a case title"
            """;

        var cases = ConformanceCatalog.ParseCaseIdsAndTitles(yaml);

        var only = Assert.Single(cases);
        Assert.Equal("only-case", only.Id);
        Assert.Equal("Only", only.Title);
    }

    [Fact]
    public void RealCatalog_ParsesEveryCaseWithACleanTitle()
    {
        var cases = ConformanceCatalog.LoadCases();

        Assert.NotEmpty(cases);
        Assert.Equal(cases.Count, cases.Select(c => c.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.All(cases, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Title));
            // A trailing backslash or quote is the footprint of a mis-parsed quoted scalar.
            Assert.DoesNotContain('\\', c.Title);
            Assert.False(c.Title.EndsWith('"'));
        });
    }
}
