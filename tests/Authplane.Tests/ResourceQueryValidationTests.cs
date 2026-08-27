using Xunit;

namespace Authplane.Tests;

/// <summary>
/// RFC 3986 §3.4 — the resource identifier's query must be a valid
/// <c>query</c> production. The derived well-known URL carries the query
/// verbatim from the original identifier string, so a query outside the
/// production yields an advertised URL that is not a URI and that no client
/// can fetch. It is rejected at construction, where the operator can act on
/// it, rather than at request time.
///
/// Not a header-injection guard: the MCP middleware's challenge escaper
/// already handles '"', '\' and CTLs, and did so before the query was
/// preserved.
/// </summary>
public sealed class ResourceQueryValidationTests
{
    [Theory]
    [InlineData("https://api.example.com/mcp?a=\"b\"", "query")]
    // A space in the query is whitespace first: the whitespace gate runs
    // ahead of the query gate at every site, and its message already names
    // the fix (percent-encode as %20).
    [InlineData("https://api.example.com/mcp?a=b c", "whitespace")]
    [InlineData("https://api.example.com/mcp?a=%zz", "query")]
    [InlineData("https://api.example.com/mcp?a=%2", "query")]
    [InlineData("https://api.example.com/mcp?a=b%", "query")]
    public async Task CreateAsync_InvalidQuery_Throws(string resource, string expectedInMessage)
    {
        // No test server: the guard runs ahead of the issuer metadata fetch, so
        // a misconfigured identifier fails without a network round trip.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains(expectedInMessage, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://api.example.com/mcp?a=\"b\"")]
    [InlineData("https://api.example.com/mcp?a=%zz")]
    public void GetDocumentUrl_InvalidQuery_Throws(string resourceUrl)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resourceUrl));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("query", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetDocumentUrl_LegalQueryCharacters_Accepted()
    {
        // Every non-pct-encoded character the production allows: unreserved,
        // sub-delims, and ":" / "@" / "/" / "?" — plus a well-formed escape.
        const string query = "?q=-._~!$&'()*+,;=:@/?&esc=%7E";

        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp" + query,
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp" + query));
    }
}
