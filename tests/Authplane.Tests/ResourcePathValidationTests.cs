using Xunit;

namespace Authplane.Tests;

/// <summary>
/// RFC 3986 §3.3 — the resource identifier's path must be a valid
/// <c>path</c> production. The derived well-known URL carries the path
/// verbatim from the original identifier string, so a path outside the
/// production — a raw non-ASCII segment, an unencoded delimiter, a malformed
/// percent-escape — yields an advertised URL that is not a URI (RFC 3986 §2,
/// RFC 8707 §2) and that no client can fetch. It is rejected at construction,
/// where the operator can act on it, rather than at request time — before it
/// can reach a <c>WWW-Authenticate</c> field value, whose RFC 9110 §5.5
/// grammar has no interpretation for non-ASCII bytes.
///
/// The other half of the contract is what the gate does not touch: every
/// well-formed percent-encoding stays byte-exact through the derivation,
/// asserted in <see cref="OAuthProtectedResourceMetadataTests"/>.
/// </summary>
public sealed class ResourcePathValidationTests
{
    [Theory]
    [InlineData("https://api.example.com/café", "path")]
    [InlineData("https://api.example.com/m\u200Bcp", "path")]
    [InlineData("https://api.example.com/m%zzcp", "path")]
    [InlineData("https://api.example.com/m%2", "path")]
    // The escape is malformed because the path is terminal at '?': the two
    // characters after '%' must be hex digits *inside the path*.
    [InlineData("https://api.example.com/m%2?x=1", "path")]
    [InlineData("https://api.example.com/m<cp", "path")]
    [InlineData("https://api.example.com/m{cp}", "path")]
    [InlineData("https://api.example.com/m|cp", "path")]
    // A space in the path is whitespace first: the whitespace gate runs
    // ahead of the path gate at every site, and its message already names
    // the fix (percent-encode as %20). Same for the backslash.
    [InlineData("https://api.example.com/my mcp", "whitespace")]
    [InlineData("https://api.example.com/m\\cp", "backslash")]
    public async Task CreateAsync_InvalidPath_Throws(string resource, string expectedInMessage)
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
    [InlineData("https://api.example.com/café")]
    [InlineData("https://api.example.com/m\u200Bcp")]
    [InlineData("https://api.example.com/m%zzcp")]
    [InlineData("https://api.example.com/m<cp")]
    public void GetDocumentUrl_InvalidPath_Throws(string resourceUrl)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resourceUrl));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("path", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetDocumentUrl_LegalPathCharacters_Accepted()
    {
        // Every non-pct-encoded character the production allows: unreserved,
        // sub-delims, ":" / "@", and the "/" delimiter — plus a well-formed
        // escape, preserved byte-exact.
        const string path = "/-._~!$&'()*+,;=:@/x%7E";

        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource" + path,
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com" + path));
    }

    [Fact]
    public void GetDocumentUrl_NonAsciiInQuery_IsAlsoRejected()
    {
        // The query production is ASCII-only too — char.IsAsciiLetterOrDigit
        // and the sub-delims list admit no raw non-ASCII — so U+200B has no
        // hiding place one component over.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?a=\u200B"));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("query", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
