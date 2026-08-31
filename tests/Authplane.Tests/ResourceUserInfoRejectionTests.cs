using Xunit;

namespace Authplane.Tests;

/// <summary>
/// RFC 9110 §4.2.4 — the userinfo subcomponent must not be generated in
/// http(s) URIs. Before this gate an identifier with userinfo passed
/// construction (the absoluteness gate only checks scheme and host) and every
/// request then died on the userinfo backstop inside
/// <c>GetDocumentUrl</c> — an unhandled per-request exception instead of a
/// startup error.
/// </summary>
public sealed class ResourceUserInfoRejectionTests
{
    [Theory]
    // Explicit credentials in an https identifier.
    [InlineData("https://svc:s3cr3t@api.example.com/mcp")]
    // A scheme whose syntax fills the userinfo slot: mailto parses with
    // UserInfo "ops" and Host "example.com", so it clears the absoluteness
    // gate and must be stopped here.
    [InlineData("mailto:ops@example.com")]
    public async Task CreateAsync_UserInfoInResource_Throws(string resource)
    {
        // No test server: the guard runs ahead of the issuer metadata fetch, so
        // a misconfigured identifier fails without a network round trip.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("userinfo", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetDocumentUrl_UserInfoBackstop_StillThrows()
    {
        // The public-API backstop inside GetDocumentUrl stays in place for
        // direct callers that bypass the constructor gates. It is the same
        // ResourceIdentifiers.ThrowIfUserInfo the constructor path runs, so
        // both sites use identical wording.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://svc:s3cr3t@api.example.com/mcp"));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("userinfo", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RFC 9110", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GetDocumentUrl_UserInfoReportedBeforeQuery()
    {
        // GetDocumentUrl runs the gates in the constructor path's order —
        // fragment, whitespace/backslash, absoluteness, userinfo, query — so
        // an identifier carrying both userinfo and a malformed query reports
        // userinfo from both sites, not "userinfo" from one and "query" from
        // the other.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(
                "https://svc:s3cr3t@api.example.com/mcp?a=%zz"));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("userinfo", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("query", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
