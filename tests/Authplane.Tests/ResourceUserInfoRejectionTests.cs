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
    // The empty form, which Uri.UserInfo cannot distinguish from "no userinfo":
    // RFC 9110 §4.2.4 forbids generating the subcomponent, not merely non-empty
    // credentials.
    [InlineData("https://@api.example.com/mcp")]
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

    /// <summary>
    /// The gate is scoped to the authority, because that is the only place RFC 3986
    /// §3.2 puts a userinfo subcomponent. An opaque identifier has no authority, so
    /// its '@' is data and this gate must not claim it — it is refused, but for the
    /// reason it is actually refused for: no host, so no metadata URL derives from
    /// it. The distinction is the whole value of the error message, which is what
    /// tells the operator what to change.
    /// </summary>
    [Theory]
    [InlineData("mailto:ops@example.com")]
    [InlineData("urn:example:api")]
    public async Task CreateAsync_OpaqueIdentifier_IsNotReportedAsUserInfo(string resource)
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("userinfo", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("mailto:ops@example.com")]
    [InlineData("urn:example:api")]
    public void GetDocumentUrl_OpaqueIdentifier_IsNotReportedAsUserInfo(string resource)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("userinfo", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// An '@' outside the authority is data (RFC 3986 §§3.3, 3.4) and stays
    /// accepted — the other half of scoping the gate. A guard that scanned the
    /// whole string would turn these away.
    /// </summary>
    [Theory]
    [InlineData("https://api.example.com/mcp/a@b")]
    [InlineData("https://api.example.com/mcp?to=a@b")]
    public void GetDocumentUrl_AtSignOutsideTheAuthority_StaysAccepted(string resource)
    {
        var ex = Record.Exception(() => OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Null(ex);
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
