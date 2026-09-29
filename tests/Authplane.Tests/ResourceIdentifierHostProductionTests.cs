using Xunit;

namespace Authplane.Tests;

/// <summary>
/// RFC 3986 §3.2.2 — the <c>host</c> production is <c>IP-literal / IPv4address /
/// reg-name</c>, and <c>reg-name</c> admits only <c>unreserved / pct-encoded /
/// sub-delims</c>, all ASCII. An internationalized host belongs in a URI as its
/// A-label (<c>xn--caf-dma.example.com</c>).
///
/// No gate over the authority was a character production before this. The host's
/// only constraints were whitespace and control characters, the malformed-port
/// gate, and the userinfo gate, so <c>https://café.example.com/mcp</c> cleared
/// all of them: <c>é</c> is above 0x20 and not whitespace, there is no ':' to
/// read as a port and no '@' as userinfo, and <c>Uri.TryCreate</c> parses an IDN
/// host to a non-empty <c>Host</c>, so the absoluteness gate saw a scheme and a
/// host. The derivation slices the authority verbatim off the original string, so
/// the host rode into the derived metadata URL and out to unauthenticated clients
/// in the <c>resource_metadata</c> parameter of a <c>WWW-Authenticate</c>
/// challenge — bytes RFC 9110 §5.5 gives no interpretation for.
/// </summary>
/// <remarks>
/// Deliberately unmarked. The pinned catalog carries no case over the host
/// component — <c>rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host</c>
/// is the presence-of-a-host axis, not a character production over it — so
/// claiming a case here would name coverage that maps to nothing, which the
/// alignment guard rejects and rightly.
/// </remarks>
public sealed class ResourceIdentifierHostProductionTests
{
    [Theory]
    [InlineData("https://café.example.com/mcp")]              // Latin-1 supplement, prints
    [InlineData("https://例え.example.com/mcp")]                // CJK
    [InlineData("https://api​.example.com/mcp")]          // zero-width space, invisible
    [InlineData("https://api.exämple.com/mcp")]                // non-ASCII in a later label
    [InlineData("https://münchen.example.com:8443/mcp")]       // with a valid port after it
    [InlineData("https://café.example.com")]                   // no path at all
    public async Task CreateAsync_NonAsciiHost_ThrowsNamingTheHostProduction(string resource)
    {
        // No test server: the gate runs ahead of the issuer metadata fetch, so a
        // misconfigured identifier fails without a network round trip.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("host", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("§3.2.2", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The message has to tell the operator what to do about it — the gate
    /// deliberately does not convert to an A-label on their behalf, because
    /// encoding the host on the way into the derived URL alone would make it
    /// disagree with the identifier the served document emits verbatim.
    /// </summary>
    [Fact]
    public void GetDocumentUrl_NonAsciiHost_MessageNamesTheALabelRemedy()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://café.example.com/mcp"));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("A-label", ex.Message, StringComparison.Ordinal);
        Assert.Contains("xn--", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A non-ASCII host is named by code point, not printed. 'é' would render, but
    /// a zero-width space is invisible and half a surrogate pair is not a
    /// character — the same rule the path and query gates apply.
    /// </summary>
    [Fact]
    public void GetDocumentUrl_InvisibleNonAsciiHostCharacter_IsNamedByCodePoint()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api​.example.com/mcp"));

        Assert.Contains("U+200B", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GetDocumentUrl_MalformedPercentEscapeInHost_ThrowsNamingTheEscape()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api%zz.example.com/mcp"));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("host", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("percent-encoding", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The A-label form is what the gate is steering operators towards, so it has
    /// to derive byte-exact.
    /// </summary>
    [Fact]
    public void GetDocumentUrl_ALabelHost_IsAcceptedAndDerivedByteExact()
    {
        Assert.Equal(
            "https://xn--caf-dma.example.com/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://xn--caf-dma.example.com/mcp"));
    }

    /// <summary>
    /// Everything inside the production stays accepted and byte-exact. A gate that
    /// rejected any of these would be worse than no gate: these are ordinary
    /// configurations, and the IPv6 and zone-identifier rows are exactly the shapes
    /// a naive hex-only reading of the IP-literal production turns away.
    /// </summary>
    [Theory]
    [InlineData("https://api.example.com/mcp")]
    [InlineData("https://api.example.com:8443/mcp")]
    [InlineData("http://localhost:8080/mcp")]
    [InlineData("http://127.0.0.1:8080/mcp")]
    [InlineData("https://[::1]:8443/mcp")]
    [InlineData("https://[fe80::1]/mcp")]
    [InlineData("https://[fe80::1%25eth0]/mcp")]  // RFC 6874 zone id: 'eth0' is not all hex
    [InlineData("https://api-1.sub_domain.example.com/mcp")]
    [InlineData("https://api.example.com/mcp?tenant=acme")]
    [InlineData("https://api.example.com/mcp/a@b")]  // '@' in the path is data, not userinfo
    public void GetDocumentUrl_HostInsideTheProduction_StaysAccepted(string resource)
    {
        var ex = Record.Exception(() => OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Null(ex);
    }

    /// <summary>
    /// The zone identifier survives byte-exact rather than being dropped — the
    /// property the derivation's string slice exists to preserve, re-asserted here
    /// because the new gate scans that same slice and must not disturb it.
    /// </summary>
    [Fact]
    public void GetDocumentUrl_Ipv6ZoneIdentifier_IsPreservedByteExact()
    {
        Assert.Equal(
            "https://[fe80::1%25eth0]/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://[fe80::1%25eth0]/mcp"));
    }

    /// <summary>
    /// A non-ASCII character outside the host must not be blamed on the host. The
    /// path gate owns its own component, and reporting the wrong one sends the
    /// operator to the wrong part of their configuration.
    /// </summary>
    [Fact]
    public void GetDocumentUrl_NonAsciiInPath_IsStillBlamedOnThePath()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/café"));

        Assert.Contains("path", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("§3.2.2", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// An authority that is userinfo and nothing else has no host for this gate to
    /// read a character out of. The gate has to hand the identifier on rather than
    /// index past the end of it: it runs ahead of the absoluteness and userinfo
    /// gates at every site, so it is first to see the input, and a throw with no
    /// message replaces the diagnosis the operator used to get. The rows below have
    /// no path, query or fragment either — with any of the three the authority ends
    /// before the end of the string and the index is in bounds, which is why this
    /// shape and only this shape needs the boundary check.
    /// </summary>
    [Theory]
    [InlineData("https://user@")]
    [InlineData("https://@")]
    [InlineData("https://svc:s3cr3t@")]
    [InlineData("https://user@:8443")]  // port delimiter, still no host
    public async Task CreateAsync_AuthorityIsUserInfoOnly_ReportsTheMissingHost(string resource)
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://user@")]
    [InlineData("https://@")]
    [InlineData("https://svc:s3cr3t@")]
    [InlineData("https://user@:8443")]
    public void GetDocumentUrl_AuthorityIsUserInfoOnly_ReportsTheMissingHost(string resource)
    {
        // Public API, and its documented contract is ArgumentException: asserting
        // the exact type is the point of the row, not merely that it does not
        // return a URL.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetDocumentUrl_AuthorityIsUserInfoOnly_DoesNotEchoTheCredential()
    {
        // The shape carries credentials, so the gate that ends up reporting it must
        // hold to the same non-echo rule as the userinfo gate.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://svc:s3cr3t@"));

        Assert.DoesNotContain("s3cr3t", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A userinfo carrying a non-ASCII character is reported as userinfo, not as a
    /// bad host: the userinfo gate runs first, and its rejection does not echo the
    /// identifier because it can carry credentials.
    /// </summary>
    [Fact]
    public void GetDocumentUrl_NonAsciiInUserInfo_IsStillBlamedOnUserInfo()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://ü:pw@api.example.com/mcp"));

        Assert.Contains("userinfo", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
