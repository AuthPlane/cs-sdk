using Xunit;

namespace Authplane.Tests;

/// <summary>
/// RFC 8707 §2 — "The URI MUST NOT include a fragment component" — and the
/// matching RFC 9728 §1.2 definition of the resource identifier.
///
/// Before this gate the fragment was silently dropped: the derived well-known
/// URL is built from the authority plus <c>Uri.AbsolutePath</c>, which never
/// carries a fragment, while the PRM <c>resource</c> field echoes the
/// identifier verbatim. The served document therefore named a resource that
/// differed from its own URL, and RFC 9728 §3.3 requires a conformant client to
/// discard such a response — a silent interop failure with nothing logged or
/// raised server-side.
/// </summary>
public sealed class ResourceFragmentRejectionTests
{
    [Theory]
    [InlineData("https://api.example.com/mcp#section")]
    [InlineData("https://api.example.com/mcp#")]
    [InlineData("https://api.example.com/#frag")]
    [InlineData("https://api.example.com#frag")]
    public async Task CreateAsync_FragmentInResource_Throws(string resource)
    {
        // No test server: the guard runs ahead of the issuer metadata fetch, so
        // a misconfigured identifier fails without a network round trip.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("fragment", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://api.example.com/mcp#section")]
    [InlineData("https://api.example.com#frag")]
    public void ProtectedResourceMetadataBuild_FragmentInResource_Throws(string resource)
    {
        // The emission half. ToRfc9728Json writes `resource` verbatim, so
        // without this gate the mismatch above is constructible through public
        // API even though the derivation half rejects it.
        var ex = Assert.Throws<ArgumentException>(() =>
            ProtectedResourceMetadata.Build(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("fragment", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProtectedResourceMetadataCtor_FragmentInResource_Throws()
    {
        // Build delegates here, but the constructor is public in its own right.
        var ex = Assert.Throws<ArgumentException>(() =>
            new ProtectedResourceMetadata(
                resource: "https://api.example.com/mcp#section",
                issuer: "https://auth.example.com",
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
    }

    [Fact]
    public void FragmentRejection_MessageNamesTheOffendingIdentifier()
    {
        // A process can host several resources against one AS, so paramName
        // alone does not say which identifier failed. Parity with the sibling
        // SDKs, all of which name something.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp#anchor-value"));

        Assert.Contains("https://api.example.com/mcp", ex.Message, StringComparison.Ordinal);
        // The rejected component itself is not echoed back.
        Assert.DoesNotContain("anchor-value", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FragmentRejection_MessageElidesUserInfo()
    {
        // The identifier is operator-supplied and can carry credentials; the
        // message goes to logs. Everything up to the authority's '@' is cut.
        var ex = Assert.Throws<ArgumentException>(() =>
            new ProtectedResourceMetadata(
                resource: "https://alice:s3cret@api.example.com/mcp#anchor-value",
                issuer: "https://auth.example.com",
                scopes: Array.Empty<string>()));

        Assert.DoesNotContain("s3cret", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", ex.Message, StringComparison.Ordinal);
        Assert.Contains("https://api.example.com/mcp", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    // An unescaped '@' in the userinfo: RFC 3986 §3.2.1 forbids it, so the real
    // delimiter is the *last* '@' in the authority. A scan that took the first one
    // shipped the tail of the password into the message.
    [InlineData("https://alice:s3cret@ret@api.example.com/mcp#anchor-value")]
    // An unescaped '/' in the password moves the authority's terminating '/' before
    // the '@', so a bounded scan elided nothing at all and printed the credential
    // whole.
    [InlineData("https://alice:pa/ss3cret@api.example.com/mcp#anchor-value")]
    public void FragmentRejection_MalformedUserInfo_IsNotEchoed(string resource)
    {
        // This formatter runs ahead of any validation — nothing in this change
        // rejects a malformed identifier before it — so malformed is the expected
        // input, not the edge case. Neither shape parses, and an identifier that
        // cannot be shown to be credential-free is refused rather than echoed.
        var ex = Assert.Throws<ArgumentException>(() =>
            new ProtectedResourceMetadata(
                resource: resource,
                issuer: "https://auth.example.com",
                scopes: Array.Empty<string>()));

        Assert.DoesNotContain("s3cret", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", ex.Message, StringComparison.Ordinal);
        Assert.Contains("(unparseable identifier)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FragmentRejection_OpaqueIdentifier_IsNamedInFull()
    {
        // An identifier with no authority has nowhere to hide a credential, and
        // refusing to name it would cost the operator the one thing the message is
        // for. Only the fragment is dropped.
        var ex = Assert.Throws<ArgumentException>(() =>
            new ProtectedResourceMetadata(
                resource: "urn:example:api#anchor-value",
                issuer: "https://auth.example.com",
                scopes: Array.Empty<string>()));

        Assert.Contains("urn:example:api", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("anchor-value", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FragmentRejection_AuthoritylessScheme_IsNotRebuiltWithASynthesizedSlashSlash()
    {
        // `mailto:` puts data in the authority slot without a "//", so `Uri`
        // reports a non-empty Host for it. Rebuilding from that would print
        // 'mailto://example.com' — correctly redacted, and an identifier that
        // exists nowhere in the operator's config, which costs the message the
        // other half of its job. It carries an '@', so it is refused instead.
        var ex = Assert.Throws<ArgumentException>(() =>
            new ProtectedResourceMetadata(
                resource: "mailto:ops@example.com#anchor-value",
                issuer: "https://auth.example.com",
                scopes: Array.Empty<string>()));

        Assert.DoesNotContain("mailto://", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("ops", ex.Message, StringComparison.Ordinal);
        Assert.Contains("(unparseable identifier)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FragmentRejection_QueryIsDroppedWithTheFragment()
    {
        // Neither is needed to name the identifier and both can carry a secret, so
        // the rebuilt message stops at the path.
        var ex = Assert.Throws<ArgumentException>(() =>
            new ProtectedResourceMetadata(
                resource: "https://api.example.com/mcp?token=s3cret#anchor-value",
                issuer: "https://auth.example.com",
                scopes: Array.Empty<string>()));

        Assert.DoesNotContain("s3cret", ex.Message, StringComparison.Ordinal);
        Assert.Contains("https://api.example.com/mcp", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FragmentRejection_MessageKeepsPathAtSignAsData()
    {
        // An '@' in the path is ordinary data (RFC 3986 §3.3), not a userinfo
        // delimiter — the cut is bounded by the authority's terminating '/'.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/users/@bob#anchor-value"));

        Assert.Contains("https://api.example.com/users/@bob", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GetDocumentUrl_FragmentInResource_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp#frag"));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("fragment", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // The unaffected-path cases this guard must not disturb live in
    // OAuthProtectedResourceMetadataTests, which is the fixture for this method:
    // the plain `/mcp` derivation in GetDocumentUrl_Rfc9728Examples and the
    // percent-encoded %23 in GetDocumentUrl_PercentEncodedHashIsData. What stays
    // here is the one axis this fixture owns.
    [Fact]
    public void GetDocumentUrl_NoFragment_IsUnaffected()
    {
        // A query component is a different axis: legal (RFC 8707 §2 states the
        // SHOULD NOT and its exception in the same sentence) and preserved in
        // the derived URL per RFC 9728 §3.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?v=1",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?v=1"));
    }
}
