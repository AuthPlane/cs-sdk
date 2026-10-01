using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// RFC 8707 §2 — the resource parameter "MUST be an absolute URI, as specified
/// by Section 4.3 of [RFC3986]" — and RFC 9728 §3, which inserts the
/// well-known suffix after the host component, so an identifier without a host
/// has no derivable metadata URL.
///
/// Before this gate a relative or opaque identifier was accepted and produced
/// a malformed metadata URL: `urn:example:api` derived the garbage
/// `/.well-known/oauth-protected-resourceexample:api`, and the runtime's
/// implicit `file` scheme let `/mcp` and the scheme-relative
/// `//api.example.com/mcp` slip through `new Uri(…, UriKind.Absolute)` — the
/// latter even parses with a non-empty host, which is why the gate checks the
/// written scheme explicitly instead of testing for an authority.
///
/// `http` hosts stay accepted for local development — a deliberate profile
/// relaxation; the gate imposes no scheme allowlist.
/// </summary>
public sealed class ResourceIdentifierAbsolutenessTests
{
    // The catalog case carries these two rows and requires each to reject on
    // its own — a guard that only asks whether the identifier is
    // authority-less would accept the scheme-relative form, so rejecting
    // "/mcp" alone does not satisfy it.
    //
    // The opaque row lives in its own unmarked theory below. The case's note 4
    // excludes it in as many words — "This case takes no position on it: ...
    // its 'reject' outcome must not be read as covering the opaque case" — so
    // carrying it under this marker is exactly the read the catalog forbids,
    // even though this SDK does reject it.
    [Theory]
    [InlineData("/mcp")]                    // relative reference
    [InlineData("//api.example.com/mcp")]   // scheme-relative (network-path) reference
    [Conformance("rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host")]
    public async Task CreateAsync_NonAbsoluteUrlResource_Throws(string resource)
    {
        // No test server: the guard runs ahead of the issuer metadata fetch, so
        // a misconfigured identifier fails without a network round trip.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // The authority delimiter is required as written rather than inferred from
    // `Uri.Host`, and this is the shape an operator produces by dropping a
    // slash off an ordinary configuration. Unmarked: the catalog case's rows
    // are the relative and scheme-relative references, and this is neither.
    //
    // Which branch of the gate turns it away is worth pinning rather than
    // assuming. Measured on this runtime, `Uri.TryCreate` returns false for a
    // scheme-only `https:` with no "//" — it does not fabricate an authority —
    // so the parse clause rejects it and the explicit "//" requirement never
    // gets a look at it. That requirement earns its place on the opaque
    // identifiers that *do* parse with a host-shaped part after the ':'
    // (`mailto:ops@example.com`), covered in ResourceUserInfoRejectionTests.
    // If a future runtime starts fixing this shape up into an authority, the
    // "//" clause catches it and this row keeps passing either way — which is
    // the reason to have it.
    [Theory]
    [InlineData("https:api.example.com/mcp")]   // no "//" at all
    [InlineData("https:/api.example.com/mcp")]  // one slash: a path, not an authority
    [InlineData("http:api.example.com/mcp")]
    public async Task CreateAsync_SpecialSchemeWithoutTheAuthorityDelimiter_Throws(string resource)
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
    [InlineData("https:api.example.com/mcp")]
    [InlineData("https:/api.example.com/mcp")]
    public void GetDocumentUrl_SpecialSchemeWithoutTheAuthorityDelimiter_Throws(string resource)
    {
        // The derivation is the half that would slice a phantom authority out
        // of this, so it gets the row too.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // Outside the catalog case, by that case's own note: an opaque identifier
    // has a scheme but no host, and the SDKs have not settled whether to
    // accept one for RFC 8707 audience binding. This SDK rejects it, and this
    // is that behaviour of ours rather than a claim about the case.
    [Theory]
    [InlineData("urn:example:api")]
    public async Task CreateAsync_OpaqueResource_Throws(string resource)
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // The row the case *mandates*: note 3 makes accepting `http://localhost`
    // a MUST — "an SDK is free to add a separate https policy ... but that is
    // a different requirement" — so it belongs under the marker, and against
    // the case's own `resource.create` stimulus rather than the path accessor.
    [Fact]
    [Conformance("rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host")]
    public async Task CreateAsync_HttpLocalhost_IsAccepted()
    {
        // Reaches the metadata fetch, which is as far as this can go without a
        // test server — the point is that the identifier gate does not reject
        // it, so any failure past this must not be an ArgumentException naming
        // `resource`.
        var ex = await Record.ExceptionAsync(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: "http://localhost:8080/mcp",
                scopes: new[] { "tools/add" }));

        Assert.False(
            ex is ArgumentException { ParamName: "resource" },
            $"the identifier gate rejected a row the case requires accepting: {ex?.Message}");
    }

    [Theory]
    [InlineData("/mcp")]
    [InlineData("//api.example.com/mcp")]
    [InlineData("urn:example:api")]
    public void GetDocumentUrl_NonAbsoluteUrlResource_Throws(string resource)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetDocumentUrl_HttpLocalhost_StaysAccepted()
    {
        // Deliberate profile relaxation: an `http` host is accepted so local
        // development works. The gate requires a scheme and a host, not a
        // particular scheme.
        Assert.Equal(
            "http://localhost:8080/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("http://localhost:8080/mcp"));
    }

    [Theory]
    [InlineData("https://api.example.com/mcp ")]    // trailing — Uri.TryCreate trims, so it parsed clean
    [InlineData(" https://api.example.com/mcp")]    // leading — was rejected, but blamed absoluteness
    [InlineData("https://api.example.com/my mcp")]  // interior — Uri escaped it to %20 in the derived URL
    public async Task CreateAsync_WhitespaceInResource_ThrowsNamingWhitespace(string resource)
    {
        // Uri does not reject whitespace, it rewrites: surrounding whitespace
        // is trimmed before parsing (RESOURCE_URL out of a .env is exactly how
        // it arrives), and an interior space is escaped to %20 in the derived
        // document URL. The PRM `resource` field echoes the identifier
        // verbatim, so either rewrite makes the published identifier and the
        // derived URL silently diverge — the RFC 9728 §3.3 mismatch a
        // conformant client discards the document over. Pinning the message
        // also fixes the leading-space case, which was rejected with an error
        // naming the wrong defect.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("whitespace", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateAsync_BackslashInResource_ThrowsNamingBackslash()
    {
        // Uri converts '\' to '/' — `m\cp` derives `…/m/cp` — the same silent
        // rewrite class as whitespace: not an RFC 3986 equivalence, so the
        // verbatim PRM `resource` field and the derived document URL diverge.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: "https://api.example.com/m\\cp",
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("backslash", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://api.example.com/mcp ", "whitespace")]
    [InlineData("https://api.example.com/my mcp", "whitespace")]
    [InlineData("https://api.example.com/m\\cp", "backslash")]
    public void GetDocumentUrl_WhitespaceOrBackslashInResource_Throws(string resource, string expectedInMessage)
    {
        // Pins the two rewrite shapes this axis closes — whitespace and the
        // backslash — rejected before any derivation. Its siblings resolve
        // differently: a C0 control is rejected by the same gate with its own
        // message, while a non-ASCII segment and a malformed percent-escape
        // construct and derive byte-exact, pinned per-axis in
        // OAuthProtectedResourceMetadataTests.
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Equal("resourceUrl", ex.ParamName);
        Assert.Contains(expectedInMessage, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateAsync_FragmentReportedBeforeAbsoluteness()
    {
        // An identifier broken both ways reports the fragment: the fragment
        // gate runs first at every site, so the error an operator sees is
        // stable regardless of which defect they fix first.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: "/mcp#frag",
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("fragment", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    // The emission path is the fifth gate site. This class writes `resource`
    // verbatim into the document while the derivation half of the same SDK
    // refuses the identical input, so without the gates here an operator can
    // construct and serve a document naming an identifier no client can derive
    // the URL of — the RFC 9728 §3.3 mismatch, through public API.
    [InlineData("/mcp", "absolute URL")]
    [InlineData("//api.example.com/mcp", "absolute URL")]
    [InlineData("urn:example:api", "absolute URL")]
    [InlineData("https://svc:s3cr3t@api.example.com/mcp", "userinfo")]
    [InlineData("https://api.example.com/mcp ", "whitespace")]
    [InlineData("https://api.example.com/m\\cp", "backslash")]
    [InlineData("https://api.example.com/mcp#frag", "fragment")]
    [InlineData("https://api.example.com:80O/mcp", "port")]
    public void ProtectedResourceMetadata_InvalidResource_ThrowsAtConstruction(
        string resource, string expectedInMessage)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new ProtectedResourceMetadata(
                resource: resource,
                issuer: "https://auth.example.com",
                scopes: Array.Empty<string>()));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains(expectedInMessage, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProtectedResourceMetadata_QueryIsStillAccepted()
    {
        // The one axis deliberately excluded here: a query is carried into the
        // derived URL, so emitting one raises no mismatch for this type to
        // prevent. Pinned so the exclusion stays a decision rather than a gap.
        var prm = new ProtectedResourceMetadata(
            resource: "https://api.example.com/mcp?tenant=a",
            issuer: "https://auth.example.com",
            scopes: Array.Empty<string>());

        Assert.Equal("https://api.example.com/mcp?tenant=a", prm.Resource);
    }

    [Theory]
    // Its own axis, not a case of absoluteness: all three are absolute URLs
    // with a scheme and a host. Reporting them as neither points the operator
    // at the wrong thing for a typo they will actually make.
    [InlineData("https://api.example.com:99999/mcp")]
    [InlineData("https://api.example.com:80O/mcp")]
    [InlineData("https://api.example.com:abc/mcp")]
    public async Task CreateAsync_MalformedPort_ReportsThePort(string resource)
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("port", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateAsync_MalformedPort_DoesNotEchoANonDigitPort()
    {
        // A port carrying non-digits has the same shape as a userinfo whose '@'
        // was forgotten, so echoing it back would defeat the redaction the other
        // gates apply.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: "https://user:s3cr3t/mcp",
                scopes: new[] { "tools/add" }));

        Assert.DoesNotContain("s3cr3t", ex.Message, StringComparison.Ordinal);
        Assert.Contains("(malformed port)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_EmptyUserInfo_IsRejected()
    {
        // RFC 9110 §4.2.4 forbids *generating* the subcomponent, not merely
        // non-empty credentials. `Uri.UserInfo` is "" both when there is no '@'
        // and when it is present but empty, so the gate reads the authority
        // slice of the original string instead.
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: "https://@api.example.com/mcp",
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("userinfo", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetDocumentUrl_AtSignInThePath_IsStillData()
    {
        // The authority slice ends at the first '/', so an '@' in a path is
        // data (RFC 3986 §3.3) and must not be read as a userinfo delimiter.
        // Asserted through the derivation rather than CreateAsync, which would
        // go on to reach the network once the gates pass.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/users/@bob",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/users/@bob"));
    }

    [Theory]
    // The derivation site had a per-axis test for every gate but this one.
    [InlineData("https://api.example.com:80O/mcp")]
    [InlineData("https://api.example.com:99999/mcp")]
    public void GetDocumentUrl_MalformedPort_Throws(string resource)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Contains("port", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    // A leading zero is legal RFC 3986 §3.2.3 syntax and is rejected anyway:
    // the derivation slices the authority verbatim, but stripping the zero is
    // not an RFC 3986 §6.2 equivalence, and a client whose URL stack
    // normalizes `:0080` to `:80` re-derives a document URL disagreeing with
    // the served document's verbatim `resource` member — the mismatch this
    // axis exists to make unconstructible, moved client-side.
    [InlineData("https://api.example.com:0080/mcp")]
    [InlineData("https://api.example.com:00/mcp")]
    [InlineData("https://[::1]:0080/mcp")]
    public void GetDocumentUrl_LeadingZeroPort_Throws(string resource)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Contains("leading zero", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    // C0 controls and DEL: no RFC 3986 production admits them, the byte-exact
    // derivation would carry them verbatim into the advertised URL, and
    // char.IsWhiteSpace does not cover them.
    [InlineData("https://api.example.com/a\u0001b")]
    [InlineData("https://api.example.com/a\u007Fb")]
    public void GetDocumentUrl_ControlCharacter_Throws(string resource)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            OAuthProtectedResourceMetadata.GetDocumentUrl(resource));

        Assert.Contains("control character", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
