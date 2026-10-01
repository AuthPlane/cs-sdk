using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

public sealed class OAuthProtectedResourceMetadataTests
{
    [Fact]
    [Conformance("rfc9728-well-known-path-must-derive-from-resource-uri")]
    public void GetDocumentUrl_Rfc9728Examples()
    {
        Assert.Equal(
            "https://rs.example.com/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://rs.example.com/mcp"));

        Assert.Equal(
            "https://rs.example.com/.well-known/oauth-protected-resource",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://rs.example.com/"));
    }

    [Fact]
    public void GetDocumentUrl_PercentEncodedHashIsData()
    {
        // RFC 3986 §3.5: '#' is the only fragment delimiter, so a percent-encoded
        // %23 is ordinary path data and must keep deriving a document URL. The
        // fragment guard scans for the literal character precisely so it cannot
        // swallow this case. Sibling of the %2F assertion below: the path is
        // sliced off the original string, so the escaped form survives
        // byte-for-byte in both.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp%23x",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp%23x"));
    }

    [Fact]
    [Conformance("rfc9728-well-known-path-must-derive-from-resource-uri")]
    public void GetDocumentUrl_DropsTrailingSlashOnResourcePath()
    {
        // Identifiers differing only by a trailing slash resolve to the same document.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp/"));

        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/v2/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/v2/mcp"));

        // Root with trailing slash still yields the bare well-known URL.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/"));

        // Bare host (no path at all) also yields the bare well-known URL.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com"));

        // RFC 3986 §3.3: a percent-encoded %2F is data inside the final
        // segment, not the "/" delimiter, so it must survive the trim.
        // Pins that the trim runs over the raw slice, where the escaped
        // form never decodes into a trimmable slash.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp%2F",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp%2F"));

        // RFC 9728 §3.1 only removes the *terminating* slash: a leading empty
        // segment is path data, so `//mcp` and `/mcp` are distinct resources
        // and must derive distinct document URLs. Pins TrimEnd('/') against a
        // future Trim('/') simplification.
        Assert.NotEqual(
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com//mcp"),
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp"));
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource//mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com//mcp"));
    }

    // The query case, distinct from the path-derivation case above: that one
    // is query-less and stays so deliberately, since SDKs report against case
    // ids and widening it would silently change what a passing report means.
    // The first three assertions are the case's result_shape, one row each, in
    // catalog order; the rest are this SDK's own additions.
    [Fact]
    [Conformance("rfc9728-well-known-url-must-preserve-the-resource-query-component")]
    public void GetDocumentUrl_PreservesQueryComponent()
    {
        // RFC 9728 §3 inserts the well-known string "between the host component
        // and the path and/or query components, if any" — the query is part of
        // the identifier and must survive into the derived document URL. A
        // query is legal on a resource identifier: RFC 8707 §2 states the
        // SHOULD NOT and its exception in the same sentence, and RFC 9728 §1.2
        // carries that forward.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=a"));

        // The row the case exists for: two identifiers differing only by their
        // query MUST NOT collapse onto one document URL. Without this the
        // requirement_summary is unasserted, and the failure it describes is a
        // multi-tenant misroute — a client asking for tenant a's metadata is
        // served tenant b's, HTTP 200, no signal.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=b",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=b"));

        // No terminating slash exists to remove — the suffix lands directly
        // after the host and the query follows.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource?x=1",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com?x=1"));

        // Distinctness over the whole derived set, so a future reorder or an
        // accidental collapse cannot pass by dropping one row: three
        // identifiers in, three different document URLs out.
        string[] derived =
        [
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=a"),
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=b"),
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com?x=1"),
        ];
        Assert.Equal(derived.Length, derived.Distinct().Count());

        // RFC 9728 §3.1 removes the terminating slash following the host when
        // a path or query component is present, so this derives the same URL
        // as the slashless form above.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource?x=1",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/?x=1"));

        // The query is sliced off the original string, so percent-encoding is
        // preserved byte-for-byte. %2F encodes a reserved character.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a%2Fb",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=a%2Fb"));

        // %7E encodes an unreserved character ('~'), which Uri.Query unescapes
        // during canonicalization — this is the case that pins the derivation
        // to the original string rather than the parsed Uri.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a%7Eb",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=a%7Eb"));
    }

    [Fact]
    public void GetDocumentUrl_BareQuestionMark_DerivesQuerylessUrl()
    {
        // A bare "?" is an empty query, which is legal per RFC 3986
        // (`*( pchar / "/" / "?" )` admits zero characters). Empty-versus-
        // absent resolves as absent, so the derived document URL is query-less
        // rather than carrying a dangling "?".
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?"));

        // Same on a bare host: no path, empty query — bare well-known URL.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com?"));
    }

    [Fact]
    public void GetDocumentUrl_QueryDistinctIdentifiers_DeriveDistinctUrls()
    {
        // Identifiers differing only in the query are different resources
        // (identity is exact-string) and must not collapse onto one document
        // URL, which is what dropping the query used to do.
        //
        // With one sanctioned exception, asserted below rather than left for a
        // reader to discover: a bare trailing '?' is an empty query and derives
        // the query-less URL, so `…/mcp?` and `…/mcp` do collapse. That is
        // deliberate — an empty query and an absent one resolve the same way
        // wherever this identifier is parsed — and it is the
        // one direction with an RFC 9728 §3.3 consequence: a client holding
        // `…/mcp` derives the shared URL and is served a document naming
        // `…/mcp?`, which §3.3 tells it to discard. Settled as harmless in
        // round 3; pinned here so it stays settled.
        var a = OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=a");
        var b = OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?tenant=b");
        var none = OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp");

        Assert.NotEqual(a, b);
        Assert.NotEqual(a, none);
        Assert.NotEqual(b, none);

        Assert.Equal(none, OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp?"));
    }

    // The byte-exact axes below are not tagged [Conformance]: the
    // path-derivation catalog case carries none of these shapes. Each fact
    // pins one member of the class the derivation used to re-render: the PRM
    // `resource` member emits the configured bytes verbatim, so any rewrite in
    // the derived URL is the RFC 9728 §3.3 mismatch a conformant client
    // discards the document over. The members of that class that are not URIs
    // in the first place — a raw non-ASCII segment (`/café`), a zero-width
    // space, a malformed percent-escape (`/m%zzcp`) — are rejected at
    // construction by the §3.3 path gate rather than preserved; those live in
    // ResourcePathValidationTests. What byte-exactness pins here is every
    // shape that is a URI and that `Uri` would still have rewritten.

    [Fact]
    public void GetDocumentUrl_PercentEncodedUnreservedInPath_IsPreservedByteForByte()
    {
        // %7E encodes an unreserved character ('~'), which Uri.AbsolutePath
        // unescapes during canonicalization — the path sibling of the %7E
        // query case above, and the case that pins the path slice to the
        // original string rather than the parsed Uri.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/m%7Ecp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/m%7Ecp"));
    }

    [Fact]
    public void GetDocumentUrl_Ipv6ZoneIdentifier_IsPreservedByteForByte()
    {
        // The authority-side member of the same class:
        // Uri.GetLeftPart(UriPartial.Authority) re-rendered the authority and
        // dropped an RFC 6874 zone identifier — `[fe80::1%25eth0]` derived
        // `[fe80::1]`. The authority is now sliced off the original string.
        Assert.Equal(
            "https://[fe80::1%25eth0]/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://[fe80::1%25eth0]/mcp"));
    }

    [Fact]
    public void GetDocumentUrl_DoesNotApplyRfc3986Equivalences()
    {
        // The byte-exact slice deliberately stops applying the RFC 3986 §6.2
        // equivalences the Uri-based derivation performed as a side effect:
        // case (§6.2.2.1), dot-segments (§6.2.2.3), default-port removal
        // (§6.2.3). They are equivalences — a recipient MAY normalize them —
        // but the identifier's identity is exact-string, and a client
        // re-deriving from its own copy of the identifier starts from the
        // same bytes; emitting one form while deriving another was the
        // divergence, not the cure for it.
        Assert.Equal(
            "HTTPS://API.EXAMPLE.COM/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("HTTPS://API.EXAMPLE.COM/mcp"));

        Assert.Equal(
            "https://api.example.com:443/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com:443/mcp"));

        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/a/../b",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/a/../b"));
    }

    [Fact]
    public void GetDocumentUrl_DerivedUrlIsTheIdentifierWithTheWellKnownStringInserted()
    {
        // The identity property stated end to end: removing the well-known
        // insertion from the derived URL yields the configured identifier,
        // byte for byte, for every divergence shape above at once. The sample
        // deliberately excludes the two shapes where the identity does not
        // hold, both asserted individually above: a trailing slash (removed
        // per RFC 9728 §3.1) and a bare '?' (an empty query, settled as
        // deriving the query-less URL).
        string[] identifiers =
        [
            "https://api.example.com/m%7Ecp",
            "https://api.example.com/mcp%2F",
            "https://api.example.com/mcp%23x",
            "https://[fe80::1%25eth0]/mcp",
            "HTTPS://API.EXAMPLE.COM/mcp",
            "https://api.example.com:443/mcp",
            "https://api.example.com/a/../b",
            "https://api.example.com/mcp?tenant=a%7Eb",
            "https://api.example.com?x=1",
            "https://api.example.com",
        ];

        const string wellKnown = "/.well-known/oauth-protected-resource";
        foreach (var identifier in identifiers)
        {
            var derived = OAuthProtectedResourceMetadata.GetDocumentUrl(identifier);
            // Removed at the known insertion offset — the end of the
            // authority, where the path or query starts — rather than by
            // Replace: the property is "remove the one inserted segment", and
            // an identifier whose own path contained the well-known string
            // would make a Replace pass for the wrong reason. The offset is
            // the derivation's own path-start boundary — the first '/' or '?'
            // after the authority — so a path-less identifier (with or
            // without a query, where a '/'-only search returns -1 or finds a
            // '/' inside the query) computes the same offset the derivation
            // inserted at; for the bare authority-only shape that is the end
            // of the string.
            var authorityStart = identifier.IndexOf("//", StringComparison.Ordinal) + 2;
            var insertionOffset = identifier.IndexOfAny(['/', '?'], authorityStart);
            if (insertionOffset < 0)
            {
                insertionOffset = identifier.Length;
            }

            Assert.Equal(identifier, derived.Remove(insertionOffset, wellKnown.Length));
        }
    }
}
