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
        // swallow this case. Sibling of the %2F assertion below: Uri.AbsolutePath
        // hands back the escaped form for both, because both encode *reserved*
        // characters, which canonicalization leaves alone.
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
        // Pins that Uri.AbsolutePath hands back the escaped form rather
        // than decoding it into a trimmable slash.
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

    // Not tagged [Conformance]: the path-derivation catalog case is query-less
    // and does not cover these assertions. The marker for the query case lands
    // together with the catalog case itself.
    [Fact]
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

        // No terminating slash exists to remove — the suffix lands directly
        // after the host and the query follows.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource?x=1",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com?x=1"));

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
        // absent was settled family-wide as absent, so the derived document
        // URL is query-less rather than carrying a dangling "?".
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
        // deliberate and family-wide — python's urlsplit yields "" for it and
        // urlunsplit omits it, go dropped its ForceQuery carry — and it is the
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
}
