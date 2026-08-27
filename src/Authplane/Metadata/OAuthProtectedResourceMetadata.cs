namespace Authplane;

/// <summary>
/// RFC 9728 helpers for OAuth Protected Resource Metadata (document URL and JSON shape).
/// </summary>
public static class OAuthProtectedResourceMetadata
{
    /// <summary>
    /// RFC 9728 §3.1 — absolute URL of the Protected Resource Metadata document for <paramref name="resourceUrl"/>.
    /// Path template: <c>/.well-known/oauth-protected-resource{resource-path}{resource-query}</c>.
    /// Trailing slashes on the resource path are dropped, so identifiers differing only by
    /// a trailing slash resolve to the same metadata document. A query component on the
    /// identifier is preserved: RFC 9728 §3 inserts the well-known string "between the host
    /// component and the path and/or query components, if any". Only the well-known path
    /// derivation normalizes — the resource identifier itself stays exact-string everywhere else.
    /// </summary>
    /// <param name="resourceUrl">The resource identifier. Must be an absolute URL carrying no
    /// fragment component (RFC 8707 §2, RFC 9728 §1.2) and no userinfo. A percent-encoded
    /// <c>%23</c> is path data, not a fragment, and stays accepted.</param>
    /// <returns>The absolute URL of the metadata document for <paramref name="resourceUrl"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="resourceUrl"/> is null, empty or
    /// whitespace, or carries a fragment component or userinfo. Carrying a fragment previously
    /// returned a URL with the fragment silently dropped.</exception>
    public static string GetDocumentUrl(string resourceUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceUrl);

        // Backstops only — the authoritative gates are in the AuthplaneResource
        // constructor, so a defective identifier never reaches here from a
        // configured resource. This method is also public API a caller can
        // invoke with an arbitrary string: dropping a fragment silently is
        // exactly the mismatch RFC 9728 §3.3 tells clients to discard the
        // document over, and without the absoluteness gate the runtime's
        // implicit `file` scheme lets `/mcp` slip through `new Uri(…,
        // UriKind.Absolute)` and a host-less `urn:example:api` derives a
        // malformed URL. The list and its order mirror the constructor path
        // exactly, so both sites report the same defect with the same wording
        // for an identifier broken more than one way.
        ResourceIdentifiers.ThrowIfFragment(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfWhitespaceOrBackslash(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfMalformedPort(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfNotAbsoluteUrl(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfUserInfo(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfInvalidQuery(resourceUrl, nameof(resourceUrl));

        var uri = new Uri(resourceUrl, UriKind.Absolute);

        // Root "/" trims to empty, yielding the bare well-known URL. RFC 9728
        // §3.1 removes the terminating slash following the host when a path or
        // query component is present, so `https://api.example.com/?x=1` and
        // `https://api.example.com?x=1` both derive
        // `…/.well-known/oauth-protected-resource?x=1`.
        //
        // The path is NOT byte-exact, unlike the query below: `Uri.AbsolutePath`
        // returns the canonicalized form, which unescapes percent-encodings of
        // unreserved characters (`%7E` becomes `~`) and applies RFC 3986 §5.2.4
        // dot-segment removal. That diverges from python's `urlsplit(...).path`
        // and java's raw derivation. A known limitation; the fix is to slice the
        // path off the original string the way the query already is.
        var resourcePath = uri.AbsolutePath.TrimEnd('/');

        // The query component is carried over verbatim: RFC 9728 §3 inserts the
        // well-known string "between the host component and the path and/or
        // query components, if any". A query is legal on a resource identifier
        // — RFC 8707 §2 states the SHOULD NOT and its exception in the same
        // sentence, and RFC 9728 §1.2 carries that forward. The query is sliced
        // off the original string, not off the parsed Uri: `Uri` canonicalizes
        // on construction and unescapes percent-encodings of unreserved
        // characters (`%7E` becomes `~`), so `Uri.Query` is not byte-for-byte.
        // The fragment gate above guarantees nothing follows the query.
        var queryStart = resourceUrl.IndexOf('?', StringComparison.Ordinal);
        var query = queryStart >= 0 ? resourceUrl[queryStart..] : string.Empty;

        // A bare "?" is an empty query. Empty-versus-absent was settled
        // family-wide as absent: the derived document URL is query-less
        // rather than carrying a dangling "?".
        if (query == "?")
        {
            query = string.Empty;
        }

        return $"{uri.GetLeftPart(UriPartial.Authority)}/.well-known/oauth-protected-resource{resourcePath}{query}";
    }
}
