namespace Authplane;

/// <summary>
/// RFC 9728 helpers for OAuth Protected Resource Metadata (document URL and JSON shape).
/// </summary>
public static class OAuthProtectedResourceMetadata
{
    /// <summary>
    /// RFC 9728 §3.1 — absolute URL of the Protected Resource Metadata document for <paramref name="resourceUrl"/>.
    /// Path template: <c>/.well-known/oauth-protected-resource{resource-path}{resource-query}</c>.
    /// The derived URL is byte-exact with respect to the identifier: every component is
    /// sliced off the original string, so the result is the identifier with the well-known
    /// string inserted between the authority and the path. Exactly two transformations
    /// apply: trailing slashes on the resource path are dropped per RFC 9728 §3.1, so
    /// identifiers differing only by a trailing slash resolve to the same metadata
    /// document, and a bare trailing <c>?</c> — an empty query — derives the query-less
    /// URL. A non-empty query component is preserved: RFC 9728 §3 inserts the well-known
    /// string "between the host component and the path and/or query components, if any".
    /// The resource identifier itself stays exact-string everywhere else.
    /// </summary>
    /// <param name="resourceUrl">The resource identifier. Must be an absolute URL carrying no
    /// fragment component (RFC 8707 §2, RFC 9728 §1.2) and no userinfo. A percent-encoded
    /// <c>%23</c> is path data, not a fragment, and stays accepted.</param>
    /// <returns>The absolute URL of the metadata document for <paramref name="resourceUrl"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="resourceUrl"/> is null, empty or
    /// whitespace; carries a fragment component (previously the URL was returned with the
    /// fragment silently dropped) or a userinfo component; contains whitespace, a C0 control
    /// or DEL, or a backslash; carries a malformed or leading-zero port; is not an absolute
    /// URL with a scheme and a host; or carries a host, path or query outside its RFC 3986
    /// production (§3.2.2 / §3.3 / §3.4) — a raw non-ASCII character or a malformed
    /// percent-escape anywhere in any of the three components.</exception>
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
        ResourceIdentifiers.ThrowIfInvalidHost(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfNotAbsoluteUrl(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfUserInfo(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfInvalidPath(resourceUrl, nameof(resourceUrl));
        ResourceIdentifiers.ThrowIfInvalidQuery(resourceUrl, nameof(resourceUrl));

        // Every component is sliced off the original identifier string; the
        // parsed `Uri` is never consulted. `Uri` canonicalizes on construction
        // and re-renders what it hands back: `Uri.AbsolutePath` unescapes
        // percent-encodings of unreserved characters (`%7E` becomes `~`) and
        // applies RFC 3986 §5.2.4 dot-segment removal;
        // `Uri.GetLeftPart(UriPartial.Authority)` lowercases the scheme and
        // host, removes a default port, and drops an IPv6 zone identifier
        // (`[fe80::1%25eth0]` becomes `[fe80::1]`). The served document's
        // `resource` member carries the configured bytes verbatim, so any
        // re-rendering here makes the advertised document URL disagree with
        // the URL a client re-derives from its own copy of the identifier —
        // the mismatch RFC 9728 §3.3 has it discard the document over. Those
        // rewrites are RFC 3986 §6.2 equivalences a recipient MAY apply, but
        // the identifier's identity is exact-string, so the derivation
        // preserves the configured bytes and leaves normalization to parties
        // entitled to it. `Uri` also rewrote shapes that are not URIs at all —
        // it re-encoded a raw non-ASCII segment (`/café` became `/caf%C3%A9`),
        // percent-encoded a zero-width space, and repaired a malformed
        // percent-escape (`/m%zzcp` became `/m%25zzcp`); on the path and
        // query those shapes never reach the slice — the §3.3 and §3.4
        // production gates above reject them at construction. The host is
        // gated the same way: `ThrowIfInvalidHost` is the §3.2.2 production
        // over it, so an IDN host (`https://café.example.com/mcp`) is refused
        // at construction rather than sliced into the derived URL — a non-URI,
        // since `reg-name` admits only ASCII and an IDN belongs in a URI as
        // its A-label. Converting it here instead is deliberately not done:
        // the served document emits the identifier verbatim, so encoding the
        // host only on the way into the derived URL would create the §3.3
        // mismatch. Producing the A-label is the operator's job.
        //
        // The slice boundaries lean on the gates above. The absoluteness gate
        // guarantees the string leads with its scheme, and RFC 3986 §3.1
        // admits no ':' inside one, so the first ':' ends it. The authority
        // then runs to the first '/' or '?': the userinfo gate leaves no
        // userinfo to hide either character in, an IPv6 literal admits
        // neither (RFC 3986 §3.2.2), and the fragment gate guarantees no '#'
        // anywhere in the string. The "//" check is defensive rather than
        // load-bearing: the absoluteness gate requires the delimiter outright,
        // so every identifier reaching here carries it, and a shape without it
        // would still slice at the first '/' or '?' after the scheme.
        var authorityStart = resourceUrl.IndexOf(':', StringComparison.Ordinal) + 1;
        if (resourceUrl.AsSpan(authorityStart).StartsWith("//"))
        {
            authorityStart += 2;
        }

        var pathStart = resourceUrl.IndexOfAny(['/', '?'], authorityStart);
        var schemeAndAuthority = pathStart >= 0 ? resourceUrl[..pathStart] : resourceUrl;

        // The fragment gate above guarantees nothing follows the query.
        var queryStart = resourceUrl.IndexOf('?', StringComparison.Ordinal);
        var pathEnd = queryStart >= 0 ? queryStart : resourceUrl.Length;

        // Root "/" trims to empty, yielding the bare well-known URL. RFC 9728
        // §3.1 removes the terminating slash following the host when a path or
        // query component is present, so `https://api.example.com/?x=1` and
        // `https://api.example.com?x=1` both derive
        // `…/.well-known/oauth-protected-resource?x=1`. When the identifier
        // has no path (`pathStart` is -1, or lands on the '?'), the slice is
        // empty and the suffix sits directly after the authority.
        var resourcePath = pathStart >= 0
            ? resourceUrl[pathStart..pathEnd].TrimEnd('/')
            : string.Empty;

        // The query component is carried over verbatim: RFC 9728 §3 inserts the
        // well-known string "between the host component and the path and/or
        // query components, if any". A query is legal on a resource identifier
        // — RFC 8707 §2 states the SHOULD NOT and its exception in the same
        // sentence, and RFC 9728 §1.2 carries that forward.
        var query = queryStart >= 0 ? resourceUrl[queryStart..] : string.Empty;

        // A bare "?" is an empty query. Empty-versus-absent resolves as
        // absent: the derived document URL is query-less rather than
        // carrying a dangling "?".
        if (query == "?")
        {
            query = string.Empty;
        }

        return $"{schemeAndAuthority}/.well-known/oauth-protected-resource{resourcePath}{query}";
    }
}
