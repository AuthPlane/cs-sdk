namespace Authplane;

/// <summary>
/// Validation shared by every path that accepts an operator-configured resource
/// identifier.
/// </summary>
internal static class ResourceIdentifiers
{
    /// <summary>
    /// Reject a resource identifier carrying a URI fragment.
    ///
    /// RFC 8707 §2: "The URI MUST NOT include a fragment component." RFC 9728
    /// §1.2 restates it in the definition of the resource identifier — "a URL
    /// that uses the https scheme and has no fragment component."
    ///
    /// Without this gate the fragment is silently dropped rather than rejected:
    /// <see cref="OAuthProtectedResourceMetadata.GetDocumentUrl"/> derives the
    /// well-known URL from <c>Uri.AbsolutePath</c> and the authority, neither of
    /// which carries the fragment, while <c>AuthplaneResource.Resource</c> keeps
    /// the identifier verbatim and emits it as the PRM <c>resource</c> field.
    /// The served document then names a resource that differs from the URL it
    /// was fetched from, and RFC 9728 §3.3 requires a conformant client to
    /// discard it — an interop failure with no error anywhere on the server
    /// side. Failing at construction turns that into a startup error the
    /// operator can act on.
    ///
    /// The check is a literal '#' scan rather than a parse: '#' is the only
    /// fragment delimiter (RFC 3986 §3.5), a percent-encoded <c>%23</c> is data
    /// and stays accepted, and scanning avoids imposing any absoluteness or
    /// scheme requirement on identifiers that are not http(s) URLs.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentException">The identifier contains a fragment.</exception>
    internal static void ThrowIfFragment(string resource, string paramName)
    {
        var fragmentStart = resource.IndexOf('#', StringComparison.Ordinal);
        if (fragmentStart >= 0)
        {
            throw new ArgumentException(
                "Resource identifier must not contain a fragment component " +
                $"(RFC 8707 §2, RFC 9728 §1.2), got '{Redact(resource, fragmentStart)}'.",
                paramName);
        }
    }

    /// <summary>
    /// Reject a resource identifier whose query is not a valid RFC 3986 §3.4
    /// <c>query</c> production: <c>*( pchar / "/" / "?" )</c>, where
    /// <c>pchar</c> is unreserved / pct-encoded / sub-delims / ":" / "@".
    ///
    /// The derived well-known URL carries the query sliced verbatim off the
    /// original identifier string, so whatever the operator configured is what
    /// gets advertised. A query outside the production makes that URL not a
    /// URI: a client that reads <c>resource_metadata</c> and fetches it is
    /// handed something it cannot parse. Failing at construction turns a
    /// misconfiguration into a startup error the operator can act on, rather
    /// than an unusable advertised URL discovered at request time.
    ///
    /// This is not an injection gate, and does not close one. The MCP
    /// middleware runs every challenge value through its escaper, which
    /// backslash-escapes '"' and '\' and drops CTLs (RFC 9110 §11.2), and has
    /// done since before the query was preserved — so an unencoded '"' never
    /// reached a header unescaped either way. What this gate adds beyond the
    /// escaper is that <see cref="OAuthProtectedResourceMetadata.GetDocumentUrl"/>
    /// is public API whose return value a caller may place in a header, or a
    /// redirect, of their own with no escaper in the path.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentException">The query is not a valid RFC 3986 §3.4 query.</exception>
    internal static void ThrowIfInvalidQuery(string resource, string paramName)
    {
        var queryStart = resource.IndexOf('?', StringComparison.Ordinal);
        if (queryStart < 0)
        {
            return;
        }

        for (var i = queryStart + 1; i < resource.Length; i++)
        {
            var c = resource[i];
            if (c == '%')
            {
                if (i + 2 >= resource.Length
                    || !char.IsAsciiHexDigit(resource[i + 1])
                    || !char.IsAsciiHexDigit(resource[i + 2]))
                {
                    var escape = resource[i..Math.Min(i + 3, resource.Length)];
                    throw new ArgumentException(
                        $"Resource identifier query contains a malformed percent-encoding ('{escape}' at offset {i}); "
                            + $"every '%' must be followed by two hex digits (RFC 3986 §2.1), got '{Redact(resource, resource.Length)}'.",
                        paramName);
                }

                i += 2;
                continue;
            }

            if (!IsQueryChar(c))
            {
                throw new ArgumentException(
                    $"Resource identifier query contains a character ('{c}') at offset {i} outside the RFC 3986 §3.4 "
                        + $"query production; percent-encode it in the configured identifier, got '{Redact(resource, resource.Length)}'.",
                    paramName);
            }
        }
    }

    /// <summary>
    /// RFC 3986 §3.4 query characters other than pct-encoded: unreserved
    /// (ALPHA / DIGIT / "-" / "." / "_" / "~"), sub-delims
    /// ("!" / "$" / "&amp;" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="),
    /// plus ":" / "@" / "/" / "?".
    /// </summary>
    private static bool IsQueryChar(char c) =>
        char.IsAsciiLetterOrDigit(c)
        || c is '-' or '.' or '_' or '~'
        or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '='
        or ':' or '@' or '/' or '?';

    /// <summary>
    /// Stands in for an identifier the formatter will not echo, because it could
    /// not be shown to be free of credentials.
    /// </summary>
    private const string UnredactableIdentifier = "(unparseable identifier)";

    /// <summary>
    /// The identifier up to the fragment delimiter, with any userinfo elided.
    /// </summary>
    /// <remarks>
    /// A process can host several resources against one AS
    /// (<c>AuthplaneClient.CreateResourceAsync</c>), so <c>paramName</c> alone
    /// does not tell the operator which identifier failed. The fragment is
    /// dropped — it is the rejected part, and it is the component most likely
    /// to be pasted from somewhere — and userinfo with it, since it can carry
    /// credentials.
    ///
    /// <para>This parses rather than scanning, and does not inherit the no-parse
    /// property of <see cref="ThrowIfFragment"/>. That property is there so the
    /// gate imposes neither absoluteness nor a scheme on identifiers it is not
    /// judging; a message formatter carries no such obligation, and a failed
    /// parse here simply means "redact more". An index scan cannot be made
    /// correct on this input: it runs ahead of any validation, so the shapes it
    /// must survive are exactly the illegal ones. An unescaped <c>@</c> in the
    /// userinfo (RFC 3986 §3.2.1 forbids it) moves the real delimiter past the
    /// first <c>@</c>, and an unescaped <c>/</c> in a password moves the
    /// authority's end before it — the first leaks the tail of the credential,
    /// the second leaks all of it.</para>
    ///
    /// <para><see cref="Uri.Authority"/> is <c>host[:port]</c>: userinfo is not
    /// part of it, so rebuilding from it makes the credential structurally
    /// unreachable instead of cut by hand. Note <see cref="Uri.GetLeftPart"/>
    /// with <see cref="UriPartial.Path"/> does <em>not</em> work here — on .NET
    /// it keeps the userinfo it appears to drop.</para>
    ///
    /// <para>Anything that does not yield a host is refused rather than echoed,
    /// matching the python sibling's <c>except ValueError</c>. The one exception
    /// is an identifier with no authority at all and no <c>@</c> in it — an
    /// opaque <c>urn:example:api</c> has nowhere to hide a credential, and
    /// naming it is what makes the error actionable.</para>
    /// </remarks>
    private static string Redact(string resource, int fragmentStart)
    {
        var head = resource[..fragmentStart];

        if (Uri.TryCreate(head, UriKind.Absolute, out var parsed))
        {
            // The "//" is required, not synthesized. A scheme that puts data in
            // the authority slot without one — mailto:ops@example.com — parses
            // with a non-empty Host, and rebuilding it would print
            // 'mailto://example.com': an identifier the operator never wrote and
            // cannot grep their config for. The redaction would be right and the
            // other half of the message's job would be lost. Such a shape has an
            // '@', so the fallback below refuses it for the right reason.
            if (parsed.Host.Length > 0 && head.Contains("//", StringComparison.Ordinal))
            {
                // Authority is host[:port]; the path keeps an '@' in it, which is
                // data (RFC 3986 §3.3). Query goes with the fragment: neither is
                // needed to name the identifier, and both can carry a secret.
                return $"{parsed.Scheme}://{parsed.Authority}{parsed.AbsolutePath}";
            }

            if (!head.Contains('@', StringComparison.Ordinal))
            {
                // No authority component, so nothing that can hold userinfo.
                return head;
            }
        }

        return UnredactableIdentifier;
    }

    /// <summary>
    /// Reject a resource identifier containing whitespace or a backslash
    /// anywhere in the string.
    ///
    /// Neither character can appear unescaped in an RFC 3986 URI — no grammar
    /// production admits them — and <see cref="Uri"/> does not reject them but
    /// silently rewrites: surrounding whitespace is trimmed before parsing, an
    /// interior space is escaped to <c>%20</c> in the derived parts, and a
    /// backslash is converted to '/'. <c>AuthplaneResource.Resource</c> keeps
    /// the identifier verbatim and emits it as the PRM <c>resource</c> field,
    /// so each rewrite makes the served document name a resource that differs
    /// from the URL it was derived from. None of these rewrites is an RFC 3986
    /// equivalence (unlike case, default ports and dot-segments, which are),
    /// so RFC 9728 §3.3 requires a conformant client to discard the document —
    /// an interop failure with no error anywhere on the server side. Failing
    /// at construction turns that into a startup error the operator can act on.
    ///
    /// Runs ahead of <see cref="ThrowIfNotAbsoluteUrl"/> at every site, both
    /// so the error names the actual defect instead of misreporting
    /// absoluteness and because that gate's parse would itself trim
    /// surrounding whitespace and accept the identifier.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentException">The identifier contains whitespace
    /// or a backslash.</exception>
    internal static void ThrowIfWhitespaceOrBackslash(string resource, string paramName)
    {
        foreach (var c in resource)
        {
            if (char.IsWhiteSpace(c))
            {
                throw new ArgumentException(
                    "Resource identifier must not contain whitespace; remove surrounding whitespace, or percent-encode an intentional space as %20 (RFC 3986 §2.1).",
                    paramName);
            }

            // C0 controls and DEL, which `Uri` percent-encodes into the derived
            // URL while the identifier is emitted verbatim. `char.IsWhiteSpace`
            // does not cover them: U+0001 and U+007F are not separators. Closed
            // here rather than in a path validator, matching python's whitespace
            // gate (`ch.isspace() or ord(ch) <= 0x20`). Its own message, since
            // telling an operator to look for a space they cannot see is worse
            // than saying nothing. U+200B is deliberately not covered — it is a
            // format character above 0x20, and stays with the path-canonicalization
            // divergence class recorded at the derivation in
            // `OAuthProtectedResourceMetadata`.
            if (c <= 0x20 || c == 0x7F)
            {
                throw new ArgumentException(
                    $"Resource identifier must not contain a control character (U+{(int)c:X4} at offset {resource.IndexOf(c, StringComparison.Ordinal)}); percent-encode it (RFC 3986 §2.1).",
                    paramName);
            }

            if (c == '\\')
            {
                throw new ArgumentException(
                    "Resource identifier must not contain a backslash; percent-encode it as %5C (RFC 3986 §2.1).",
                    paramName);
            }
        }
    }

    /// <summary>
    /// Require the resource identifier to be an absolute URL with both a
    /// scheme and a host.
    ///
    /// The scheme requirement is RFC 8707 §2: the resource parameter "MUST be
    /// an absolute URI, as specified by Section 4.3 of [RFC3986]", and an
    /// RFC 3986 §4.3 absolute URI starts with a scheme. The host requirement
    /// is RFC 9728 §3: the well-known suffix is inserted after the host
    /// component — with no host there is no derivable metadata URL, and until
    /// this gate `urn:example:api` quietly derived the garbage
    /// `/.well-known/oauth-protected-resourceexample:api`.
    ///
    /// <c>http</c> hosts stay accepted for local development — a deliberate
    /// profile relaxation; this gate imposes no scheme allowlist.
    ///
    /// <see cref="Uri.TryCreate(string?, UriKind, out Uri?)"/> with
    /// <see cref="UriKind.Absolute"/> is not the RFC 3986 §4.3 test on its
    /// own: the runtime infers an implicit <c>file</c> scheme, so <c>/mcp</c>
    /// parses "absolutely" as <c>file:///mcp</c> and the scheme-relative
    /// <c>//api.example.com/mcp</c> even parses with a non-empty host. A
    /// scheme the operator actually wrote is distinguishable because the
    /// parsed scheme then leads the original string; an inferred one does not.
    /// A guard phrased as "opaque or authority-less" would wrongly admit the
    /// scheme-relative form, so the scheme is checked explicitly.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentException">The identifier is not an absolute
    /// URL with a scheme and a host.</exception>
    internal static void ThrowIfNotAbsoluteUrl(string resource, string paramName)
    {
        // Uri.TryCreate trims surrounding whitespace before parsing, so this
        // gate on its own would accept a non-trimmed identifier;
        // ThrowIfWhitespaceOrBackslash runs ahead of it at every site and
        // rejects that shape first.
        if (!Uri.TryCreate(resource, UriKind.Absolute, out var uri) ||
            !resource.StartsWith(uri.Scheme + ":", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(uri.Host))
        {
            // The identifier is not echoed: it can carry userinfo, matching
            // ThrowIfFragment and the userinfo guard in GetDocumentUrl.
            throw new ArgumentException(
                "Resource identifier must be an absolute URL with a scheme and a host (RFC 8707 §2, RFC 9728 §3).",
                paramName);
        }
    }

    /// <summary>
    /// Reject a resource identifier whose port is not an RFC 3986 §3.2.3
    /// <c>port</c> production: <c>*DIGIT</c>, in range.
    /// </summary>
    /// <remarks>
    /// Its own axis rather than a case of the absoluteness gate, because it is
    /// not one: <c>https://api.example.com:80O/mcp</c> — letter O for zero — is
    /// an absolute URL with a scheme and a host, and reporting it as neither
    /// points the operator at the wrong thing for a typo they will actually
    /// make. <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> fails on it,
    /// so this runs <em>ahead</em> of the absoluteness gate — behind it the
    /// parse failure gets there first and the message is the wrong one again.
    /// Python orders it last because its absoluteness check does not fail on
    /// these shapes; the axis is the same, the position is forced by the
    /// platform.
    ///
    /// <para>The port is read off the original string, since a value <c>Uri</c>
    /// would not parse cannot be read back from it. Only the digits are echoed:
    /// a port carrying non-digits has the same shape as a userinfo whose '@'
    /// was forgotten (<c>https://user:pass/x</c>), so quoting it back would
    /// defeat the redaction the other gates apply.</para>
    ///
    /// <para>Matches the python sibling, which landed this as its own axis with
    /// its own message.</para>
    /// </remarks>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentException">The port is malformed or out of range.</exception>
    internal static void ThrowIfMalformedPort(string resource, string paramName)
    {
        var authorityStart = resource.IndexOf("//", StringComparison.Ordinal);
        if (authorityStart < 0)
        {
            return;
        }

        authorityStart += 2;
        var authorityEnd = resource.IndexOfAny(['/', '?', '#'], authorityStart);
        if (authorityEnd < 0)
        {
            authorityEnd = resource.Length;
        }

        // After any userinfo, and after an IPv6 literal's closing bracket, so a
        // ':' inside either is not read as the port delimiter (RFC 3986 §3.2.2).
        var hostStart = resource.LastIndexOf('@', authorityEnd - 1, authorityEnd - authorityStart) + 1;
        if (hostStart <= 0)
        {
            hostStart = authorityStart;
        }

        var bracket = resource.LastIndexOf(']', authorityEnd - 1, authorityEnd - hostStart);
        var searchFrom = bracket >= 0 ? bracket + 1 : hostStart;
        if (searchFrom >= authorityEnd)
        {
            return;
        }

        var colon = resource.IndexOf(':', searchFrom, authorityEnd - searchFrom);
        if (colon < 0)
        {
            return;
        }

        var port = resource[(colon + 1)..authorityEnd];
        if (port.Length == 0)
        {
            return; // RFC 3986 §3.2.3 permits an empty port; Uri treats it as the default.
        }

        var allDigits = port.All(char.IsAsciiDigit);
        // A leading zero is legal `*DIGIT` per RFC 3986 §3.2.3 and is rejected
        // anyway, because this SDK derives through Uri.GetLeftPart, which
        // re-renders the port: `:0080` emits verbatim and derives `:80`. That is
        // the emit-versus-derive divergence this axis exists to make
        // unconstructible, and it is not an RFC 3986 §6.2 equivalence — unlike
        // host case (§6.2.2.1), dot-segments (§6.2.2.3) and default-port removal
        // (§6.2.3), which are, and which the derivation is documented to apply.
        // A conformant client discards the mismatch (RFC 9728 §3.3). python and
        // go rebuild from `netloc` / `u.Host` and never re-render, so this is a
        // cs-only exposure rather than a family gap.
        var hasLeadingZero = port.Length > 1 && port[0] == '0';
        if (allDigits
            && !hasLeadingZero
            && int.TryParse(port, out var value)
            && value is >= 0 and <= 65535)
        {
            return;
        }

        var shown = allDigits ? $"'{port}'" : "(malformed port)";
        var reason = hasLeadingZero
            ? "must not carry a leading zero, which the derived metadata URL would strip"
            : "must be digits in the range 0-65535";
        throw new ArgumentException(
            $"Resource identifier port {reason} (RFC 3986 §3.2.3), got {shown}.",
            paramName);
    }

    /// <summary>
    /// Reject a resource identifier carrying a userinfo component.
    ///
    /// RFC 9110 §4.2.4 forbids generating the userinfo subcomponent in http(s)
    /// URIs, and the derived well-known URL would otherwise embed credentials.
    /// Without this gate the identifier passes construction and every request
    /// then dies on the userinfo backstop inside
    /// <see cref="OAuthProtectedResourceMetadata.GetDocumentUrl"/> — an
    /// unhandled per-request exception instead of the startup error the
    /// constructor gates exist to produce. This covers both explicit
    /// credentials (<c>https://svc:s3cr3t@api.example.com/mcp</c>) and schemes
    /// whose syntax puts data in the userinfo slot
    /// (<c>mailto:ops@example.com</c> parses with UserInfo "ops" and a
    /// non-empty host, so it clears the absoluteness gate).
    ///
    /// Runs after <see cref="ThrowIfNotAbsoluteUrl"/>, which rejects an
    /// identifier that does not parse; for such input the repeated parse here
    /// fails and this guard is a no-op — safe only because the absoluteness
    /// gate has already reported the defect, not because this guard would.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentException">The identifier contains userinfo.</exception>
    internal static void ThrowIfUserInfo(string resource, string paramName)
    {
        // Read off the original string, not `Uri.UserInfo`. That property is the
        // empty string both when there is no '@' and when the subcomponent is
        // present but empty, so the two are indistinguishable through it — and
        // RFC 9110 §4.2.4 forbids *generating* the subcomponent, not merely
        // non-empty credentials. `https://@api.example.com/mcp` used to clear
        // the gate and then derive a well-known URL that carries the '@' into
        // the `resource_metadata` value unauthenticated clients are handed.
        // `GetLeftPart(UriPartial.Authority)` keeps it too, the same .NET quirk
        // `Redact`'s doc records for `UriPartial.Path`.
        // Two checks, not one. The authority slice catches the empty form, which
        // `Uri.UserInfo` cannot see; `Uri.UserInfo` catches a scheme that puts
        // data in the userinfo slot without a "//" (`mailto:ops@example.com`
        // parses with UserInfo "ops" and a non-empty host), which the slice
        // cannot see. Neither subsumes the other.
        if (HasAuthorityDelimiter(resource, '@')
            || (Uri.TryCreate(resource, UriKind.Absolute, out var uri)
                && !string.IsNullOrEmpty(uri.UserInfo)))
        {
            // The identifier is not echoed: it can carry credentials.
            throw new ArgumentException(
                "Resource identifier must not contain a userinfo component (RFC 9110 §4.2.4).",
                paramName);
        }
    }

    /// <summary>
    /// Whether the authority component of <paramref name="resource"/> contains
    /// <paramref name="delimiter"/>.
    /// </summary>
    /// <remarks>
    /// The authority is what sits between "//" and the next "/", "?" or "#"
    /// (RFC 3986 §3.2), so a '@' in a path is data and is not matched.
    /// </remarks>
    private static bool HasAuthorityDelimiter(string resource, char delimiter)
    {
        var authorityStart = resource.IndexOf("//", StringComparison.Ordinal);
        if (authorityStart < 0)
        {
            return false;
        }

        authorityStart += 2;
        var authorityEnd = resource.IndexOfAny(['/', '?', '#'], authorityStart);
        if (authorityEnd < 0)
        {
            authorityEnd = resource.Length;
        }

        return resource.IndexOf(delimiter, authorityStart, authorityEnd - authorityStart) >= 0;
    }
}
