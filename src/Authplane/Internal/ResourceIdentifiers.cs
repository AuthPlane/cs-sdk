namespace Authplane;

/// <summary>
/// Validation shared by every path that accepts an operator-configured resource
/// identifier.
/// </summary>
internal static class ResourceIdentifiers
{
    /// <summary>
    /// What the gates call the value they rejected. These same gates guard more
    /// than one operator-supplied setting that reaches the
    /// <c>resource_metadata</c> quoted-string, so the sentence has to name the
    /// one the operator actually typed — an operator who put a trailing space
    /// in <c>resourceMetadataUrl</c> and is told "Resource identifier must not
    /// contain whitespace" goes looking at the wrong setting.
    /// </summary>
    internal const string DefaultSubject = "Resource identifier";

    /// <summary>
    /// Reject a resource identifier carrying a URI fragment.
    ///
    /// RFC 8707 §2: "The URI MUST NOT include a fragment component." RFC 9728
    /// §1.2 restates it in the definition of the resource identifier — "a URL
    /// that uses the https scheme and has no fragment component."
    ///
    /// Without this gate the fragment flows into the derived well-known URL:
    /// <see cref="OAuthProtectedResourceMetadata.GetDocumentUrl"/> slices the
    /// path and query off the original identifier string, relying on this gate
    /// for the guarantee that nothing follows them. A trailing <c>#frag</c>
    /// would ride the slice into the advertised <c>resource_metadata</c>
    /// value; a fetch of that URL strips the fragment on the wire (RFC 3986
    /// §3.5), so the served document — whose <c>resource</c> field emits the
    /// identifier verbatim, fragment included — names a resource that differs
    /// from what the client can ever fetch, and RFC 9728 §3.3 requires a
    /// conformant client to discard it — an interop failure with no error
    /// anywhere on the server side. Failing at construction turns that into a
    /// startup error the operator can act on.
    ///
    /// The check is a literal '#' scan rather than a parse: '#' is the only
    /// fragment delimiter (RFC 3986 §3.5), a percent-encoded <c>%23</c> is data
    /// and stays accepted, and scanning avoids imposing any absoluteness or
    /// scheme requirement on identifiers that are not http(s) URLs.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    /// <exception cref="ArgumentException">The identifier contains a fragment.</exception>
    internal static void ThrowIfFragment(string resource, string paramName, string subject = DefaultSubject)
    {
        var fragmentStart = resource.IndexOf('#', StringComparison.Ordinal);
        if (fragmentStart >= 0)
        {
            throw new ArgumentException(
                $"{subject} must not contain a fragment component " +
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
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    /// <exception cref="ArgumentException">The query is not a valid RFC 3986 §3.4 query.</exception>
    internal static void ThrowIfInvalidQuery(string resource, string paramName, string subject = DefaultSubject)
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
                        $"{subject} query contains a malformed percent-encoding ('{escape}' at offset {i}); "
                            + $"every '%' must be followed by two hex digits (RFC 3986 §2.1), got '{Redact(resource, resource.Length)}'.",
                        paramName);
                }

                i += 2;
                continue;
            }

            if (!IsQueryChar(c))
            {
                throw new ArgumentException(
                    $"{subject} query contains a character ('{c}') at offset {i} outside the RFC 3986 §3.4 "
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
    /// Reject a resource identifier whose path is not a valid RFC 3986 §3.3
    /// <c>path</c> production: <c>*( "/" segment )</c>, where a segment is
    /// <c>*pchar</c> and <c>pchar</c> is unreserved / pct-encoded / sub-delims
    /// / ":" / "@".
    ///
    /// The derived well-known URL carries the path sliced verbatim off the
    /// original identifier string, so whatever the operator configured is what
    /// gets advertised. A path outside the production makes that URL not a
    /// URI: RFC 3986 §2 limits a URI to a fixed ASCII repertoire, and RFC 8707
    /// §2 requires the resource identifier to be an absolute URI — a raw
    /// non-ASCII segment (<c>/café</c>, or a zero-width space) is an IRI shape
    /// at best, and a malformed percent-escape (<c>%zz</c>) is in no
    /// production at all. Failing at construction turns the misconfiguration
    /// into a startup error the operator can act on, rather than an
    /// unfetchable advertised URL discovered at request time — or a
    /// <c>WWW-Authenticate</c> field value carrying bytes RFC 9110 §5.5 gives
    /// no interpretation for, which an ASCII-encoding server stack then maps
    /// to <c>?</c>, handing the client a different, valid-looking URL.
    ///
    /// The same argument the query gate records applies here verbatim:
    /// <see cref="OAuthProtectedResourceMetadata.GetDocumentUrl"/> is public
    /// API whose return value a caller may place in a header, or a redirect,
    /// of their own with no escaper in the path. What the gate does not touch
    /// is any well-formed percent-encoding: <c>%7E</c>, <c>%2F</c> and
    /// <c>%23</c> are inside the production and ride the slice out byte-exact
    /// — rejecting the shapes that are not a URI is what makes preserving the
    /// ones that are sound.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    /// <exception cref="ArgumentException">The path is not a valid RFC 3986 §3.3 path.</exception>
    internal static void ThrowIfInvalidPath(string resource, string paramName, string subject = DefaultSubject)
    {
        var authorityStart = resource.IndexOf("//", StringComparison.Ordinal);
        if (authorityStart < 0)
        {
            return;
        }

        // The path runs from the first '/' or '?' after the authority to the
        // query delimiter, the same boundaries the derivation slices at; a
        // '?' first means there is no path component at all.
        var pathStart = resource.IndexOfAny(['/', '?'], authorityStart + 2);
        if (pathStart < 0 || resource[pathStart] == '?')
        {
            return;
        }

        var queryStart = resource.IndexOf('?', pathStart);
        var pathEnd = queryStart >= 0 ? queryStart : resource.Length;

        for (var i = pathStart; i < pathEnd; i++)
        {
            var c = resource[i];
            if (c == '%')
            {
                if (i + 2 >= pathEnd
                    || !char.IsAsciiHexDigit(resource[i + 1])
                    || !char.IsAsciiHexDigit(resource[i + 2]))
                {
                    var escape = resource[i..Math.Min(i + 3, pathEnd)];
                    throw new ArgumentException(
                        $"{subject} path contains a malformed percent-encoding ('{escape}' at offset {i}); "
                            + $"every '%' must be followed by two hex digits (RFC 3986 §2.1), got '{Redact(resource, resource.Length)}'.",
                        paramName);
                }

                i += 2;
                continue;
            }

            if (!IsPathChar(c))
            {
                // A non-ASCII character is named by code point, matching the
                // control-character message above: 'é' would print, but a
                // zero-width space is invisible and half a surrogate pair is
                // not a character.
                var shown = c <= 0x7E ? $"'{c}'" : $"U+{(int)c:X4}";
                throw new ArgumentException(
                    $"{subject} path contains a character ({shown}) at offset {i} outside the RFC 3986 §3.3 "
                        + $"path production; percent-encode it in the configured identifier, got '{Redact(resource, resource.Length)}'.",
                    paramName);
            }
        }
    }

    /// <summary>
    /// RFC 3986 §3.3 path characters other than pct-encoded: <c>pchar</c> —
    /// unreserved (ALPHA / DIGIT / "-" / "." / "_" / "~"), sub-delims
    /// ("!" / "$" / "&amp;" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="),
    /// ":" / "@" — plus the "/" segment delimiter. The §3.4 query production
    /// is this set plus '?'.
    /// </summary>
    private static bool IsPathChar(char c) =>
        char.IsAsciiLetterOrDigit(c)
        || c is '-' or '.' or '_' or '~'
        or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '='
        or ':' or '@' or '/';

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
    /// <para>Anything that does not yield a host is refused rather than echoed:
    /// a value that failed to parse cannot be redacted safely. The one exception
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
    /// production admits them — and the derivation slices the derived document
    /// URL off the original identifier string, so either would ride along
    /// verbatim: the advertised <c>resource_metadata</c> value would not be a
    /// URI, and no client could fetch it. Surrounding whitespace fails more
    /// quietly still: <see cref="Uri.TryCreate(string?, UriKind, out Uri?)"/>
    /// trims it before parsing, so the absoluteness gate alone would accept
    /// the identifier while the emitted PRM <c>resource</c> field and the
    /// derived URL both keep the stray bytes. Failing at construction turns
    /// each shape into a startup error the operator can act on.
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
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    internal static void ThrowIfWhitespaceOrBackslash(string resource, string paramName, string subject = DefaultSubject)
    {
        foreach (var c in resource)
        {
            if (char.IsWhiteSpace(c))
            {
                throw new ArgumentException(
                    $"{subject} must not contain whitespace; remove surrounding whitespace, or percent-encode an intentional space as %20 (RFC 3986 §2.1).",
                    paramName);
            }

            // C0 controls and DEL, which no RFC 3986 production admits and the
            // byte-exact derivation would carry verbatim into the advertised
            // URL. `char.IsWhiteSpace` does not cover them: U+0001 and U+007F
            // are not separators. Closed here rather than in a path validator:
            // the gate covers `ch <= 0x20` as well as `char.IsWhiteSpace`,
            // because U+0001 and U+007F are controls RFC 3986 admits nowhere
            // but `IsWhiteSpace` does not report. Its own message, since
            // telling an operator to look for a
            // space they cannot see is worse than saying nothing. U+200B is
            // not covered here — it is a format character above 0x20, neither
            // whitespace nor a control; in the path or the query it falls to
            // the §3.3/§3.4 production gates, which reject every raw
            // non-ASCII character.
            if (c <= 0x20 || c == 0x7F)
            {
                throw new ArgumentException(
                    $"{subject} must not contain a control character (U+{(int)c:X4} at offset {resource.IndexOf(c, StringComparison.Ordinal)}); percent-encode it (RFC 3986 §2.1).",
                    paramName);
            }

            if (c == '\\')
            {
                throw new ArgumentException(
                    $"{subject} must not contain a backslash; percent-encode it as %5C (RFC 3986 §2.1).",
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
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    internal static void ThrowIfNotAbsoluteUrl(string resource, string paramName, string subject = DefaultSubject)
    {
        // Uri.TryCreate trims surrounding whitespace before parsing, so this
        // gate on its own would accept a non-trimmed identifier;
        // ThrowIfWhitespaceOrBackslash runs ahead of it at every site and
        // rejects that shape first.
        // The authority delimiter is required rather than inferred from
        // `Uri.Host`. A host is a subcomponent of the authority (RFC 3986 §3.2)
        // and an authority is introduced by "//", so an identifier without the
        // delimiter has no host however the platform parser reports one — and it
        // does report one for an opaque identifier whose scheme puts a
        // host-shaped string after its ':' (`mailto:ops@example.com` parses to
        // Host "example.com"). Such an identifier used to clear this gate on that
        // phantom host and get refused one gate later as carrying userinfo, which
        // named the wrong defect; and had it cleared both, the derivation would
        // have sliced it into `mailto:ops@example.com/.well-known/…`, a URL that
        // resolves to nothing and would have been advertised to clients.
        if (!Uri.TryCreate(resource, UriKind.Absolute, out var uri) ||
            !resource.StartsWith(uri.Scheme + ":", StringComparison.OrdinalIgnoreCase) ||
            !resource.AsSpan(uri.Scheme.Length + 1).StartsWith("//") ||
            string.IsNullOrEmpty(uri.Host))
        {
            // The identifier is not echoed: it can carry userinfo, matching
            // ThrowIfFragment and the userinfo guard in GetDocumentUrl.
            throw new ArgumentException(
                $"{subject} must be an absolute URL with a scheme and a host (RFC 8707 §2, RFC 9728 §3).",
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
    /// The axis is independent of the ordering — the position is forced by
    /// the platform's parser, and an implementation whose absoluteness check
    /// does not fail on these shapes is free to order it last.
    ///
    /// <para>The port is read off the original string, since a value <c>Uri</c>
    /// would not parse cannot be read back from it. Only the digits are echoed:
    /// a port carrying non-digits has the same shape as a userinfo whose '@'
    /// was forgotten (<c>https://user:pass/x</c>), so quoting it back would
    /// defeat the redaction the other gates apply.</para>
    ///
    /// <para>Its own axis with its own message, rather than folded into a
    /// neighbouring gate — the operator needs to be told which rule the
    /// identifier broke.</para>
    /// </remarks>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    /// <exception cref="ArgumentException">The port is malformed or out of range.</exception>
    internal static void ThrowIfMalformedPort(string resource, string paramName, string subject = DefaultSubject)
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
        // anyway. The derivation now slices the authority off the original
        // string, so `:0080` would emit and derive consistently on this side —
        // but stripping the zero is not an RFC 3986 §6.2 equivalence, so a
        // client is not entitled to it either, and real URL stacks (this
        // runtime's own `Uri` among them) normalize `:0080` to `:80` anyway. A
        // client whose stack has normalized its configured identifier
        // re-derives a document URL naming `:80` against a served document
        // naming `:0080` — the RFC 9728 §3.3 mismatch, moved client-side.
        // Rejecting the shape keeps the identifier one that renders the same
        // through any stack.
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
            ? "must not carry a leading zero, which normalizing URL parsers strip"
            : "must be digits in the range 0-65535";
        throw new ArgumentException(
            $"{subject} port {reason} (RFC 3986 §3.2.3), got {shown}.",
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
    /// whose syntax puts data in the userinfo slot.
    ///
    /// Scoped to the authority, because that is where the subcomponent lives.
    /// RFC 3986 §3.2 defines <c>authority = [ userinfo "@" ] host [ ":" port ]</c>
    /// and an authority is introduced by "//", so an identifier without one has
    /// no userinfo subcomponent for an '@' to delimit and the '@' is data. This
    /// gate must not claim it: <c>mailto:ops@example.com</c> parses to
    /// <see cref="Uri.UserInfo"/> "ops" and a non-empty <see cref="Uri.Host"/>,
    /// but that is the platform parser modelling an opaque URI through the
    /// authority-shaped properties it has, not a userinfo component in the URI.
    /// Reporting such an identifier as carrying credentials named the wrong
    /// defect and sent the operator looking for a secret that was never there;
    /// it is refused for the reason it is actually refused for — an opaque URI
    /// has no host, so no metadata URL derives from it — by
    /// <see cref="ThrowIfNotAbsoluteUrl"/>.
    ///
    /// Runs after <see cref="ThrowIfNotAbsoluteUrl"/>, which rejects an
    /// identifier that does not parse; for such input this guard is a no-op —
    /// safe only because the absoluteness gate has already reported the defect,
    /// not because this guard would.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    /// <exception cref="ArgumentException">The identifier contains userinfo.</exception>
    internal static void ThrowIfUserInfo(string resource, string paramName, string subject = DefaultSubject)
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
        // The slice is also what keeps the gate to its own axis. `Uri.UserInfo`
        // is non-empty for an opaque identifier whose scheme puts data before an
        // '@' with no authority at all, where RFC 3986 §3.2 has no userinfo
        // subcomponent to populate; reading it here made this gate reject such an
        // identifier as carrying credentials. The absoluteness gate refuses it for
        // the reason it is actually refused for.
        if (HasAuthorityDelimiter(resource, '@'))
        {
            // The identifier is not echoed: it can carry credentials.
            throw new ArgumentException(
                $"{subject} must not contain a userinfo component (RFC 9110 §4.2.4).",
                paramName);
        }
    }

    /// <summary>
    /// Reject a resource identifier whose host is not an RFC 3986 §3.2.2
    /// <c>host</c> production: <c>IP-literal / IPv4address / reg-name</c>,
    /// where <c>reg-name</c> is <c>*( unreserved / pct-encoded / sub-delims )</c>.
    ///
    /// The other gates over the authority are not character productions: the
    /// host's only constraints were whitespace and control characters, the
    /// malformed-port gate, and the userinfo gate. An internationalized host
    /// therefore cleared all of them — <c>é</c> is above 0x20 and is not
    /// whitespace, there is no ':' for the port gate to read and no '@' for the
    /// userinfo gate, and <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// parses an IDN host to a non-empty <see cref="Uri.Host"/>, so the
    /// absoluteness gate saw a scheme and a host and passed it.
    ///
    /// <see cref="OAuthProtectedResourceMetadata.GetDocumentUrl"/> slices the
    /// authority verbatim off the original string, so such a host rode into the
    /// derived URL and out to unauthenticated clients in the
    /// <c>resource_metadata</c> parameter of a <c>WWW-Authenticate</c>
    /// challenge — a value RFC 9110 §5.5 gives no interpretation for outside
    /// ASCII. RFC 3986 §3.2.2 <c>reg-name</c> admits only the ASCII repertoire,
    /// and an internationalized name belongs in a URI as its A-label
    /// (<c>xn--caf-dma.example.com</c>), so the derived URL was not a URI and
    /// RFC 8707 §2 requires the identifier to be one.
    ///
    /// Runs <em>ahead</em> of <see cref="ThrowIfNotAbsoluteUrl"/>, for the reason
    /// the malformed-port gate records: <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// fails on a malformed percent-escape in the host, so behind the absoluteness
    /// gate that parse failure gets there first and the operator is told the
    /// identifier is not an absolute URL when the actual defect is one character in
    /// the host. The two authority gates group together for the same reason. It
    /// therefore also runs on a string not yet known to be an absolute URL, which
    /// costs nothing: the host slice is keyed off the "//" delimiter, so an
    /// identifier without an authority is a no-op here and the absoluteness gate
    /// behind it still reports it.
    ///
    /// Converting to an A-label here is deliberately not attempted. The
    /// identifier's identity is exact-string, and the served document's
    /// <c>resource</c> member emits the configured bytes verbatim; encoding the
    /// host on the way into the derived URL alone would make the advertised URL
    /// disagree with the one a client re-derives from its own copy of the
    /// identifier, which is the mismatch RFC 9728 §3.3 has it discard the
    /// document over. Producing the A-label is the operator's job, and the
    /// message says so.
    /// </summary>
    /// <param name="resource">The operator-configured resource identifier.</param>
    /// <param name="paramName">Name of the caller's parameter, for the exception.</param>
    /// <param name="subject">What to call the value in the message; defaults to the resource identifier.</param>
    /// <exception cref="ArgumentException">The host is not a valid RFC 3986 §3.2.2 host.</exception>
    internal static void ThrowIfInvalidHost(string resource, string paramName, string subject = DefaultSubject)
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

        if (authorityEnd <= authorityStart)
        {
            return;
        }

        // Host boundaries, matching the malformed-port gate: after any userinfo,
        // and up to the port delimiter, which is the first ':' outside an IPv6
        // literal's brackets (RFC 3986 §3.2.2).
        var hostStart = resource.LastIndexOf('@', authorityEnd - 1, authorityEnd - authorityStart) + 1;
        if (hostStart <= 0)
        {
            hostStart = authorityStart;
        }

        if (hostStart >= authorityEnd)
        {
            // The authority is userinfo and nothing else ("https://user@"), so
            // there is no host to read a character out of. The absoluteness
            // gate behind this one reports the missing host with a message;
            // indexing here would fail with no message at all.
            return;
        }

        var hostEnd = authorityEnd;
        var bracket = resource.LastIndexOf(']', authorityEnd - 1, authorityEnd - hostStart);
        var searchFrom = bracket >= 0 ? bracket + 1 : hostStart;
        if (searchFrom < authorityEnd)
        {
            var colon = resource.IndexOf(':', searchFrom, authorityEnd - searchFrom);
            if (colon >= 0)
            {
                hostEnd = colon;
            }
        }

        // An IP-literal is bracketed, and its body admits ':' for IPv6 plus the
        // RFC 6874 zone identifier, whose "%25" prefix and name are pct-encoded
        // and unreserved characters. Everything else is a reg-name.
        var isIpLiteral = resource[hostStart] == '[';
        var scanStart = isIpLiteral ? hostStart + 1 : hostStart;
        var scanEnd = isIpLiteral && hostEnd > scanStart && resource[hostEnd - 1] == ']'
            ? hostEnd - 1
            : hostEnd;

        for (var i = scanStart; i < scanEnd; i++)
        {
            var c = resource[i];
            if (c == '%')
            {
                if (i + 2 >= scanEnd
                    || !char.IsAsciiHexDigit(resource[i + 1])
                    || !char.IsAsciiHexDigit(resource[i + 2]))
                {
                    var escape = resource[i..Math.Min(i + 3, scanEnd)];
                    throw new ArgumentException(
                        $"{subject} host contains a malformed percent-encoding ('{escape}' at offset {i}); "
                            + $"every '%' must be followed by two hex digits (RFC 3986 §2.1), got '{Redact(resource, resource.Length)}'.",
                        paramName);
                }

                i += 2;
                continue;
            }

            if (IsRegNameChar(c) || (isIpLiteral && c == ':'))
            {
                continue;
            }

            // Named by code point past ASCII, matching the path and query gates:
            // 'é' would print, but a zero-width space is invisible and half a
            // surrogate pair is not a character.
            var shown = c <= 0x7E ? $"'{c}'" : $"U+{(int)c:X4}";
            throw new ArgumentException(
                $"{subject} host contains a character ({shown}) at offset {i} outside the RFC 3986 §3.2.2 "
                    + "host production, which admits only ASCII; configure an internationalized host as its A-label "
                    + $"(for example 'xn--caf-dma.example.com' rather than 'café.example.com'), got '{Redact(resource, resource.Length)}'.",
                paramName);
        }
    }

    /// <summary>
    /// RFC 3986 §3.2.2 <c>reg-name</c> characters other than pct-encoded:
    /// unreserved (ALPHA / DIGIT / "-" / "." / "_" / "~") and sub-delims
    /// ("!" / "$" / "&amp;" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=").
    /// Neither ':' nor '@' is included: they delimit the port and the userinfo,
    /// and both sit outside the host slice this is applied to.
    /// </summary>
    private static bool IsRegNameChar(char c) =>
        char.IsAsciiLetterOrDigit(c)
        || c is '-' or '.' or '_' or '~'
        or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=';

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
