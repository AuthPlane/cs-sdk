namespace Authplane.Mcp;

/// <summary>
/// Convenience APIs to plug Authplane JWT validation into MCP C# servers.
/// </summary>
public static class AuthplaneMcpAuth
{
    /// <summary>
    /// Basic configuration options for Authplane + MCP.
    /// </summary>
    public sealed class Options
    {
        public string Issuer { get; }
        public string Resource { get; }
        public IReadOnlyList<string> Scopes { get; }
        public bool DevMode { get; }

        /// <summary>
        /// Optional realm value for WWW-Authenticate challenges (RFC 6750 §3).
        /// When non-null, included as the <c>realm</c> parameter in all Bearer challenges.
        /// </summary>
        public string? Realm { get; }

        /// <summary>
        /// Optional inbound DPoP enforcement options (RFC 9449). When non-null the
        /// configured <see cref="AuthplaneResource"/> accepts (or requires)
        /// DPoP-bound access tokens, the PRM document advertises DPoP, and the
        /// middleware's WWW-Authenticate challenges include the DPoP scheme.
        /// When null the entire MCP integration is Bearer-only: the verifier
        /// rejects any inbound DPoP signal, the PRM omits DPoP fields, and the
        /// challenge advertises Bearer alone. Leaving this null while the
        /// challenge still advertised DPoP was the source of a real bug where
        /// clients negotiated DPoP and then had every request rejected as
        /// <c>DPoPNotSupportedException</c>.
        /// </summary>
        public InboundDPoPOptions? InboundDPoP { get; }

        /// <summary>
        /// Optional absolute URL advertised as the <c>resource_metadata</c>
        /// parameter of every WWW-Authenticate challenge (RFC 9728 §5.1) in
        /// place of the URL derived from <see cref="Resource"/>. Use it when the
        /// Protected Resource Metadata document is hosted by the authorization
        /// server rather than by this resource — authserver serves one per
        /// registered Resource at
        /// <c>{issuer}/.well-known/oauth-protected-resource/{ref}</c>. Null
        /// (the default) keeps the derived resource-hosted URL, and the
        /// middleware keeps serving that document regardless of this value.
        /// The <c>resource</c> field of the document at this URL must equal
        /// <see cref="Resource"/> byte for byte (RFC 9728 §3.3), or clients
        /// discard it.
        /// </summary>
        public string? ResourceMetadataUrl { get; }

        public Options(
            string issuer,
            string resource,
            IReadOnlyList<string> scopes,
            bool devMode = false,
            string? realm = null,
            InboundDPoPOptions? inboundDpop = null,
            string? resourceMetadataUrl = null)
        {
            Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            Resource = resource ?? throw new ArgumentNullException(nameof(resource));
            // The single operator-facing entry for the adapter: every
            // downstream consumer of the identifier — CreateResourceAsync,
            // SetupAsync, and UseAuthplaneMcpAuth's DPoP htu origin — receives
            // it through this Options instance, so gating here makes a
            // misconfigured identifier fail where the operator writes it, at
            // startup. In particular the user guide's lazy DI wiring defers
            // CreateResourceAsync (and the AuthplaneResource constructor
            // gates) to the first request; without this copy, `/mcp` would
            // boot cleanly and then take an unhandled exception out of the
            // middleware on the first request, including the public PRM GET.
            ResourceIdentifiers.ThrowIfFragment(resource, nameof(resource));
            ResourceIdentifiers.ThrowIfWhitespaceOrBackslash(resource, nameof(resource));
            ResourceIdentifiers.ThrowIfMalformedPort(resource, nameof(resource));
            ResourceIdentifiers.ThrowIfInvalidHost(resource, nameof(resource));
            ResourceIdentifiers.ThrowIfNotAbsoluteUrl(resource, nameof(resource));
            ResourceIdentifiers.ThrowIfUserInfo(resource, nameof(resource));
            ResourceIdentifiers.ThrowIfInvalidPath(resource, nameof(resource));
            ResourceIdentifiers.ThrowIfInvalidQuery(resource, nameof(resource));
            Scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
            DevMode = devMode;
            Realm = realm;
            InboundDPoP = inboundDpop;
            if (resourceMetadataUrl is not null)
            {
                ThrowIfInvalidResourceMetadataUrl(resourceMetadataUrl);
            }

            ResourceMetadataUrl = resourceMetadataUrl;
        }

        /// <summary>
        /// The override reaches the same <c>resource_metadata</c> quoted-string
        /// the resource identifier does, so it gets the identifier's whole gate
        /// set rather than a subset: an IDN host, a raw non-ASCII path segment,
        /// a malformed percent-escape or a bad port all parse into a
        /// <see cref="Uri"/> with a scheme and a host, ride into the challenge
        /// and out to unauthenticated clients, and fail discovery with nothing
        /// on the server side to say why. Same order as the identifier above,
        /// and the same <see cref="ArgumentException"/> at construction.
        ///
        /// Shape only: no scheme narrowing beyond http(s) and no host policy.
        /// The value is advertised, never fetched, so it carries no SSRF
        /// surface of its own, and <c>http</c> is accepted on any host because
        /// a loopback-only carve-out would refuse the in-cluster and
        /// docker-compose topologies dev mode exists to serve, so a single
        /// deployment configuration is accepted wherever this option is set.
        /// </summary>
        private static void ThrowIfInvalidResourceMetadataUrl(string resourceMetadataUrl)
        {
            const string subject = "resourceMetadataUrl";

            // Raw-string scans first, exactly as the resource gate orders them:
            // Uri.TryCreate trims surrounding whitespace before parsing, so a
            // trailing space or a backslash clears every check below and is
            // then stored and advertised verbatim. The challenge escaper
            // strips control characters but not U+0020, so the client fetches
            // a percent-encoded space and gets a 404 — a silent discovery
            // failure, which is the thing this gate exists to prevent.
            ResourceIdentifiers.ThrowIfFragment(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);
            ResourceIdentifiers.ThrowIfWhitespaceOrBackslash(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);
            ResourceIdentifiers.ThrowIfMalformedPort(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);
            ResourceIdentifiers.ThrowIfInvalidHost(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);
            ResourceIdentifiers.ThrowIfNotAbsoluteUrl(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);
            ResourceIdentifiers.ThrowIfUserInfo(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);
            ResourceIdentifiers.ThrowIfInvalidPath(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);
            ResourceIdentifiers.ThrowIfInvalidQuery(resourceMetadataUrl, nameof(resourceMetadataUrl), subject);

            // http(s) only: those are the schemes an OAuth client will
            // dereference, so anything else names a document nobody retrieves.
            if (!Uri.TryCreate(resourceMetadataUrl, UriKind.Absolute, out var uri) ||
                (!uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                 !uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException(
                    "resourceMetadataUrl scheme must be https or http (RFC 9728 §3).",
                    nameof(resourceMetadataUrl));
            }
        }
    }

    /// <summary>
    /// Create and configure an <see cref="AuthplaneResource"/> for use in an MCP C# server.
    /// </summary>
    /// <remarks>
    /// This initial iteration only returns the core verifier. A later iteration will wrap this
    /// into MCP-specific auth settings and token verifier types from the MCP C# SDK.
    /// </remarks>
    public static Task<AuthplaneResource> CreateResourceAsync(
        Options options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var fetchSettings = FetchSettings.FromDevMode(options.DevMode);

        return AuthplaneResource.CreateAsync(
            issuer: options.Issuer,
            resource: options.Resource,
            scopes: options.Scopes,
            fetchSettings: fetchSettings,
            inboundDpop: options.InboundDPoP,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Async-disposable handle exposing the configured <see cref="AuthplaneResource"/>
    /// alongside an ordered shutdown hook:
    /// callers <c>await using var handle = await AuthplaneMcpAuth.SetupAsync(options);</c>
    /// register <c>handle.Resource</c> with DI, and the underlying HTTP client / JWKS
    /// background refresh task are released when the handle is disposed.
    /// </summary>
    public sealed class AuthplaneMcpAuthHandle : IAsyncDisposable
    {
        /// <summary>The configured resource verifier. Register this with DI:
        /// <c>services.AddSingleton(handle.Resource);</c>.</summary>
        public AuthplaneResource Resource { get; }

        internal AuthplaneMcpAuthHandle(AuthplaneResource resource)
        {
            Resource = resource;
        }

        /// <summary>Release the underlying HTTP client + JWKS refresh background task.</summary>
        public ValueTask DisposeAsync() => Resource.DisposeAsync();
    }

    /// <summary>
    /// Setup factory that returns an <see cref="AuthplaneMcpAuthHandle"/> so the underlying
    /// <see cref="AuthplaneResource"/> can be disposed in a single call at host shutdown.
    /// </summary>
    public static async Task<AuthplaneMcpAuthHandle> SetupAsync(
        Options options,
        CancellationToken cancellationToken = default)
    {
        var resource = await CreateResourceAsync(options, cancellationToken).ConfigureAwait(false);
        return new AuthplaneMcpAuthHandle(resource);
    }

    /// <summary>
    /// Legacy compatibility: creates an <see cref="AuthplaneVerifier"/> wrapper instance.
    /// Prefer <see cref="CreateResourceAsync"/> going forward.
    /// </summary>
#pragma warning disable CS0618 // Obsolete: AuthplaneVerifier kept for backward compat
    public static Task<AuthplaneVerifier> CreateVerifierAsync(
        Options options,
        CancellationToken cancellationToken = default) =>
        AuthplaneVerifier.CreateAsync(
            issuer: options.Issuer,
            resource: options.Resource,
            scopes: options.Scopes,
            fetchSettings: FetchSettings.FromDevMode(options.DevMode),
            cancellationToken: cancellationToken);
#pragma warning restore CS0618
}

