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

        public Options(
            string issuer,
            string resource,
            IReadOnlyList<string> scopes,
            bool devMode = false,
            string? realm = null,
            InboundDPoPOptions? inboundDpop = null)
        {
            Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            Resource = resource ?? throw new ArgumentNullException(nameof(resource));
            Scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
            DevMode = devMode;
            Realm = realm;
            InboundDPoP = inboundDpop;
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

