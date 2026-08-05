namespace Authplane;

public sealed partial class AuthplaneAuthClient : IAsyncDisposable
{
    private readonly HttpClient _httpClient;
    private readonly CircuitBreaker _circuitBreaker;
    private readonly OAuthOperations.Context _oauthContext;
    private readonly TokenCache _tokenCache;

    public AuthplaneAuthClient(
        string issuerUrl,
        string clientId,
        string clientSecret,
        FetchSettings? fetchSettings = null,
        IDPoPSigner? dpopSigner = null,
        AuthplaneAuthResilienceOptions? resilience = null,
        IDPoPNonceStore? dpopNonceStore = null)
        : this(
            issuerUrl: RequireIssuer(issuerUrl),
            authProvider: BuildClientCredentialsProvider(clientId, clientSecret),
            clientId: clientId,
            clientSecret: clientSecret,
            fetchSettings: fetchSettings,
            dpopSigner: dpopSigner,
            resilience: resilience,
            dpopNonceStore: dpopNonceStore)
    {
    }

    /// <summary>
    /// Construct an auth client using a pluggable <see cref="IAuthProvider"/>.
    /// Use this overload when client authentication is something other than
    /// HTTP Basic — e.g. mTLS via a custom <see cref="HttpClient"/>, or any
    /// header-based scheme that <see cref="IAuthProvider.AuthHeaders"/> can
    /// supply. The legacy (issuerUrl, clientId, clientSecret) constructor
    /// remains the convenient choice for confidential clients with a shared
    /// secret.
    /// </summary>
    /// <remarks>
    /// RFC 7523 <c>client_secret_jwt</c> / <c>private_key_jwt</c> are NOT
    /// supported through this interface today: they require
    /// <c>client_assertion</c> / <c>client_assertion_type</c> as request-body
    /// parameters (not headers), which <see cref="IAuthProvider.AuthHeaders"/>
    /// cannot supply. Track support in a follow-up if needed.
    /// </remarks>
    public AuthplaneAuthClient(
        string issuerUrl,
        IAuthProvider authProvider,
        FetchSettings? fetchSettings = null,
        IDPoPSigner? dpopSigner = null,
        AuthplaneAuthResilienceOptions? resilience = null,
        IDPoPNonceStore? dpopNonceStore = null)
        : this(
            issuerUrl: RequireIssuer(issuerUrl),
            authProvider: authProvider ?? throw new ArgumentNullException(nameof(authProvider)),
            clientId: string.Empty,
            clientSecret: string.Empty,
            fetchSettings: fetchSettings,
            dpopSigner: dpopSigner,
            resilience: resilience,
            dpopNonceStore: dpopNonceStore)
    {
    }

    // Pre-validated inputs only — every public constructor funnels here so the
    // endpoint pre-flight, HttpClient creation, context wiring, and circuit /
    // cache instantiation live in exactly one place. Empty `clientId` /
    // `clientSecret` mean "credentials come from `authProvider`, not from the
    // legacy basic-auth fallback in OAuthHttpClient."
    private AuthplaneAuthClient(
        string issuerUrl,
        IAuthProvider authProvider,
        string clientId,
        string clientSecret,
        FetchSettings? fetchSettings,
        IDPoPSigner? dpopSigner,
        AuthplaneAuthResilienceOptions? resilience,
        IDPoPNonceStore? dpopNonceStore)
    {
        var settings = fetchSettings ?? FetchSettings.FromDevMode(devMode: false);
        TransportSecurity.ValidateFetchUrl(
            OAuthEndpoints.TokenUrl(issuerUrl), settings, "token endpoint");
        TransportSecurity.ValidateFetchUrl(
            OAuthEndpoints.IntrospectionUrl(issuerUrl), settings, "introspection endpoint");
        TransportSecurity.ValidateFetchUrl(
            OAuthEndpoints.RevocationUrl(issuerUrl), settings, "revocation endpoint");
        _httpClient = TransportSecurity.CreateHttpClient(settings);
        _oauthContext = new OAuthOperations.Context(
            IssuerUrl: issuerUrl,
            ClientId: clientId,
            ClientSecret: clientSecret,
            HttpClient: _httpClient,
            DPoPSigner: dpopSigner,
            FetchSettings: settings,
            DPoPNonceStore: dpopNonceStore,
            AuthProvider: authProvider);

        var r = resilience ?? new AuthplaneAuthResilienceOptions();
        _circuitBreaker = new CircuitBreaker(
            r.CircuitBreakerThreshold,
            TimeSpan.FromSeconds(r.CircuitBreakerCooldownSeconds));
        _tokenCache = new TokenCache();
    }

    // Mirrors the legacy empty-vs-whitespace contract callers depend on: an
    // empty `issuerUrl` throws ArgumentNullException, not ArgumentException.
    // Public ctors call this in their `: this(...)` chain so the throw happens
    // before any other work.
    private static string RequireIssuer(string issuerUrl)
        => !string.IsNullOrWhiteSpace(issuerUrl)
            ? issuerUrl
            : throw new ArgumentNullException(nameof(issuerUrl));

    // Materialize the legacy `clientId` + `clientSecret` pair as an
    // IAuthProvider. ClientCredentialsProvider would itself throw
    // ArgumentException on empty inputs; the public ctor's contract has
    // always been ArgumentNullException, so we pre-validate here.
    private static ClientCredentialsProvider BuildClientCredentialsProvider(
        string clientId,
        string clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentNullException(nameof(clientId));
        }
        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ArgumentNullException(nameof(clientSecret));
        }
        return new ClientCredentialsProvider(clientId, clientSecret);
    }

    /// <summary>
    /// Construct an auth client using a unified <see cref="DPoPProvider"/> for outbound
    /// DPoP. The provider supplies both the proof signer and the nonce store; callers
    /// no longer need to wire them as two separate arguments —
    /// <see cref="DPoPProvider"/> is the single canonical input.
    /// </summary>
    public AuthplaneAuthClient(
        string issuerUrl,
        string clientId,
        string clientSecret,
        DPoPProvider dpopProvider,
        FetchSettings? fetchSettings = null,
        AuthplaneAuthResilienceOptions? resilience = null)
        : this(
            issuerUrl: issuerUrl,
            clientId: clientId,
            clientSecret: clientSecret,
            fetchSettings: fetchSettings,
            dpopSigner: dpopProvider ?? throw new ArgumentNullException(nameof(dpopProvider)),
            resilience: resilience,
            dpopNonceStore: dpopProvider.NonceStore)
    {
    }

    /// <summary>
    /// Construct an auth client using a pluggable <see cref="IAuthProvider"/> together
    /// with a unified <see cref="DPoPProvider"/>.
    /// </summary>
    public AuthplaneAuthClient(
        string issuerUrl,
        IAuthProvider authProvider,
        DPoPProvider dpopProvider,
        FetchSettings? fetchSettings = null,
        AuthplaneAuthResilienceOptions? resilience = null)
        : this(
            issuerUrl: issuerUrl,
            authProvider: authProvider,
            fetchSettings: fetchSettings,
            dpopSigner: dpopProvider ?? throw new ArgumentNullException(nameof(dpopProvider)),
            resilience: resilience,
            dpopNonceStore: dpopProvider.NonceStore)
    {
    }

    /// <summary>
    /// Construct an auth client using <see cref="ASCredentials"/> as a single value
    /// holder for the <c>client_id</c> / <c>client_secret</c> pair. Equivalent to the
    /// <c>(issuerUrl, clientId, clientSecret, …)</c> overload, but the same record can
    /// be shared across introspection, revocation, and exchange wiring.
    /// </summary>
    public AuthplaneAuthClient(
        string issuerUrl,
        ASCredentials asCredentials,
        FetchSettings? fetchSettings = null,
        IDPoPSigner? dpopSigner = null,
        AuthplaneAuthResilienceOptions? resilience = null,
        IDPoPNonceStore? dpopNonceStore = null)
        : this(
            issuerUrl: issuerUrl,
            clientId: (asCredentials ?? throw new ArgumentNullException(nameof(asCredentials))).ClientId,
            clientSecret: asCredentials.ClientSecret,
            fetchSettings: fetchSettings,
            dpopSigner: dpopSigner,
            resilience: resilience,
            dpopNonceStore: dpopNonceStore)
    {
    }

    /// <summary>
    /// <see cref="ASCredentials"/> overload bundling the unified <see cref="DPoPProvider"/>.
    /// </summary>
    public AuthplaneAuthClient(
        string issuerUrl,
        ASCredentials asCredentials,
        DPoPProvider dpopProvider,
        FetchSettings? fetchSettings = null,
        AuthplaneAuthResilienceOptions? resilience = null)
        : this(
            issuerUrl: issuerUrl,
            clientId: (asCredentials ?? throw new ArgumentNullException(nameof(asCredentials))).ClientId,
            clientSecret: asCredentials.ClientSecret,
            dpopProvider: dpopProvider,
            fetchSettings: fetchSettings,
            resilience: resilience)
    {
    }

    /// <summary>Effective circuit state for tests and observability.</summary>
    public CircuitBreakerState CircuitBreakerState => _circuitBreaker.EffectiveState;

    public Task<TokenResponse> ClientCredentialsAsync(
        string? scope,
        string? resource = null,
        CancellationToken cancellationToken = default)
        => ClientCredentialsAsync(scope, resource, useCache: true, cancellationToken);

    /// <summary>
    /// Client credentials grant. When <paramref name="useCache"/> is true (default),
    /// a previously-issued token for the same <paramref name="scope"/> +
    /// <paramref name="resource"/> is reused within its remaining lifetime; pass
    /// <c>false</c> to force a fresh AS round-trip (e.g. after a 401 from a
    /// resource server, where the cached token is presumed compromised / revoked).
    /// </summary>
    public Task<TokenResponse> ClientCredentialsAsync(
        string? scope,
        string? resource,
        bool useCache,
        CancellationToken cancellationToken = default)
    {
        if (!useCache)
        {
            return ExecuteWithCircuitAsync(
                () => OAuthOperations.ClientCredentialsAsync(_oauthContext, scope, resource, cancellationToken));
        }

        // Check the circuit BEFORE the cache lookup so an open circuit sheds
        // requests even when there's a still-valid cached token. Without
        // this, a cache hit would silently bypass the breaker — the breaker
        // is a backpressure signal to callers, not just AS protection.
        if (!_circuitBreaker.AllowRequest())
        {
            throw new CircuitOpenException();
        }

        // Per-(client_id, scope, resource) cache (TokenCache) — successful
        // responses with an `expires_in` hint are reused across calls within
        // their lifetime minus a 30s buffer. The principal is part of the
        // key so a caller that ever shares this cache across multiple
        // confidential clients cannot serve a token issued to one client in
        // response to a request from another. Failures throw and are never cached.
        return _tokenCache.GetOrFetchAsync(
            scope: scope,
            resource: resource,
            factory: ct => ExecuteWithCircuitAsync(
                () => OAuthOperations.ClientCredentialsAsync(
                    _oauthContext,
                    scope,
                    resource,
                    ct)),
            cancellationToken: cancellationToken,
            clientId: _oauthContext.ClientId);
    }

    /// <summary>
    /// Client credentials grant with multiple resource indicators (RFC 8707).
    /// Each resource is emitted as a separate <c>resource</c> form parameter.
    /// </summary>
    public Task<TokenResponse> ClientCredentialsAsync(
        string? scope,
        System.Collections.Generic.IReadOnlyList<string>? resources,
        CancellationToken cancellationToken = default)
        => ClientCredentialsAsync(scope, resources, useCache: true, cancellationToken);

    /// <summary>
    /// Client credentials grant (multi-resource). See the single-resource overload
    /// for the <paramref name="useCache"/> contract.
    /// </summary>
    public Task<TokenResponse> ClientCredentialsAsync(
        string? scope,
        System.Collections.Generic.IReadOnlyList<string>? resources,
        bool useCache,
        CancellationToken cancellationToken = default)
    {
        if (!useCache)
        {
            return ExecuteWithCircuitAsync(
                () => OAuthOperations.ClientCredentialsAsync(_oauthContext, scope, resources, cancellationToken));
        }

        if (!_circuitBreaker.AllowRequest())
        {
            throw new CircuitOpenException();
        }

        // Multi-resource keys: filter blanks (matching what OAuthOperations
        // actually sends) and join with `,` so the cache key reflects the wire
        // request. Order is preserved (RFC 8707 treats `resource` parameters as
        // an ordered set).
        var resourceKey = resources is null
            ? null
            : string.Join(',', resources.Where(r => !string.IsNullOrWhiteSpace(r)));
        return _tokenCache.GetOrFetchAsync(
            scope: scope,
            resource: resourceKey,
            factory: ct => ExecuteWithCircuitAsync(
                () => OAuthOperations.ClientCredentialsAsync(
                    _oauthContext,
                    scope,
                    resources,
                    ct)),
            cancellationToken: cancellationToken,
            clientId: _oauthContext.ClientId);
    }

    /// <summary>
    /// Drop any cached <c>client_credentials</c> token for the given
    /// <paramref name="scope"/> + <paramref name="resource"/> so the next call
    /// re-issues. Use after a 401 from a downstream resource server.
    /// Single-resource overload — for entries fetched with multiple resources,
    /// use the <see cref="InvalidateClientCredentialsCache(string?, System.Collections.Generic.IReadOnlyList{string}?)"/>
    /// overload (or <see cref="ClearClientCredentialsCache"/>).
    /// </summary>
    public void InvalidateClientCredentialsCache(string? scope = null, string? resource = null)
        => _tokenCache.Invalidate(scope, resource, _oauthContext.ClientId);

    /// <summary>
    /// Drop any cached <c>client_credentials</c> token keyed off the given
    /// <paramref name="scope"/> + ordered <paramref name="resources"/> list, so
    /// the next call re-issues. Mirrors the multi-resource fetch path
    /// (<see cref="ClientCredentialsAsync(string?, System.Collections.Generic.IReadOnlyList{string}?, bool, CancellationToken)"/>):
    /// blanks are dropped and the remaining values are joined with <c>,</c> in
    /// order, matching the wire request and RFC 8707 ordered-set semantics.
    /// </summary>
    public void InvalidateClientCredentialsCache(
        string? scope,
        System.Collections.Generic.IReadOnlyList<string>? resources)
    {
        var resourceKey = resources is null
            ? null
            : string.Join(',', resources.Where(r => !string.IsNullOrWhiteSpace(r)));
        _tokenCache.Invalidate(scope, resourceKey, _oauthContext.ClientId);
    }

    /// <summary>Drop the entire client-credentials cache (e.g. on credential rotation).</summary>
    public void ClearClientCredentialsCache() => _tokenCache.Clear();

    /// <summary>
    /// Introspect token status (RFC 7662). Uses the configured
    /// <see cref="IAuthProvider"/> for client authentication (HTTP Basic by
    /// default; any header-based scheme an alternate provider supplies).
    /// </summary>
    public Task<IntrospectionResponse> IntrospectAsync(
        string token,
        string tokenTypeHint = OAuthConstants.TokenTypeHintAccessToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        return ExecuteWithCircuitAsync(
            () => OAuthOperations.IntrospectAsync(_oauthContext, token, cancellationToken, tokenTypeHint));
    }

    /// <summary>
    /// Perform a token exchange (RFC 8693). Uses DPoP proof at the token endpoint if configured.
    /// </summary>
    public Task<TokenResponse> TokenExchangeAsync(
        TokenExchangeOptions opts,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(opts);

        return ExecuteWithCircuitAsync(
            () => OAuthOperations.TokenExchangeAsync(
                _oauthContext,
                opts,
                cancellationToken));
    }

    private async Task<T> ExecuteWithCircuitAsync<T>(Func<Task<T>> operation)
    {
        if (!_circuitBreaker.AllowRequest())
        {
            throw new CircuitOpenException();
        }

        try
        {
            var result = await operation().ConfigureAwait(false);
            _circuitBreaker.RecordSuccess();
            return result;
        }
        catch (Exception ex)
        {
            HandleFailure(ex);
            throw;
        }
    }

    private void HandleFailure(Exception ex)
    {
        if (CircuitPolicy.ShouldRecordFailure(ex))
        {
            _circuitBreaker.RecordFailure();
        }
    }

    public ValueTask DisposeAsync()
    {
        // HttpClient.Dispose is synchronous, but exposing this as
        // IAsyncDisposable keeps the door open for handlers that later
        // grow async-dispose semantics (e.g. SocketsHttpHandler).
        // Also clear the in-memory token cache so disposal actually
        // releases the secrets it was holding — previously they
        // survived until GC.
        _httpClient.Dispose();
        _tokenCache.Clear();
        return ValueTask.CompletedTask;
    }
}
