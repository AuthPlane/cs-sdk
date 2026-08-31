using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Authplane;

/// <summary>
/// Shared infrastructure for one authorization server: HTTP client, RFC 8414 / OIDC discovery for JWKS URI, and JWKS cache.
/// Create resources via <see cref="CreateResourceAsync"/>.
/// </summary>
public sealed class AuthplaneClient : IAsyncDisposable
{
    private readonly HttpClient _httpClient;
    private readonly JwksCache _jwksCache;
    private readonly MetadataCache _metadataCache;

    private AuthplaneClient(string issuer, FetchSettings fetchSettings)
    {
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        FetchSettings = fetchSettings ?? throw new ArgumentNullException(nameof(fetchSettings));
        _httpClient = TransportSecurity.CreateHttpClient(fetchSettings);

        // Cache the AS metadata document with conditional-GET / stale-fallback so a
        // `jwks_uri` rotation propagates without requiring the client to be recreated.
        _metadataCache = new MetadataCache(
            fetcher: ct => FetchMetadataAsync(issuer, fetchSettings, _httpClient, ct),
            refreshInterval: TimeSpan.FromHours(1));

        // JwksCache provides stampede protection, stale-fallback, and force-refresh
        // on kid miss. The fetcher consults the metadata cache for the current
        // `jwks_uri` on every refresh.
        _jwksCache = new JwksCache(async ct =>
        {
            var metadata = await _metadataCache.GetAsync(ct).ConfigureAwait(false);
            var jwksUri = metadata.JwksUri;
            TransportSecurity.ValidateFetchUrl(jwksUri, FetchSettings, "jwks_uri");

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.GetAsync(jwksUri, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new JwksFetchException("Failed to fetch JWKS: " + ex.Message, ex);
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new JwksFetchException($"Failed to fetch JWKS: HTTP {(int)response.StatusCode}");
            }

            string body;
            try
            {
                body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new JwksFetchException("Failed to read JWKS response body: " + ex.Message, ex);
            }

            JsonWebKeySet jwks;
            try
            {
                jwks = new JsonWebKeySet(body);
            }
            catch (Exception ex)
            {
                throw new JwksFetchException("Failed to parse JWKS document: " + ex.Message, ex);
            }

            // RFC 7234: honour server cache hints for JWKS refresh interval.
            // Distinguish "no header" (null → use default refresh interval) from
            // "explicitly stale" (Zero → no-store / no-cache / past Expires →
            // force re-fetch on next Get). Previously both collapsed to null,
            // so no-store endpoints were cached for the full default TTL.
            TimeSpan? serverTtl = null;
            var serverExpiry = CacheHeaders.ParseExpiresAt(response.Headers);
            if (serverExpiry is { } expiry)
            {
                var ttl = expiry - DateTimeOffset.UtcNow;
                serverTtl = ttl > TimeSpan.Zero ? ttl : TimeSpan.Zero;
            }

            return new JwksFetchResult(jwks, serverTtl);
        }, refreshInterval: TimeSpan.FromMinutes(5));
    }

    public string Issuer { get; }

    public FetchSettings FetchSettings { get; }

    /// <summary>
    /// Creates a client and primes the metadata cache via RFC 8414 OAuth AS metadata or
    /// OpenID Connect discovery. Throws if neither endpoint is reachable so configuration
    /// problems fail fast rather than at first verify.
    /// </summary>
    public static async Task<AuthplaneClient> CreateAsync(
        string issuer,
        FetchSettings? fetchSettings = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);

        var settings = fetchSettings ?? FetchSettings.FromDevMode(devMode: false);
        var client = new AuthplaneClient(issuer, settings);
        // Force initial metadata fetch so a bad issuer fails at CreateAsync rather than
        // at the first token-verify call.
        await client._metadataCache.GetAsync(cancellationToken).ConfigureAwait(false);
        return client;
    }

    /// <summary>
    /// Creates an <see cref="AuthplaneResource"/> bound to this client, sharing
    /// its JWKS cache, metadata cache, and HTTP stack. Prefer this over
    /// <see cref="AuthplaneResource.CreateAsync"/> when a process hosts more than
    /// one RS against the same AS.
    /// </summary>
    /// <param name="resource">Resource identifier this RS publishes (RFC 9728).
    /// Must be an absolute URL with a scheme and a host (RFC 8707 §2,
    /// RFC 9728 §3) and must not contain a fragment component (RFC 8707 §2,
    /// RFC 9728 §1.2); violations are rejected here rather than silently
    /// producing a malformed metadata URL.</param>
    /// <param name="scopes">Scopes this RS requires; surfaced in PRM and on 401
    /// challenges.</param>
    /// <param name="revocationChecker">Optional revocation hook (RFC 7009).</param>
    /// <param name="failClosed">If true, revocation-check transport failures
    /// reject the token; the default <c>false</c> fails open.</param>
    /// <param name="clockSkewSeconds">Tolerance applied to <c>exp</c>/<c>iat</c>/<c>nbf</c>;
    /// default 30s.</param>
    /// <param name="inboundDpop">Per-resource DPoP enforcement options (RFC 9449
    /// inbound). When null, DPoP is off and only Bearer is accepted.</param>
    /// <param name="allowedAlgorithms">Subset of <c>SupportedAccessTokenAlgorithms</c>
    /// this RS will accept on the access token. Null defaults to the standard
    /// allowlist.</param>
    /// <param name="cancellationToken">Cancels the synchronous setup
    /// (no I/O on the happy path; the metadata fetch already happened on this
    /// client).</param>
    public Task<AuthplaneResource> CreateResourceAsync(
        string resource,
        System.Collections.Generic.IEnumerable<string> scopes,
        IRevocationChecker? revocationChecker = null,
        bool failClosed = false,
        long clockSkewSeconds = 30,
        InboundDPoPOptions? inboundDpop = null,
        System.Collections.Generic.IEnumerable<string>? allowedAlgorithms = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);

        ArgumentNullException.ThrowIfNull(scopes);

        var scopeList = scopes is System.Collections.Generic.IReadOnlyList<string> ro
            ? ro
            : new System.Collections.Generic.List<string>(scopes);

        var resourceObj = new AuthplaneResource(
            this, resource, scopeList, ownsClient: false,
            revocationChecker: revocationChecker,
            failClosed: failClosed,
            clockSkewSeconds: clockSkewSeconds,
            inboundDpop: inboundDpop,
            allowedAlgorithms: allowedAlgorithms);
        return Task.FromResult(resourceObj);
    }

    internal async Task<JsonWebKey> GetSigningKeyAsync(string kid, CancellationToken cancellationToken, string? tokenAlg = null)
    {
        // Try cached set first.
        var jwks = await _jwksCache.GetAsync(cancellationToken).ConfigureAwait(false);
        var signingKey = SelectSigningKey(jwks, kid, tokenAlg);
        if (signingKey is not null)
        {
            return signingKey;
        }

        // Kid not found — force-refresh once (key rotation scenario).
        await _jwksCache.ForceRefreshAsync(cancellationToken).ConfigureAwait(false);
        jwks = await _jwksCache.GetAsync(cancellationToken).ConfigureAwait(false);
        signingKey = SelectSigningKey(jwks, kid, tokenAlg);
        if (signingKey is null)
        {
            throw new InvalidSignatureException($"Token kid '{kid}' not found in JWKS.");
        }

        return signingKey;
    }

    /// <summary>
    /// Selects a JWK from the key set matching kid, and also honoring use, key_ops, and alg
    /// per RFC 8725 best practices.
    /// </summary>
    private static JsonWebKey? SelectSigningKey(JsonWebKeySet jwks, string kid, string? tokenAlg = null)
    {
        foreach (var k in jwks.Keys)
        {
            if (!string.Equals(k.Kid, kid, StringComparison.Ordinal))
            {
                continue;
            }

            // Skip keys explicitly marked for a purpose other than signing
            if (!string.IsNullOrEmpty(k.Use) && !string.Equals(k.Use, "sig", StringComparison.Ordinal))
            {
                continue;
            }

            // Skip keys whose key_ops does not include "verify"
            if (k.KeyOps is not null && k.KeyOps.Count > 0 && !k.KeyOps.Contains("verify"))
            {
                continue;
            }

            // Skip keys whose alg doesn't match the requested algorithm
            if (!string.IsNullOrEmpty(k.Alg) && tokenAlg is not null
                && !string.Equals(k.Alg, tokenAlg, StringComparison.Ordinal))
            {
                continue;
            }

            return k;
        }

        return null;
    }

    private static async Task<MetadataFetchResult> FetchMetadataAsync(
        string issuer,
        FetchSettings fetchSettings,
        HttpClient http,
        CancellationToken cancellationToken)
    {
        // RFC 8414 §3.3: issuer comparison MUST be identical on both sides — byte for
        // byte. Do not trim the configured value either; a configured trailing slash
        // must match a trailing slash in the metadata document.
        var candidates = new[]
        {
            MetadataUrlBuilder.BuildOAuthAuthorizationServerMetadataUrl(issuer),
            MetadataUrlBuilder.BuildOpenIdConfigurationMetadataUrl(issuer),
        };

        // When every candidate URL fails, surface the LAST validation failure
        // (issuer mismatch / missing field) so the caller sees the actual
        // problem rather than the generic "neither endpoint reachable". The
        // exception type stays MissingMetadataEndpointException (callers can
        // still catch it), with the validation issue chained.
        MetadataFetchException? lastValidationFailure = null;
        Exception? lastTransportFailure = null;

        foreach (var url in candidates)
        {
            TransportSecurity.ValidateFetchUrl(url, fetchSettings, "metadata discovery URL");
            try
            {
                using var resp = await http.GetAsync(url, cancellationToken).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    continue;
                }

                var json = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);

                // RFC 8414 §3.3: issuer in metadata MUST be identical to configured issuer.
                if (doc.RootElement.TryGetProperty("issuer", out var issuerProp) &&
                    issuerProp.ValueKind == JsonValueKind.String)
                {
                    var metadataIssuer = issuerProp.GetString();
                    if (!string.Equals(issuer, metadataIssuer, StringComparison.Ordinal))
                    {
                        throw new MetadataFetchException(
                            $"Metadata issuer mismatch: configured '{issuer}' but metadata document reports '{metadataIssuer}'.");
                    }
                }
                else
                {
                    throw new MetadataFetchException(
                        "Metadata document is missing the required 'issuer' field.");
                }

                // jwks_uri is required for JWT validation.
                if (!doc.RootElement.TryGetProperty("jwks_uri", out var jwks) ||
                    jwks.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(jwks.GetString()))
                {
                    throw new MetadataFetchException(
                        "Metadata document is missing the required 'jwks_uri' field.");
                }

                var jwksUri = jwks.GetString()!;
                TransportSecurity.ValidateFetchUrl(jwksUri, fetchSettings, "jwks_uri");

                // See JWKS fetcher above — null means "no header", Zero means
                // "explicitly stale" (no-store / no-cache / past Expires).
                TimeSpan? serverTtl = null;
                var serverExpiry = CacheHeaders.ParseExpiresAt(resp.Headers);
                if (serverExpiry is { } expiry)
                {
                    var ttl = expiry - DateTimeOffset.UtcNow;
                    serverTtl = ttl > TimeSpan.Zero ? ttl : TimeSpan.Zero;
                }

                return new MetadataFetchResult(
                    new MetadataDocument(Issuer: issuer, JwksUri: jwksUri),
                    serverTtl);
            }
            catch (MetadataFetchException ex)
            {
                // Validation failure on this discovery URL (issuer mismatch, missing
                // issuer / jwks_uri). Fall through to the next URL — the alternative
                // endpoint may serve a well-formed document. Keep
                // the most recent validation error so we can surface it if every
                // candidate fails.
                lastValidationFailure = ex;
            }
            catch (AuthplaneException)
            {
                // URL-policy / SSRF rejection from TransportSecurity. Propagate;
                // the issuer itself is unsafe, no alternative endpoint will help.
                throw;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Caller cancellation must propagate. Falling into the generic
                // transport-failure catch would otherwise loop to the next
                // candidate (which re-cancels immediately) and surface as
                // MissingMetadataEndpointException, hiding the cancellation.
                throw;
            }
            catch (Exception ex)
            {
                // Transport / parse failure — try next discovery URL but keep
                // the cause so it can be surfaced if every candidate fails.
                // Previously this was a bare `catch { }` and the operator was
                // told "neither endpoint reachable" with no root cause attached.
                lastTransportFailure = ex;
            }
        }

        // If every endpoint returned an INVALID document, surface that — the
        // operator-actionable error is "the document is wrong", not "I couldn't
        // reach you". When the failure is genuinely transport (e.g. neither
        // endpoint was reachable), surface the most recent transport cause.
        if (lastValidationFailure is not null)
        {
            throw new MissingMetadataEndpointException(
                $"Failed to discover JWKS URI for issuer '{issuer}': {lastValidationFailure.Message}");
        }

        if (lastTransportFailure is not null)
        {
            throw new MissingMetadataEndpointException(
                $"Failed to discover JWKS URI: neither OAuth Authorization Server metadata nor OpenID Configuration " +
                $"metadata could be fetched from issuer '{issuer}'. Last transport error: {lastTransportFailure.Message}. " +
                $"Candidates: {string.Join(", ", candidates)}",
                lastTransportFailure);
        }

        throw new MissingMetadataEndpointException(
            $"Failed to discover JWKS URI: neither OAuth Authorization Server metadata nor OpenID Configuration " +
            $"metadata could be fetched from issuer '{issuer}'. Ensure the authorization server is reachable " +
            $"and serves a valid metadata document at one of: {string.Join(", ", candidates)}");
    }

    public async ValueTask DisposeAsync()
    {
        await _jwksCache.DisposeAsync().ConfigureAwait(false);
        await _metadataCache.DisposeAsync().ConfigureAwait(false);
        _httpClient.Dispose();
    }
}
