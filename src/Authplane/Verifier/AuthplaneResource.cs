using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Authplane;

public sealed class AuthplaneResource : IAsyncDisposable
{
    /// <summary>
    /// JOSE algorithms the resource will trust on the access-token signature.
    /// Defaults to <c>["RS256","ES256"]</c>. Symmetric / <c>none</c> are always rejected.
    /// Returned as a <see cref="System.Collections.ObjectModel.ReadOnlyCollection{T}"/>
    /// so a caller cannot cast to <c>string[]</c> and mutate the policy.
    /// </summary>
    public IReadOnlyList<string> AllowedAlgorithms { get; }

    private static readonly IReadOnlyList<string> DefaultAllowedAlgorithms =
        new System.Collections.ObjectModel.ReadOnlyCollection<string>(new[] { "RS256", "ES256" });

    private static readonly HashSet<string> SupportedAccessTokenAlgorithms =
        new(StringComparer.Ordinal) { "RS256", "ES256" };

    private readonly HashSet<string> _allowedAlgorithmsSet;

    /// <summary>
    /// JOSE algorithms accepted for inbound DPoP proofs at this resource. Used by adapters
    /// to advertise the <c>algs="…"</c> set in the RFC 9449 §7.1 <c>WWW-Authenticate: DPoP</c>
    /// challenge.
    /// Read-only wrapper — mutation through a cast is blocked.
    /// </summary>
    public static IReadOnlyList<string> AcceptedDPoPAlgorithms { get; } =
        new System.Collections.ObjectModel.ReadOnlyCollection<string>(new[] { "ES256", "RS256" });

    public string Issuer { get; }
    public string Resource { get; }
    public IReadOnlyList<string> Scopes { get; }
    public FetchSettings FetchSettings { get; }

    /// <summary>
    /// Clock skew (in seconds) tolerated when validating <c>exp</c>, <c>nbf</c>, <c>iat</c>
    /// on access tokens and on inbound DPoP proofs. Default <c>30</c>.
    /// </summary>
    public long ClockSkewSeconds { get; }

    private readonly AuthplaneClient _client;
    private readonly bool _ownsClient;
    private readonly IRevocationChecker? _revocationChecker;
    private readonly bool _failClosed;
    private readonly InboundDPoPOptions? _inboundDpop;
    private readonly InMemoryDPoPReplayStore _defaultReplayStore = new();

    /// <summary>
    /// Inbound DPoP configuration for this resource (null = not opted-in;
    /// any inbound DPoP signal is rejected with <see cref="DPoPNotSupportedException"/>).
    /// </summary>
    public InboundDPoPOptions? InboundDPoP => _inboundDpop;

    internal AuthplaneResource(
        AuthplaneClient client,
        string resource,
        IReadOnlyList<string> scopes,
        bool ownsClient,
        IRevocationChecker? revocationChecker = null,
        bool failClosed = false,
        long clockSkewSeconds = 30,
        InboundDPoPOptions? inboundDpop = null,
        IEnumerable<string>? allowedAlgorithms = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        Resource = resource ?? throw new ArgumentNullException(nameof(resource));
        // Authoritative identifier gates: every construction path — CreateAsync,
        // AuthplaneClient.CreateResourceAsync, and the MCP adapter's factory —
        // funnels through this constructor, so no configured resource can carry
        // a fragment, whitespace, a backslash, userinfo, or a malformed query
        // into the PRM document or the derived well-known URL, and no relative,
        // scheme-relative, or host-less identifier can derive a malformed one.
        // The fragment check runs first so an identifier broken both ways
        // reports the fragment.
        ResourceIdentifiers.ThrowIfFragment(Resource, nameof(resource));
        ResourceIdentifiers.ThrowIfWhitespaceOrBackslash(Resource, nameof(resource));
        ResourceIdentifiers.ThrowIfMalformedPort(Resource, nameof(resource));
        ResourceIdentifiers.ThrowIfNotAbsoluteUrl(Resource, nameof(resource));
        ResourceIdentifiers.ThrowIfUserInfo(Resource, nameof(resource));
        ResourceIdentifiers.ThrowIfInvalidQuery(Resource, nameof(resource));
        Scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        _ownsClient = ownsClient;
        _revocationChecker = revocationChecker;
        _failClosed = failClosed;
        if (clockSkewSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkewSeconds),
                "clockSkewSeconds must be non-negative.");
        }
        ClockSkewSeconds = clockSkewSeconds;
        _inboundDpop = inboundDpop;

        if (allowedAlgorithms is null)
        {
            AllowedAlgorithms = DefaultAllowedAlgorithms;
        }
        else
        {
            var algs = allowedAlgorithms.ToArray();
            if (algs.Length == 0)
            {
                throw new ArgumentException(
                    $"allowedAlgorithms must be non-empty; pass null to accept the default {{{string.Join(", ", DefaultAllowedAlgorithms)}}}.",
                    nameof(allowedAlgorithms));
            }

            var invalid = algs.Where(a => !SupportedAccessTokenAlgorithms.Contains(a)).ToArray();
            if (invalid.Length > 0)
            {
                throw new ArgumentException(
                    $"Unsupported access token algorithms {{{string.Join(", ", invalid)}}}; only {{{string.Join(", ", SupportedAccessTokenAlgorithms)}}} are permitted.",
                    nameof(allowedAlgorithms));
            }

            // Wrap so a caller can't cast IReadOnlyList<string> back to string[] and mutate.
            AllowedAlgorithms = new System.Collections.ObjectModel.ReadOnlyCollection<string>(algs);
        }

        _allowedAlgorithmsSet = new HashSet<string>(AllowedAlgorithms, StringComparer.Ordinal);

        Issuer = client.Issuer;
        FetchSettings = client.FetchSettings;
    }

    /// <summary>
    /// Convenience entry point: build an <see cref="AuthplaneClient"/> for
    /// <paramref name="issuer"/> (fetching its metadata) and wrap it in an
    /// <see cref="AuthplaneResource"/> bound to this RS's identifier and scopes.
    /// Use <see cref="AuthplaneClient.CreateResourceAsync"/> when you already
    /// have a client and want to share its metadata/JWKS caches.
    /// </summary>
    /// <param name="issuer">Authorization server issuer URL (HTTPS) — must match
    /// the <c>iss</c> in tokens this resource will verify.</param>
    /// <param name="resource">Resource identifier this RS publishes (RFC 9728).
    /// Must be an absolute URL with a scheme and a host (RFC 8707 §2,
    /// RFC 9728 §3) and must not contain a fragment component (RFC 8707 §2,
    /// RFC 9728 §1.2); violations are rejected here rather than silently
    /// producing a malformed metadata URL.</param>
    /// <param name="scopes">Scopes this RS requires; surfaced in PRM and in
    /// <c>WWW-Authenticate</c> on 401 challenges.</param>
    /// <param name="fetchSettings">HTTP/timeout/dev-mode policy; defaults to
    /// production settings (HTTPS-only).</param>
    /// <param name="revocationChecker">Optional revocation hook (RFC 7009).</param>
    /// <param name="failClosed">If true, revocation-check transport failures
    /// reject the token; the default <c>false</c> fails open.</param>
    /// <param name="clockSkewSeconds">Tolerance applied to <c>exp</c>/<c>iat</c>/<c>nbf</c>;
    /// default 30s.</param>
    /// <param name="inboundDpop">Per-resource DPoP enforcement options (RFC 9449
    /// inbound). When null, DPoP is off and only Bearer is accepted.</param>
    /// <param name="allowedAlgorithms">Subset of <c>SupportedAccessTokenAlgorithms</c>
    /// this RS will accept on the access token. Null defaults to the standard
    /// allowlist; pass an empty list to fail validation.</param>
    /// <param name="cancellationToken">Cancels the metadata fetch.</param>
    public static async Task<AuthplaneResource> CreateAsync(
        string issuer,
        string resource,
        IEnumerable<string> scopes,
        FetchSettings? fetchSettings = null,
        IRevocationChecker? revocationChecker = null,
        bool failClosed = false,
        long clockSkewSeconds = 30,
        InboundDPoPOptions? inboundDpop = null,
        IEnumerable<string>? allowedAlgorithms = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        // Repeated ahead of the constructor so a bad identifier fails before
        // the issuer metadata fetch below rather than after a network round
        // trip. It also keeps these two cases clear of a known leak: the
        // constructor runs after AuthplaneClient.CreateAsync, and a throw from
        // it leaks that client (its HttpClient and the JwksCache refresh task
        // are released only by DisposeAsync). Do not read this guard as a fix
        // for that — the other throw paths in the constructor still leak, and
        // the constructor's copies are what actually guarantee the invariant.
        ResourceIdentifiers.ThrowIfFragment(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfWhitespaceOrBackslash(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfMalformedPort(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfNotAbsoluteUrl(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfUserInfo(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfInvalidQuery(resource, nameof(resource));

        ArgumentNullException.ThrowIfNull(scopes);

        var scopeList = scopes is IReadOnlyList<string> r
            ? r
            : new List<string>(scopes);

        var settings = fetchSettings ?? FetchSettings.FromDevMode(devMode: false);
        var client = await AuthplaneClient.CreateAsync(issuer, settings, cancellationToken).ConfigureAwait(false);
        return new AuthplaneResource(client, resource, scopeList, ownsClient: true,
            revocationChecker: revocationChecker, failClosed: failClosed,
            clockSkewSeconds: clockSkewSeconds,
            inboundDpop: inboundDpop,
            allowedAlgorithms: allowedAlgorithms);
    }

    public Task<VerifiedClaims> VerifyAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        return VerifyAsync(token, dpopRequest: null, cancellationToken: cancellationToken);
    }

    public async Task<VerifiedClaims> VerifyAsync(
        string token,
        DPoPRequestContext? dpopRequest,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new TokenMissingException("Access token is missing.");
        }

        // 1) Decodificar header
        var header = DecodeHeader(token);

        if (!header.TryGetProperty("kid", out var kidProp) || kidProp.ValueKind != JsonValueKind.String)
        {
            throw new InvalidClaimsException("Token header missing 'kid' field.");
        }

        if (!header.TryGetProperty("alg", out var algProp) || algProp.ValueKind != JsonValueKind.String)
        {
            throw new InvalidClaimsException("Token header missing 'alg' field.");
        }

        if (!header.TryGetProperty("typ", out var typProp) || typProp.ValueKind != JsonValueKind.String)
        {
            throw new InvalidClaimsException("Token header missing 'typ' field.");
        }

        var kid = kidProp.GetString()!;
        var alg = algProp.GetString()!;
        var typ = typProp.GetString()!;

        // RFC 9068 §2.1: access tokens MUST use typ "at+jwt". We enforce this
        // strictly — tokens with "JWT" or missing typ are rejected. This
        // prevents type-confusion attacks where a
        // generic JWT is accepted as an access token.
        if (!string.Equals(typ, "at+jwt", StringComparison.Ordinal))
        {
            throw new InvalidClaimsException($"Token type must be 'at+jwt', got '{typ}'.");
        }

        // Rechazar algoritmos peligrosos y aplicar allowlist (per-resource configurable).
        if (!_allowedAlgorithmsSet.Contains(alg) || alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase) || string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidClaimsException($"Token algorithm '{alg}' is not allowed.");
        }

        // 2) Resolver clave de firma desde JWKS — pass alg so the JWK filter
        // rejects keys whose `alg` disagrees with the token header.
        var signingKey = await GetSigningKeyAsync(kid, alg, cancellationToken).ConfigureAwait(false);

        // 3) Validar token con JwtSecurityTokenHandler
        var handler = new JwtSecurityTokenHandler();
        // Keep original JWT claim names (e.g. "sub") instead of mapping to legacy .NET claim URIs.
        handler.InboundClaimTypeMap.Clear();
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = Issuer,
            ValidateAudience = true,
            ValidAudience = Resource,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(ClockSkewSeconds),
            RequireExpirationTime = true,
        };

        try
        {
            var principal = handler.ValidateToken(token, parameters, out var validatedToken);
            if (validatedToken is not JwtSecurityToken jwt)
            {
                throw new InvalidClaimsException("Validated token is not a JWT.");
            }

            // Reject iat too far in the future (not covered by JwtSecurityTokenHandler)
            var iatClaim = principal.Claims.FirstOrDefault(c => c.Type == "iat")?.Value;
            if (!string.IsNullOrEmpty(iatClaim) && long.TryParse(iatClaim, out var iatUnix))
            {
                var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (iatUnix > nowUnix + ClockSkewSeconds)
                {
                    throw new InvalidClaimsException($"Token 'iat' claim is in the future.");
                }
            }

            // Extraer claims estándar
            var sub = GetRequiredClaim(principal, "sub");
            var clientId = GetRequiredClaim(principal, "client_id");
            var jti = GetRequiredClaim(principal, "jti");
            var exp = GetRequiredUnixTimeClaim(principal, "exp");
            var iat = GetRequiredUnixTimeClaim(principal, "iat");

            // Authplane extensions:
            // - agent_id (string)
            // - agent_chain (list of strings)
            // - nbf (Unix timestamp)
            var notBefore = GetOptionalUnixTimeClaim(principal, "nbf");

            var agentId = GetOptionalClaim(principal, "agent_id");
            var agentChain = principal.Claims
                .Where(c => string.Equals(c.Type, "agent_chain", StringComparison.Ordinal))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .ToList();

            // If claims are not flattened (some token libraries keep arrays as raw payload values),
            // try to parse from the validated JWT payload.
            if ((string.IsNullOrWhiteSpace(agentId) || agentChain.Count == 0) &&
                jwt.Payload is not null)
            {
                if (string.IsNullOrWhiteSpace(agentId) &&
                    jwt.Payload.TryGetValue("agent_id", out var agentIdObj))
                {
                    agentId = ParseAgentIdFromPayload(agentIdObj);
                }

                if (agentChain.Count == 0 &&
                    jwt.Payload.TryGetValue("agent_chain", out var agentChainObj))
                {
                    agentChain = ParseStringListFromPayload(agentChainObj);
                }
            }

            // scope como lista
            var scope = GetOptionalClaim(principal, "scope");
            var scopes = string.IsNullOrWhiteSpace(scope)
                ? Array.Empty<string>()
                : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            var audienceList = jwt.Audiences?.ToList() ?? new List<string>();
            if (audienceList.Count == 0)
            {
                throw new InvalidClaimsException("Token 'aud' claim is missing or empty.");
            }

            // Construir diccionario raw
            var raw = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var claim in jwt.Claims)
            {
                if (!raw.ContainsKey(claim.Type))
                {
                    raw[claim.Type] = claim.Value;
                }
            }

            // Expose typed Authplane extension fields consistently via VerifiedClaims + raw.
            raw["agent_id"] = agentId;
            raw["agent_chain"] = agentChain;
            raw["nbf"] = notBefore;

            // DPoP inbound validation (RFC 9449 §7 / RFC 9728 §2).
            //
            // Three modes:
            //   • Not opted-in (_inboundDpop is null) — any DPoP signal is
            //     rejected with DPoPNotSupportedException; plain bearer accepted.
            //   • Supported (Required=false) — bound tokens are verified end-to-end;
            //     bearer-only accepted; proof attached to a bearer-only token is
            //     malformed and rejected.
            //   • Required (Required=true) — bearer-only tokens are rejected.
            var tokenIsBound = TryGetCnfJkt(jwt, out var cnfJkt);
            var cnfPresent = HasCnf(jwt);
            var proofPresent = dpopRequest is not null && !string.IsNullOrWhiteSpace(dpopRequest.Proof);
            // Non-null only when a nonce policy accepted the proof's nonce but
            // wants the client to rotate — surfaced as VerifiedClaims.NextDPoPNonce
            // so the adapter can advertise it on the success response
            // (RFC 9449 §8.2 via §9).
            string? nextDpopNonce = null;

            if (_inboundDpop is null)
            {
                if (tokenIsBound || cnfPresent || proofPresent)
                {
                    throw new DPoPNotSupportedException(
                        "Resource is not configured for DPoP. Pass `inboundDpop: new InboundDPoPOptions(...)` " +
                        "to AuthplaneClient.CreateResourceAsync / AuthplaneResource.CreateAsync to enable DPoP validation.");
                }
            }
            else
            {
                if (!tokenIsBound)
                {
                    if (cnfPresent)
                    {
                        // cnf present but jkt missing — structurally deficient (RFC 9449 §6).
                        throw new InvalidClaimsException(
                            "Access token has 'cnf' claim but missing 'cnf.jkt' — cannot verify DPoP binding.");
                    }

                    if (_inboundDpop.Required)
                    {
                        throw new DPoPBindingMismatchException(
                            "Resource requires DPoP-bound access tokens but the presented token has no `cnf.jkt`.");
                    }

                    if (proofPresent)
                    {
                        // Proof attached to a bearer-only token has nothing to bind to.
                        throw new DPoPBindingMismatchException(
                            "DPoP proof presented but the access token is not DPoP-bound (`cnf.jkt` missing); " +
                            "send the request without the DPoP header or use a DPoP-bound access token.");
                    }
                }
                else
                {
                    nextDpopNonce = await VerifyDpopProofAsyncCore(
                        dpopRequest,
                        expectedJkt: cnfJkt,
                        accessToken: token,
                        cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            // Revocation check (C5): runs after JWT + DPoP validation succeed.
            if (_revocationChecker is not null)
            {
                try
                {
                    var isRevoked = await _revocationChecker.IsRevokedAsync(token, cancellationToken)
                        .ConfigureAwait(false);
                    if (isRevoked)
                    {
                        throw new TokenRevokedException($"Token '{jti}' has been revoked.");
                    }
                }
                catch (TokenRevokedException)
                {
                    throw;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    // Caller cancellation must propagate. Translating it to
                    // "fail-open accepted" would silently mask the request
                    // shutdown and hide bugs where the verifier outlives its
                    // request context.
                    throw;
                }
                catch (CircuitOpenException ex)
                {
                    // The AS-call circuit is tripped — the authorization server
                    // is observably unhealthy. Apply the resource-level
                    // failClosed policy but keep the underlying cause attached
                    // so callers can distinguish "AS unavailable" from
                    // "AS said the token is revoked".
                    if (_failClosed)
                    {
                        throw new TokenRevokedException(
                            $"Revocation check for token '{jti}' could not reach the authorization server (circuit open); failClosed is enabled.",
                            ex);
                    }
                    // fail-open: accept token when revocation status is unknown
                }
                catch
                {
                    if (_failClosed)
                    {
                        throw new TokenRevokedException(
                            $"Revocation check failed for token '{jti}' and failClosed is enabled.");
                    }
                    // fail-open: accept token when revocation status is unknown
                }
            }

            return new VerifiedClaims(
                sub: sub,
                clientId: clientId,
                scopes: scopes,
                agentId: agentId,
                agentChain: agentChain,
                issuer: jwt.Issuer,
                audience: audienceList,
                expiresAt: exp,
                notBefore: notBefore,
                issuedAt: iat,
                jti: jti,
                kid: kid,
                raw: raw,
                nextDPoPNonce: nextDpopNonce);
        }
        catch (SecurityTokenExpiredException ex)
        {
            throw new TokenExpiredException($"Token has expired: {ex.Message}");
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            throw new InvalidSignatureException("Token signature verification failed.", ex);
        }
        catch (SecurityTokenException ex)
        {
            throw new InvalidClaimsException("Token claims validation failed: " + ex.Message, ex);
        }
        catch (AuthplaneException)
        {
            throw;
        }
        catch (ArgumentException ex)
        {
            // A contract violation in a verifier extension (a custom
            // IDPoPNonceIssuer emitting a non-NQCHAR nonce, for instance) is
            // the server's fault, not the token's. Folding it into the general
            // arm below would surface it as invalid_token and send a conformant
            // client into a re-authenticate loop against a healthy AS.
            throw new VerifierRuntimeException(
                "Verifier extension violated its contract: " + ex.Message, ex);
        }
        catch (Exception ex)
        {
            throw new InvalidSignatureException("Token verification failed: " + ex.Message, ex);
        }
    }

    private const long DpopMaxAgeSeconds = DPoPDefaults.MaxProofAgeSeconds;

    /// <returns>
    /// A fresh nonce to advertise in the <c>DPoP-Nonce</c> header of the
    /// success response, or <c>null</c> when no nonce policy is configured
    /// or the accepted nonce is not yet due for rotation (RFC 9449 §8.2).
    /// </returns>
    private async Task<string?> VerifyDpopProofAsyncCore(
        DPoPRequestContext? dpopRequest,
        string expectedJkt,
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (dpopRequest is null || string.IsNullOrWhiteSpace(dpopRequest.Proof))
        {
            throw new DPoPProofMissingException(
                "Access token is DPoP-bound (`cnf.jkt` present) but no DPoP proof was supplied");
        }

        var proof = dpopRequest.Proof!;
        var handler = new JwtSecurityTokenHandler();

        // Decode proof header to validate `typ` and obtain the embedded JWK.
        var proofHeader = DecodeHeader(proof);

        if (!proofHeader.TryGetProperty("typ", out var typProp) ||
            typProp.ValueKind != JsonValueKind.String ||
            !string.Equals(typProp.GetString(), "dpop+jwt", StringComparison.Ordinal))
        {
            throw new InvalidDPoPProofException("DPoP proof JOSE typ MUST be dpop+jwt.");
        }

        // Enforce alg allowlist on DPoP proofs (RFC 8725 §3, RFC 9449 §4.3 step 4).
        // Allowlist comes from InboundDPoPOptions when configured (so a caller can
        // restrict to ES256-only and have it match what PRM advertises); otherwise
        // falls back to the default ES256/RS256 set.
        var allowedProofAlgs = _inboundDpop?.AllowedProofAlgorithms ?? AcceptedDPoPAlgorithms;
        if (proofHeader.TryGetProperty("alg", out var proofAlgProp) &&
            proofAlgProp.ValueKind == JsonValueKind.String)
        {
            var proofAlg = proofAlgProp.GetString()!;
            if (!allowedProofAlgs.Contains(proofAlg))
            {
                throw new InvalidDPoPProofException($"DPoP proof algorithm '{proofAlg}' is not allowed.");
            }
        }
        else
        {
            throw new InvalidDPoPProofException("DPoP proof missing required 'alg' header.");
        }

        if (!proofHeader.TryGetProperty("jwk", out var jwkProp))
        {
            throw new InvalidDPoPProofException("DPoP proof missing required 'jwk' header.");
        }

        // Verify signature using the embedded JWK.
        var jwkJson = jwkProp.GetRawText();
        var jwk = new JsonWebKey(jwkJson);

        // Defense-in-depth — pin ValidAlgorithms on the proof signature
        // validator. The header `alg` allowlist above is already enforced, but
        // RFC 8725 §3 wants the verifier itself to also constrain accepted
        // signature algorithms so a JWK whose embedded `alg` disagrees with
        // the header can't slip through.
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireExpirationTime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = jwk,
            ValidAlgorithms = allowedProofAlgs is string[] arr ? arr : allowedProofAlgs.ToArray(),
        };

        try
        {
            handler.ValidateToken(proof, validationParameters, out _);
        }
        catch (Exception ex)
        {
            throw new InvalidDPoPProofException("DPoP proof signature validation failed.", ex);
        }

        var proofToken = handler.ReadJwtToken(proof);
        var claims = proofToken.Claims;

        string GetClaim(string name)
        {
            var val = claims.FirstOrDefault(c => c.Type == name)?.Value ?? string.Empty;
            return val;
        }

        var htm = GetClaim("htm");
        var htu = GetClaim("htu");
        var jti = GetClaim("jti");
        var ath = GetClaim("ath");
        var iatStr = GetClaim("iat");

        if (string.IsNullOrWhiteSpace(htm) ||
            string.IsNullOrWhiteSpace(htu) ||
            string.IsNullOrWhiteSpace(jti) ||
            string.IsNullOrWhiteSpace(iatStr))
        {
            throw new InvalidDPoPProofException("DPoP proof missing required claims.");
        }

        if (!long.TryParse(iatStr, out var iatSeconds))
        {
            throw new InvalidDPoPProofException("DPoP proof iat is not a valid integer.");
        }

        // RFC 9449 §4.3 step 11: htm MUST equal the request method byte-exact.
        // The HTTP method on the wire is canonical uppercase per RFC 7230
        // §3.1.1, and DPoPProofBuilder emits the proof claim uppercased as
        // well, so a strict ordinal comparison is the spec-correct check.
        // Previously both sides were ToUpperInvariant'd, which silently
        // accepted proofs with lowercased htm — a relaxation the spec does
        // not authorise.
        if (!string.Equals(htm, dpopRequest.Method, StringComparison.Ordinal))
        {
            throw new InvalidDPoPProofException("DPoP proof htm mismatch.");
        }

        // htu MUST match normalized request URL
        var normalizedHtu = NormalizeHtu(htu);
        var normalizedUrl = NormalizeHtu(dpopRequest.Url);
        if (!string.Equals(normalizedHtu, normalizedUrl, StringComparison.Ordinal))
        {
            throw new InvalidDPoPProofException("DPoP proof htu mismatch.");
        }

        var nowSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // The InboundDPoPOptions defaults used to silently shadow whatever the
        // caller passed to CreateResourceAsync's `clockSkewSeconds` — a
        // resource-level `clockSkewSeconds: 60` + `new InboundDPoPOptions(required: true)`
        // yielded 30 because that's the DPoP options' default. Now: only honour
        // the DPoP options value when the caller explicitly set it; otherwise
        // fall through to the resource-level skew.
        var clockSkewSeconds =
            (_inboundDpop is { HasExplicitClockSkewSeconds: true } skewOpts)
                ? skewOpts.ClockSkewSeconds
                : ClockSkewSeconds;
        var maxProofAge =
            (_inboundDpop is { HasExplicitMaxProofAgeSeconds: true } ageOpts)
                ? ageOpts.MaxProofAgeSeconds
                : DpopMaxAgeSeconds;
        if (iatSeconds > nowSeconds + clockSkewSeconds)
        {
            throw new InvalidDPoPProofException("DPoP proof iat is in the future.");
        }

        if (nowSeconds - iatSeconds > maxProofAge + clockSkewSeconds)
        {
            throw new InvalidDPoPProofException("DPoP proof is too old.");
        }

        // RFC 9449 §4.2 — honour exp when present
        var expStr = GetClaim("exp");
        if (!string.IsNullOrWhiteSpace(expStr) && long.TryParse(expStr, out var expSeconds))
        {
            if (expSeconds < nowSeconds - clockSkewSeconds)
            {
                throw new InvalidDPoPProofException("DPoP proof has expired.");
            }
        }

        // ath is REQUIRED when access token is presented (RFC 9449 §4.3).
        if (string.IsNullOrWhiteSpace(ath))
        {
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                throw new InvalidDPoPProofException("DPoP proof missing required 'ath' claim (access token hash).");
            }
        }
        else
        {
            var expectedAth = DPoPHashes.Sha256Base64Url(accessToken);
            if (!string.Equals(ath, expectedAth, StringComparison.Ordinal))
            {
                throw new InvalidDPoPProofException("DPoP proof ath mismatch.");
            }
        }

        // cnf.jkt MUST match JWK thumbprint.
        //
        // JwkThumbprint.Compute throws InvalidOperationException on missing /
        // unsupported kty / missing params. The earlier alg allowlist and
        // signature validation should reject those proofs first, so this is
        // unreachable in practice — but translate explicitly so a reordering
        // of the validation steps surfaces as a clean DPoP rejection rather
        // than a generic 500 on a security hot path.
        string computedJkt;
        try
        {
            computedJkt = JwkThumbprint.Compute(jwkProp);
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidDPoPProofException("DPoP proof JWK is malformed.", ex);
        }

        if (!string.Equals(computedJkt, expectedJkt, StringComparison.Ordinal))
        {
            throw new DPoPBindingMismatchException("DPoP proof key does not match token cnf.jkt.");
        }

        // Server-provided-nonce policy (RFC 9449 §9). Precedence mirrors the
        // replay store resolution below: the per-request RequiredNonce
        // override wins over the per-resource NonceIssuer, so a caller
        // distributing its own nonce values is not second-guessed by the
        // resource-level policy. With neither configured there is no nonce
        // policy at all, and a proof that happens to carry an AS-issued
        // nonce is accepted unchanged rather than rejected for
        // over-supplying a claim.
        //
        // This runs after every §4.3 proof check above so that only
        // otherwise-valid proofs reach the nonce choreography: a client with
        // a broken proof gets the proof error, not a nonce it would burn on
        // a doomed retry. It also runs BEFORE the jti replay CheckAndStore
        // below, and that ordering is load-bearing for the retry loop: a
        // nonce-rejected request must not burn its jti, so a client that
        // re-signs the same jti with the fresh nonce still verifies.
        string? nextNonce = null;
        if (!string.IsNullOrWhiteSpace(dpopRequest.RequiredNonce))
        {
            // Legacy exact-echo check (sibling-SDK `expected_nonce` parity):
            // failures keep InvalidDPoPProofException, as released.
            var proofNonce = GetClaim("nonce");
            if (string.IsNullOrWhiteSpace(proofNonce))
            {
                throw new InvalidDPoPProofException("DPoP proof missing required nonce claim.");
            }

            if (!string.Equals(proofNonce, dpopRequest.RequiredNonce, StringComparison.Ordinal))
            {
                throw new InvalidDPoPProofException("DPoP proof nonce mismatch.");
            }
        }
        else if (_inboundDpop?.NonceIssuer is { } nonceIssuer)
        {
            var proofNonce = GetClaim("nonce");
            if (string.IsNullOrWhiteSpace(proofNonce))
            {
                // First contact: the client cannot know the nonce yet, so
                // this is the §9 discovery path — the exception carries the
                // fresh nonce the adapter advertises with the 401.
                throw new DPoPNonceRequiredException(
                    "DPoP proof is missing the resource server nonce; retry with the value from the DPoP-Nonce response header.",
                    nonceIssuer.Issue());
            }

            switch (nonceIssuer.Validate(proofNonce))
            {
                case DPoPNonceValidationResult.Invalid:
                    // Expired or not ours. Still `use_dpop_nonce`, NOT
                    // `invalid_dpop_proof`: the proof itself verified fine,
                    // and §7.1's code would tell the client to fix a proof
                    // that isn't broken instead of refreshing the nonce.
                    throw new DPoPNonceRequiredException(
                        "DPoP proof nonce is expired or unknown; retry with the value from the DPoP-Nonce response header.",
                        nonceIssuer.Issue());
                case DPoPNonceValidationResult.ValidRotationDue:
                    nextNonce = nonceIssuer.Issue();
                    break;
            }
        }

        // Anti-replay on jti — resolution order: per-request override > per-resource
        // InboundDPoPOptions.ReplayStore > resource default. Multi-process deployments
        // should plug in a shared (Redis/DB) store via InboundDPoPOptions.
        //
        // CheckAndStore is atomic: two concurrent verifies of the same jti can no
        // longer both observe "not seen" before either records the seen state, which
        // a non-atomic Seen + Remember pair allowed.
        var store = dpopRequest.ReplayStore ?? _inboundDpop?.ReplayStore ?? _defaultReplayStore;
        if (store.CheckAndStore(jti, iatSeconds + maxProofAge))
        {
            throw new DPoPReplayDetectedException("DPoP proof jti has already been seen.");
        }

        return nextNonce;
    }

    private static string NormalizeHtu(string url) => DPoPHtu.Normalize(url);

    private static bool HasCnf(JwtSecurityToken jwt)
    {
        return jwt.Payload is not null &&
            jwt.Payload.TryGetValue("cnf", out var cnf) &&
            cnf is not null;
    }

    private static bool TryGetCnfJkt(JwtSecurityToken jwt, out string jkt)
    {
        jkt = string.Empty;

        if (jwt.Payload is null)
        {
            return false;
        }

        if (!jwt.Payload.TryGetValue("cnf", out var cnfObj) || cnfObj is null)
        {
            return false;
        }

        try
        {
            if (cnfObj is JsonElement cnfElem)
            {
                if (cnfElem.ValueKind == JsonValueKind.Object &&
                    cnfElem.TryGetProperty("jkt", out var jktProp) &&
                    jktProp.ValueKind == JsonValueKind.String)
                {
                    jkt = jktProp.GetString() ?? string.Empty;
                    return !string.IsNullOrWhiteSpace(jkt);
                }
            }

            if (cnfObj is IDictionary<string, object?> dict)
            {
                if (dict.TryGetValue("jkt", out var jktVal) && jktVal is not null)
                {
                    jkt = jktVal.ToString() ?? string.Empty;
                    return !string.IsNullOrWhiteSpace(jkt);
                }
            }

            // RFC 7800 `cnf` is always a JSON object, never a string.
            // Non-standard string parsing was removed.
        }
        catch
        {
            // Ignore malformed cnf claim.
        }

        return false;
    }

    public ProtectedResourceMetadata GetProtectedResourceMetadata()
    {
        // Forward FetchSettings.AllowHttp so dev-mode resources can still
        // advertise an `http://` issuer; production resources are kept strict
        // (RFC 9728 §3.6 / RFC 8414 §2 require https).
        //
        // RFC 9728 §2 DPoP fields are only advertised when the resource has
        // opted into inbound DPoP — omitting `inboundDpop` keeps these out of
        // PRM entirely.
        return ProtectedResourceMetadata.Build(
            Issuer,
            Resource,
            Scopes,
            dpopSigningAlgValuesSupported: _inboundDpop?.AllowedProofAlgorithms,
            allowHttp: FetchSettings.AllowHttp,
            dpopBoundAccessTokensRequired: _inboundDpop?.Required ?? false);
    }

    /// <summary>
    /// RFC 9728 §3.1 — absolute URL of this resource's Protected Resource Metadata document.
    /// </summary>
    public string GetProtectedResourceMetadataDocumentUrl()
    {
        return OAuthProtectedResourceMetadata.GetDocumentUrl(Resource);
    }

    public async ValueTask DisposeAsync()
    {
        if (_ownsClient)
        {
            await _client.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static JsonElement DecodeHeader(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2)
        {
            throw new InvalidSignatureException("Token format is invalid.");
        }

        try
        {
            // Base64UrlEncoder.DecodeBytes accepts unpadded URL-safe
            // base64 directly (it's already on the classpath via
            // System.IdentityModel.Tokens.Jwt), so the manual pad-and-swap
            // dance is redundant and a divergence risk.
            var bytes = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(parts[0]);
            var json = Encoding.UTF8.GetString(bytes);
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
        catch (Exception ex)
        {
            throw new InvalidSignatureException("Failed to decode token header: " + ex.Message, ex);
        }
    }

    private Task<JsonWebKey> GetSigningKeyAsync(string kid, string? tokenAlg, CancellationToken cancellationToken) =>
        _client.GetSigningKeyAsync(kid, cancellationToken, tokenAlg: tokenAlg);

    private static string GetRequiredClaim(System.Security.Claims.ClaimsPrincipal principal, string type)
    {
        var value = principal.Claims.FirstOrDefault(c => c.Type == type)?.Value;
        if (string.IsNullOrEmpty(value))
        {
            throw new InvalidClaimsException($"Token missing required '{type}' claim.");
        }

        return value;
    }

    private static string GetOptionalClaim(System.Security.Claims.ClaimsPrincipal principal, string type)
    {
        return principal.Claims.FirstOrDefault(c => c.Type == type)?.Value ?? string.Empty;
    }

    private static long GetRequiredUnixTimeClaim(System.Security.Claims.ClaimsPrincipal principal, string type)
    {
        var value = principal.Claims.FirstOrDefault(c => c.Type == type)?.Value;
        if (string.IsNullOrEmpty(value) || !long.TryParse(value, out var unix))
        {
            throw new InvalidClaimsException($"Token missing or invalid '{type}' claim.");
        }

        return unix;
    }

    private static long GetOptionalUnixTimeClaim(System.Security.Claims.ClaimsPrincipal principal, string type)
    {
        var value = principal.Claims.FirstOrDefault(c => c.Type == type)?.Value;
        if (string.IsNullOrWhiteSpace(value))
        {
            return 0;
        }

        if (!long.TryParse(value, out var unix))
        {
            throw new InvalidClaimsException($"Token has invalid '{type}' claim.");
        }

        return unix;
    }

    private static string ParseAgentIdFromPayload(object? agentIdObj)
    {
        if (agentIdObj is null)
        {
            return string.Empty;
        }

        if (agentIdObj is string s)
        {
            return s;
        }

        if (agentIdObj is JsonElement elem && elem.ValueKind == JsonValueKind.String)
        {
            return elem.GetString() ?? string.Empty;
        }

        return string.Empty;
    }

    private static List<string> ParseStringListFromPayload(object? listObj)
    {
        if (listObj is null)
        {
            return new List<string>();
        }

        if (listObj is string s)
        {
            return string.IsNullOrWhiteSpace(s) ? new List<string>() : new List<string> { s };
        }

        if (listObj is IEnumerable<string> strings)
        {
            return strings
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.Ordinal)
                .ToList();
        }

        if (listObj is IEnumerable<object?> objects)
        {
            var list = new List<string>();
            foreach (var obj in objects)
            {
                if (obj is string s2 && !string.IsNullOrWhiteSpace(s2))
                {
                    list.Add(s2);
                }
                else if (obj is JsonElement je && je.ValueKind == JsonValueKind.String)
                {
                    var v = je.GetString();
                    if (!string.IsNullOrWhiteSpace(v))
                    {
                        list.Add(v);
                    }
                }
            }
            return list;
        }

        if (listObj is JsonElement json && json.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>();
            foreach (var el in json.EnumerateArray())
            {
                if (el.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var v = el.GetString();
                if (!string.IsNullOrWhiteSpace(v))
                {
                    list.Add(v);
                }
            }
            return list.Distinct(StringComparer.Ordinal).ToList();
        }

        return new List<string>();
    }
}

