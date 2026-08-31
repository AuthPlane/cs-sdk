using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Resource-server-provided DPoP nonce enforcement (RFC 9449 §9, rotation on
/// success per §8.2): the opt-in <see cref="InboundDPoPOptions"/> nonce
/// policy, the <see cref="DPoPNonceRequiredException"/> / `use_dpop_nonce`
/// choreography, and the stateless <see cref="HmacDPoPNonceIssuer"/>.
/// </summary>
public sealed class InboundDPoPServerNonceTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly string _resource = "https://api.example.com";
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _proofKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _kid = "kid_nonce";

    public InboundDPoPServerNonceTests()
    {
        (_issuer, _listener) = LoopbackHttpListener.Start();

        var jwks = BuildJwks(_signingKey, _kid);
        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx;
                try { ctx = await _listener.GetContextAsync().ConfigureAwait(false); }
                catch { return; }

                try
                {
                    var path = ctx.Request.Url?.AbsolutePath ?? "";
                    if (path == "/.well-known/jwks.json")
                    {
                        var bytes = Encoding.UTF8.GetBytes(jwks);
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                    }
                    else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                             path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        var meta = $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";
                        var bytes = Encoding.UTF8.GetBytes(meta);
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                    }
                    else
                    {
                        ctx.Response.StatusCode = 404;
                    }
                }
                finally { ctx.Response.OutputStream.Close(); }
            }
        });
    }

    public void Dispose()
    {
        try { _listener.Stop(); } catch { /* ignore */ }
        _signingKey.Dispose();
        _proofKey.Dispose();
    }

    // -----------------------------------------------------------------------
    // Enforcement OFF (default): old behavior, byte-identical
    // -----------------------------------------------------------------------

    [Fact]
    public async Task NoNoncePolicy_ProofWithoutNonce_Verifies()
    {
        await using var verifier = await CreateVerifierAsync(nonceIssuer: null);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token);

        var claims = await verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None);

        Assert.Equal("user_1", claims.Sub);
        Assert.Null(claims.NextDPoPNonce);
    }

    [Fact]
    public async Task NoNoncePolicy_ProofCarryingForeignNonce_StillVerifies()
    {
        // With no policy configured, a proof that happens to carry a nonce
        // (e.g. one the AS issued for the token endpoint) must not be
        // rejected for over-supplying a claim.
        await using var verifier = await CreateVerifierAsync(nonceIssuer: null);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token, nonce: "as-issued-nonce");

        var claims = await verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None);

        Assert.Equal("user_1", claims.Sub);
        Assert.Null(claims.NextDPoPNonce);
    }

    // -----------------------------------------------------------------------
    // Enforcement ON: the use_dpop_nonce choreography
    // -----------------------------------------------------------------------

    [Fact]
    public async Task NoncePolicy_ProofWithoutNonce_ThrowsNonceRequired_WithFreshNonce()
    {
        var issuer = HmacDPoPNonceIssuer.CreateEphemeral();
        await using var verifier = await CreateVerifierAsync(issuer);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token);

        var ex = await Assert.ThrowsAsync<DPoPNonceRequiredException>(
            () => verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None));

        // The carried nonce is the one the adapter advertises on the 401 —
        // it must be immediately usable on the retry.
        Assert.False(string.IsNullOrWhiteSpace(ex.NewNonce));
        Assert.NotEqual(DPoPNonceValidationResult.Invalid, issuer.Validate(ex.NewNonce));
    }

    [Fact]
    public async Task NoncePolicy_MisbehavingIssuer_SurfacesAsVerifierRuntime_NotAsTokenRejection()
    {
        // An issuer that violates the NQCHAR contract is a server-side fault.
        // It must surface as VerifierRuntimeException (HttpStatus 500), never
        // as a token-shaped 401 — a conformant client told invalid_token
        // re-authenticates against a healthy AS and fails identically forever.
        await using var verifier = await CreateVerifierAsync(new MisbehavingNonceIssuer());
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token);

        var ex = await Assert.ThrowsAsync<VerifierRuntimeException>(
            () => verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None));

        Assert.Equal(500, AuthplaneErrors.HttpStatus(ex));
        Assert.IsType<ArgumentException>(ex.InnerException);
    }

    [Fact]
    public async Task NoncePolicy_ValidNonce_Verifies_NoRotation()
    {
        var issuer = HmacDPoPNonceIssuer.CreateEphemeral();
        await using var verifier = await CreateVerifierAsync(issuer);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token, nonce: issuer.Issue());

        var claims = await verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None);

        Assert.Equal("user_1", claims.Sub);
        // A just-issued nonce is in the first half of its lifetime — no
        // rotation hint on the success response.
        Assert.Null(claims.NextDPoPNonce);
    }

    [Fact]
    public async Task NoncePolicy_ExpiredNonce_ThrowsNonceRequired_NotInvalidProof()
    {
        // Freeze the verifying issuer's clock 400s after the minting
        // issuer's (same key): the nonce is past its 300s lifetime.
        var key = RandomNumberGenerator.GetBytes(32);
        var mintClock = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var verifyClock = new FixedTimeProvider(mintClock.Now.AddSeconds(400));
        var mintIssuer = new HmacDPoPNonceIssuer(key, timeProvider: mintClock);
        var verifyIssuer = new HmacDPoPNonceIssuer(key, timeProvider: verifyClock);

        await using var verifier = await CreateVerifierAsync(verifyIssuer);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token, nonce: mintIssuer.Issue());

        // The stale nonce is a choreography failure, not a proof-validity
        // one: it must NOT surface as InvalidDPoPProofException.
        var ex = await Assert.ThrowsAsync<DPoPNonceRequiredException>(
            () => verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None));
        Assert.False(string.IsNullOrWhiteSpace(ex.NewNonce));
    }

    [Fact]
    public async Task NoncePolicy_UnknownNonce_ThrowsNonceRequired()
    {
        // A nonce minted under a different key — e.g. another resource's, or
        // a value the client invented — is unknown, not merely stale.
        var foreignIssuer = HmacDPoPNonceIssuer.CreateEphemeral();
        await using var verifier = await CreateVerifierAsync(HmacDPoPNonceIssuer.CreateEphemeral());
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token, nonce: foreignIssuer.Issue());

        await Assert.ThrowsAsync<DPoPNonceRequiredException>(
            () => verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None));
    }

    [Fact]
    public async Task NoncePolicy_RotationDueNonce_Verifies_AndSurfacesNextNonce()
    {
        // Nonce aged past half its lifetime but not expired: accepted, and
        // the verifier hands back the next nonce for the success response.
        var key = RandomNumberGenerator.GetBytes(32);
        var mintClock = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var verifyClock = new FixedTimeProvider(mintClock.Now.AddSeconds(200));
        var mintIssuer = new HmacDPoPNonceIssuer(key, timeProvider: mintClock);
        var verifyIssuer = new HmacDPoPNonceIssuer(key, timeProvider: verifyClock);

        await using var verifier = await CreateVerifierAsync(verifyIssuer);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token, nonce: mintIssuer.Issue());

        var claims = await verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None);

        Assert.NotNull(claims.NextDPoPNonce);
        Assert.Equal(DPoPNonceValidationResult.Valid, verifyIssuer.Validate(claims.NextDPoPNonce!));
    }

    [Fact]
    public async Task NoncePolicy_ProofOtherwiseInvalid_KeepsInvalidProofError()
    {
        // htm mismatch with nonce enforcement on: the proof error must win —
        // handing out a nonce for a proof that can never verify would send
        // the client into a doomed retry.
        var issuer = HmacDPoPNonceIssuer.CreateEphemeral();
        await using var verifier = await CreateVerifierAsync(issuer);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("GET", _resource, token, nonce: issuer.Issue());

        var ex = await Assert.ThrowsAsync<InvalidDPoPProofException>(
            () => verifier.VerifyAsync(token, Ctx(proof), CancellationToken.None));
        Assert.Contains("htm", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NoncePolicy_PerRequestRequiredNonce_OverridesIssuer()
    {
        // RequiredNonce takes precedence: the caller-supplied echo value is
        // matched exactly and the issuer is not consulted, mirroring the
        // per-request ReplayStore override.
        var issuer = HmacDPoPNonceIssuer.CreateEphemeral();
        await using var verifier = await CreateVerifierAsync(issuer);
        var token = MintAccessToken(ComputeJkt());
        var proof = MintDPoPProof("POST", _resource, token, nonce: "caller-nonce");

        var ctx = new DPoPRequestContext(
            method: "POST",
            url: _resource,
            proof: proof,
            requiredNonce: "caller-nonce");

        var claims = await verifier.VerifyAsync(token, ctx, CancellationToken.None);
        Assert.Equal("user_1", claims.Sub);
        Assert.Null(claims.NextDPoPNonce);
    }

    // -----------------------------------------------------------------------
    // WWW-Authenticate mapping
    // -----------------------------------------------------------------------

    [Fact]
    public void WwwAuthenticate_NonceRequired_UsesDPoPScheme_AndUseDpopNonceCode()
    {
        var header = AuthplaneErrors.WwwAuthenticate(
            new DPoPNonceRequiredException("nonce required", "fresh-nonce"));

        Assert.StartsWith("DPoP ", header, StringComparison.Ordinal);
        Assert.Contains("error=\"use_dpop_nonce\"", header, StringComparison.Ordinal);
        Assert.DoesNotContain("invalid_dpop_proof", header, StringComparison.Ordinal);
        Assert.DoesNotContain("invalid_token", header, StringComparison.Ordinal);
    }

    [Fact]
    public void HttpStatus_NonceRequired_Is401()
    {
        Assert.Equal(401,
            AuthplaneErrors.HttpStatus(new DPoPNonceRequiredException("nonce required", "n")));
    }

    [Fact]
    public void ResponseHeaders_NonceRequired_CarriesDPoPNonce()
    {
        // The third leg of the adapter contract: HttpStatus + WwwAuthenticate
        // alone would emit a use_dpop_nonce challenge with nothing to re-sign
        // with (RFC 9449 §9); ResponseHeaders supplies the missing header.
        var headers = AuthplaneErrors.ResponseHeaders(
            new DPoPNonceRequiredException("nonce required", "fresh-nonce"));

        var entry = Assert.Single(headers);
        Assert.Equal("DPoP-Nonce", entry.Key);
        Assert.Equal("fresh-nonce", entry.Value);
    }

    [Fact]
    public void ResponseHeaders_OtherErrors_AreEmpty()
    {
        Assert.Empty(AuthplaneErrors.ResponseHeaders(new InvalidDPoPProofException("bad proof")));
        Assert.Empty(AuthplaneErrors.ResponseHeaders(new InsufficientScopeException("no scope")));
        Assert.Empty(AuthplaneErrors.ResponseHeaders(new TokenExpiredException("expired")));
    }

    [Fact]
    public void ResponseHeaders_EmptyResult_IsNotMutableThroughACast()
    {
        // The empty dictionary is a shared static; a caller down-casting it
        // must not be able to poison every other error's headers.
        var headers = AuthplaneErrors.ResponseHeaders(new TokenExpiredException("expired"));

        var mutable = Assert.IsAssignableFrom<IDictionary<string, string>>(headers);
        Assert.Throws<NotSupportedException>(() => mutable.Add("X-Poison", "1"));
    }

    [Fact]
    public void ResponseHeaders_LookupIsCaseInsensitive()
    {
        // HTTP field names are case-insensitive; a caller probing for
        // "dpop-nonce" must find the entry.
        var headers = AuthplaneErrors.ResponseHeaders(
            new DPoPNonceRequiredException("nonce required", "fresh-nonce"));

        Assert.True(headers.TryGetValue("dpop-nonce", out var value));
        Assert.Equal("fresh-nonce", value);
    }

    // -----------------------------------------------------------------------
    // NQCHAR gate on issuer output (RFC 9449 §8.1)
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("has\"quote")]
    [InlineData("has\\backslash")]
    [InlineData("crlf\r\ninjection")]
    [InlineData("del\u007Fchar")]
    public void NonceRequiredException_NonNQCharNonce_Throws(string badNonce)
    {
        // A custom issuer returning non-NQCHAR output is a contract violation
        // caught at the exception, before either adapter can write the header.
        Assert.Throws<ArgumentException>(
            () => new DPoPNonceRequiredException("nonce required", badNonce));
    }

    [Fact]
    public void VerifiedClaims_NonNQCharNextNonce_Throws()
    {
        // Same gate on the success/rotation path.
        Assert.Throws<ArgumentException>(() => new VerifiedClaims(
            sub: "user_1",
            clientId: "client_1",
            scopes: new[] { "tools/add" },
            agentId: string.Empty,
            agentChain: Array.Empty<string>(),
            issuer: "https://as.example.com",
            audience: new[] { _resource },
            expiresAt: 0,
            notBefore: 0,
            issuedAt: 0,
            jti: "jti_1",
            kid: "kid_1",
            raw: new Dictionary<string, object?>(),
            nextDPoPNonce: "crlf\r\ninjection"));
    }

    // -----------------------------------------------------------------------
    // HmacDPoPNonceIssuer unit coverage (no network)
    // -----------------------------------------------------------------------

    [Fact]
    public void HmacIssuer_IssueValidateRoundtrip_IsValid_AndNQCharSafe()
    {
        var issuer = HmacDPoPNonceIssuer.CreateEphemeral();
        var nonce = issuer.Issue();
        // RFC 9449 §8.1 NQCHAR contract (IDPoPNonceIssuer.Issue): base64url
        // satisfies it today; this pins that no other alphabet creeps in.
        Assert.Matches("^[A-Za-z0-9_-]+$", nonce);
        Assert.Equal(DPoPNonceValidationResult.Valid, issuer.Validate(nonce));
    }

    [Fact]
    public void HmacIssuer_SharedKey_ValidatesSiblingNonce()
    {
        // Multi-process contract: two instances holding the same key accept
        // each other's nonces.
        var key = RandomNumberGenerator.GetBytes(32);
        var a = new HmacDPoPNonceIssuer(key);
        var b = new HmacDPoPNonceIssuer(key);
        Assert.Equal(DPoPNonceValidationResult.Valid, b.Validate(a.Issue()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-base64url-!!!")]
    [InlineData("AAAA")] // decodes, but wrong length
    public void HmacIssuer_GarbageInput_IsInvalid_NotThrowing(string nonce)
    {
        var issuer = HmacDPoPNonceIssuer.CreateEphemeral();
        Assert.Equal(DPoPNonceValidationResult.Invalid, issuer.Validate(nonce));
    }

    [Fact]
    public void HmacIssuer_TamperedNonce_IsInvalid()
    {
        var issuer = HmacDPoPNonceIssuer.CreateEphemeral();
        var nonce = issuer.Issue();
        // Flip one character of the tag portion.
        var tampered = nonce[..^1] + (nonce[^1] == 'A' ? 'B' : 'A');
        Assert.Equal(DPoPNonceValidationResult.Invalid, issuer.Validate(tampered));
    }

    [Fact]
    public void HmacIssuer_FutureTimestampBeyondSkew_IsInvalid()
    {
        // A nonce "issued" 10 minutes in the future cannot come from a
        // correctly-clocked key holder; accepting it would extend its
        // lifetime past the configured window.
        var key = RandomNumberGenerator.GetBytes(32);
        var future = new HmacDPoPNonceIssuer(key,
            timeProvider: new FixedTimeProvider(DateTimeOffset.UtcNow.AddMinutes(10)));
        var present = new HmacDPoPNonceIssuer(key);
        Assert.Equal(DPoPNonceValidationResult.Invalid, present.Validate(future.Issue()));
    }

    [Fact]
    public void HmacIssuer_WindowBoundaries_FreshThenRotateThenInvalid()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var clock = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var issuer = new HmacDPoPNonceIssuer(key, nonceLifetimeSeconds: 100, timeProvider: clock);
        var nonce = issuer.Issue();

        Assert.Equal(DPoPNonceValidationResult.Valid, issuer.Validate(nonce));

        clock.Advance(TimeSpan.FromSeconds(60)); // past half-life (50s)
        Assert.Equal(DPoPNonceValidationResult.ValidRotationDue, issuer.Validate(nonce));

        clock.Advance(TimeSpan.FromSeconds(50)); // 110s total — past lifetime
        Assert.Equal(DPoPNonceValidationResult.Invalid, issuer.Validate(nonce));
    }

    [Fact]
    public void HmacIssuer_RejectsMissingOrShortKey_AndNonPositiveLifetime()
    {
        // The key is required: an accidental keyless issuer is the
        // multi-replica 401-loop trap CreateEphemeral exists to make explicit.
        Assert.Throws<ArgumentNullException>(() => new HmacDPoPNonceIssuer(key: null!));
        Assert.Throws<ArgumentException>(() => new HmacDPoPNonceIssuer(key: new byte[8]));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new HmacDPoPNonceIssuer(RandomNumberGenerator.GetBytes(32), nonceLifetimeSeconds: 0));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => HmacDPoPNonceIssuer.CreateEphemeral(nonceLifetimeSeconds: 0));
    }

    [Fact]
    public void HmacIssuer_EphemeralInstances_DoNotShareKeys()
    {
        // CreateEphemeral is the explicit single-process door: each instance
        // holds its own random key, so siblings reject each other's nonces.
        var a = HmacDPoPNonceIssuer.CreateEphemeral();
        var b = HmacDPoPNonceIssuer.CreateEphemeral();
        Assert.Equal(DPoPNonceValidationResult.Invalid, b.Validate(a.Issue()));
    }

    [Fact]
    public void HmacIssuer_KeyMutationAfterConstruction_DoesNotAffectIssuer()
    {
        // The ctor clones the key: zeroing the caller's buffer must not
        // change what the issuer validates against.
        var key = RandomNumberGenerator.GetBytes(32);
        var issuer = new HmacDPoPNonceIssuer(key);
        var nonce = issuer.Issue();
        Array.Clear(key);
        Assert.Equal(DPoPNonceValidationResult.Valid, issuer.Validate(nonce));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>Deterministic clock for exercising the nonce lifetime window.</summary>
    private sealed class MisbehavingNonceIssuer : IDPoPNonceIssuer
    {
        public string Issue() => "bad nonce";

        public DPoPNonceValidationResult Validate(string nonce) => DPoPNonceValidationResult.Invalid;
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public DateTimeOffset Now { get; private set; }

        public FixedTimeProvider(DateTimeOffset now) => Now = now;

        public void Advance(TimeSpan by) => Now += by;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private DPoPRequestContext Ctx(string proof) =>
        new(method: "POST", url: _resource, proof: proof);

    private async Task<AuthplaneResource> CreateVerifierAsync(IDPoPNonceIssuer? nonceIssuer)
    {
        return await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true),
            inboundDpop: new InboundDPoPOptions(nonceIssuer: nonceIssuer),
            cancellationToken: CancellationToken.None);
    }

    private string MintAccessToken(string cnfJkt)
    {
        var handler = new JwtSecurityTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var creds = new SigningCredentials(
            new ECDsaSecurityKey(_signingKey) { KeyId = _kid },
            SecurityAlgorithms.EcdsaSha256);

        var claims = new List<System.Security.Claims.Claim>
        {
            new("sub", "user_1"),
            new("client_id", "client_1"),
            new("scope", "tools/add"),
            new("jti", Guid.NewGuid().ToString("n")),
            new("iat", now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = _resource,
            SigningCredentials = creds,
            TokenType = "at+jwt",
            Subject = new System.Security.Claims.ClaimsIdentity(claims),
            Expires = now.AddMinutes(5).UtcDateTime,
            NotBefore = now.AddSeconds(-10).UtcDateTime,
        };

        var token = handler.CreateToken(descriptor);
        if (token is JwtSecurityToken jwt)
        {
            jwt.Payload["cnf"] = new Dictionary<string, object> { ["jkt"] = cnfJkt };
        }

        return handler.WriteToken(token);
    }

    private string ComputeJkt()
    {
        var pub = _proofKey.ExportParameters(false);
        var x = Base64UrlEncode(pub.Q!.X!);
        var y = Base64UrlEncode(pub.Q!.Y!);
        var canonical = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private string MintDPoPProof(string method, string url, string? accessToken, string? nonce = null)
    {
        var handler = new JwtSecurityTokenHandler();
        var creds = new SigningCredentials(
            new ECDsaSecurityKey(_proofKey),
            SecurityAlgorithms.EcdsaSha256);

        var pub = _proofKey.ExportParameters(false);
        var publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncode(pub.Q!.X!),
            ["y"] = Base64UrlEncode(pub.Q!.Y!)
        };

        var jwtHeader = new JwtHeader(creds);
        jwtHeader["typ"] = "dpop+jwt";
        jwtHeader["jwk"] = publicJwk;

        var payload = new JwtPayload
        {
            { "htm", method },
            { "htu", url },
            { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
            { "jti", Guid.NewGuid().ToString("n") }
        };

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            payload.Add("ath", Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(accessToken))));
        }

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            payload.Add("nonce", nonce);
        }

        return handler.WriteToken(new JwtSecurityToken(jwtHeader, payload));
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string BuildJwks(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);
        var x = Base64UrlEncode(p.Q!.X!);
        var y = Base64UrlEncode(p.Q!.Y!);
        return $@"{{""keys"":[{{""kty"":""EC"",""crv"":""P-256"",""kid"":""{kid}"",""use"":""sig"",""alg"":""ES256"",""x"":""{x}"",""y"":""{y}""}}]}}";
    }
}
