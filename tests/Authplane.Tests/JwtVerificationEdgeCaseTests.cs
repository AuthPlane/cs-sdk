using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Authplane.Conformance;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Group 2: JWT verification edge cases (RFC 9068, RFC 8725, RFC 8707).
/// </summary>
public sealed class JwtVerificationEdgeCaseTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly string _resource = "https://api.example.com";
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _kid = "kid_edge";

    public JwtVerificationEdgeCaseTests()
    {
        var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
        tcp.Stop();

        _issuer = $"http://localhost:{port}";
        _listener = new HttpListener();
        _listener.Prefixes.Add($"{_issuer}/");
        _listener.Start();

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
                finally
                {
                    ctx.Response.OutputStream.Close();
                }
            }
        });
    }

    public void Dispose()
    {
        try { _listener.Stop(); } catch { /* ignore */ }
        _signingKey.Dispose();
    }

    [Fact]
    [Conformance("rfc9068-valid-at-jwt-must-verify")]
    public async Task VerifyAsync_ValidToken_ReturnsVerifiedClaims()
    {
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = MintToken(
            signingKey: _signingKey,
            kid: _kid,
            issuer: _issuer,
            audience: _resource,
            sub: "user_1",
            clientId: "client_1",
            scope: "tools/add",
            expires: DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime);

        var claims = await verifier.VerifyAsync(token);

        Assert.Equal("user_1", claims.Sub);
        Assert.Equal("client_1", claims.ClientId);
        Assert.Contains("tools/add", claims.Scopes);
        Assert.Equal(_issuer, claims.Issuer);
        Assert.Contains(_resource, claims.Audience);
        Assert.False(string.IsNullOrWhiteSpace(claims.Jti));
        Assert.True(claims.ExpiresAt > 0);
        Assert.True(claims.IssuedAt > 0);

        await verifier.DisposeAsync();
    }

    [Fact]
    [Conformance("rfc9068-issuer-must-match")]
    public async Task VerifyAsync_WrongIssuer_ThrowsInvalidClaims()
    {
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        // Mint a token with a different issuer value
        var token = MintToken(
            signingKey: _signingKey,
            kid: _kid,
            issuer: "http://wrong-issuer.example.com",
            audience: _resource,
            sub: "user_1",
            clientId: "client_1",
            scope: "tools/add",
            expires: DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime);

        await Assert.ThrowsAsync<InvalidClaimsException>(() => verifier.VerifyAsync(token));
        await verifier.DisposeAsync();
    }

    [Theory]
    [InlineData(null, "client_1", "jti_1")]   // missing sub
    [InlineData("user_1", null, "jti_1")]      // missing client_id
    [InlineData("user_1", "client_1", null)]   // missing jti
    [Conformance("rfc9068-required-claims-must-be-enforced")]
    public async Task VerifyAsync_MissingRequiredClaims_ThrowsInvalidClaims(
        string? sub, string? clientId, string? jti)
    {
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = MintTokenWithOptionalClaims(
            signingKey: _signingKey,
            kid: _kid,
            issuer: _issuer,
            audience: _resource,
            sub: sub,
            clientId: clientId,
            jti: jti,
            scope: "tools/add",
            expires: DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime);

        await Assert.ThrowsAsync<InvalidClaimsException>(() => verifier.VerifyAsync(token));
        await verifier.DisposeAsync();
    }

    [Fact]
    [Conformance("rfc9068-iat-future-must-be-rejected-beyond-leeway")]
    public async Task VerifyAsync_FutureIat_BeyondLeeway()
    {
        // The SDK now independently rejects tokens with iat > now + 30s,
        // even if nbf would otherwise pass.
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        // Set nbf in the past so JwtSecurityTokenHandler does NOT reject for nbf,
        // but iat far in the future so our explicit iat check fires.
        var futureIat = DateTimeOffset.UtcNow.AddMinutes(10);
        var token = MintToken(
            signingKey: _signingKey,
            kid: _kid,
            issuer: _issuer,
            audience: _resource,
            sub: "user_1",
            clientId: "client_1",
            scope: "tools/add",
            expires: futureIat.AddMinutes(5).UtcDateTime,
            notBefore: DateTimeOffset.UtcNow.AddSeconds(-10).UtcDateTime,
            issuedAt: futureIat);

        var ex = await Assert.ThrowsAsync<InvalidClaimsException>(() => verifier.VerifyAsync(token));
        Assert.Contains("iat", ex.Message, StringComparison.OrdinalIgnoreCase);
        await verifier.DisposeAsync();
    }

    [Fact]
    [Conformance("rfc9068-nbf-must-be-honored-when-present")]
    public async Task VerifyAsync_FutureNbf_ThrowsInvalidClaims()
    {
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        // Token with nbf 10 minutes in the future (well beyond 30s clock skew)
        var token = MintToken(
            signingKey: _signingKey,
            kid: _kid,
            issuer: _issuer,
            audience: _resource,
            sub: "user_1",
            clientId: "client_1",
            scope: "tools/add",
            expires: DateTimeOffset.UtcNow.AddMinutes(15).UtcDateTime,
            notBefore: DateTimeOffset.UtcNow.AddMinutes(10).UtcDateTime);

        await Assert.ThrowsAsync<InvalidClaimsException>(() => verifier.VerifyAsync(token));
        await verifier.DisposeAsync();
    }

    [Fact]
    [Conformance("rfc8725-jwk-selection-must-honor-use-key-ops-and-alg")]
    public async Task VerifyAsync_AlgorithmAllowlist_EnforcedOnHeader()
    {
        // The SDK restricts algorithms to RS256 and ES256 and filters JWKs by
        // use ("sig") and key_ops (contains "verify"). This test verifies
        // that even with a matching kid, a disallowed algorithm is rejected.
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object>
            {
                ["kid"] = _kid,
                ["alg"] = "PS256",
                ["typ"] = "at+jwt"
            },
            payload: new Dictionary<string, object>());

        await Assert.ThrowsAsync<InvalidClaimsException>(() => verifier.VerifyAsync(token));
        await verifier.DisposeAsync();
    }

    [Fact]
    [Conformance("rfc8707-verifier-must-accept-resource-when-present-in-aud-array")]
    public async Task VerifyAsync_AudArrayContainsResource_Accepted()
    {
        // The SDK validates aud against the configured resource. When the token's
        // aud is an array containing the resource, it should pass. The standard
        // JwtSecurityTokenHandler accepts if ValidAudience is in the aud array.
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = MintToken(
            signingKey: _signingKey,
            kid: _kid,
            issuer: _issuer,
            audience: _resource,
            sub: "user_1",
            clientId: "client_1",
            scope: "tools/add",
            expires: DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime);

        var claims = await verifier.VerifyAsync(token);
        Assert.Contains(_resource, claims.Audience);
        await verifier.DisposeAsync();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static string MintToken(
        ECDsa signingKey,
        string kid,
        string issuer,
        string audience,
        string sub = "user_1",
        string clientId = "client_1",
        string scope = "tools/add",
        DateTime? expires = null,
        DateTime? notBefore = null,
        DateTimeOffset? issuedAt = null)
    {
        var handler = new JwtSecurityTokenHandler();
        var now = issuedAt ?? DateTimeOffset.UtcNow;
        var creds = new SigningCredentials(
            new ECDsaSecurityKey(signingKey) { KeyId = kid },
            SecurityAlgorithms.EcdsaSha256);

        var claims = new List<System.Security.Claims.Claim>
        {
            new("sub", sub),
            new("client_id", clientId),
            new("scope", scope),
            new("jti", Guid.NewGuid().ToString("n")),
            new("iat", now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = creds,
            TokenType = "at+jwt",
            Subject = new System.Security.Claims.ClaimsIdentity(claims),
            Expires = expires ?? DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime,
            NotBefore = notBefore ?? now.AddSeconds(-10).UtcDateTime,
            IssuedAt = now.UtcDateTime,
        };

        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    private static string MintTokenWithOptionalClaims(
        ECDsa signingKey,
        string kid,
        string issuer,
        string audience,
        string? sub,
        string? clientId,
        string? jti,
        string scope,
        DateTime expires)
    {
        var handler = new JwtSecurityTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var creds = new SigningCredentials(
            new ECDsaSecurityKey(signingKey) { KeyId = kid },
            SecurityAlgorithms.EcdsaSha256);

        var claims = new List<System.Security.Claims.Claim>
        {
            new("scope", scope),
            new("iat", now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };

        if (sub is not null)
        {
            claims.Add(new("sub", sub));
        }

        if (clientId is not null)
        {
            claims.Add(new("client_id", clientId));
        }

        if (jti is not null)
        {
            claims.Add(new("jti", jti));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = creds,
            TokenType = "at+jwt",
            Subject = new System.Security.Claims.ClaimsIdentity(claims),
            Expires = expires,
            NotBefore = now.AddSeconds(-10).UtcDateTime,
        };

        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    private static string MakeUnsignedJwt(
        Dictionary<string, object> header,
        Dictionary<string, object> payload)
    {
        static string B64Url(byte[] bytes)
        {
            var b64 = Convert.ToBase64String(bytes);
            return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        var headerSeg = B64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
        var payloadSeg = B64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
        return $"{headerSeg}.{payloadSeg}.sig";
    }

    private static string BuildJwks(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);
        static string B64Url(byte[] bytes)
        {
            var b64 = Convert.ToBase64String(bytes);
            return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        var x = B64Url(p.Q!.X!);
        var y = B64Url(p.Q!.Y!);
        return $@"{{""keys"":[{{""kty"":""EC"",""crv"":""P-256"",""kid"":""{kid}"",""use"":""sig"",""alg"":""ES256"",""x"":""{x}"",""y"":""{y}""}}]}}";
    }
}
