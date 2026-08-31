using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

public sealed class AuthplaneVerifierBranchCoverageTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly string _resource = "https://api.example.com";
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _kid = "kid_cov";

    public AuthplaneVerifierBranchCoverageTests()
    {
        (_issuer, _listener) = LoopbackHttpListener.Start();

        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx = null;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch
                {
                    return;
                }

                try
                {
                    var path = ctx.Request.Url?.AbsolutePath ?? "";
                    if (path == "/.well-known/jwks.json")
                    {
                        var jwks = BuildJwks(_signingKey, _kid);
                        var bytes = System.Text.Encoding.UTF8.GetBytes(jwks);
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
                    }
                    else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                             path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        var meta = $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";
                        var bytes = System.Text.Encoding.UTF8.GetBytes(meta);
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes).ConfigureAwait(false);
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
    [Conformance("rfc9068-expiration-and-clock-skew-must-be-enforced")]
    public async Task VerifyAsync_ExpiredToken_ThrowsTokenExpiredException()
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
            expires: DateTimeOffset.UtcNow.AddMinutes(-5).UtcDateTime,
            notBefore: DateTimeOffset.UtcNow.AddMinutes(-10).UtcDateTime);

        await Assert.ThrowsAsync<TokenExpiredException>(() => verifier.VerifyAsync(token));
    }

    [Fact]
    [Conformance("rfc9068-audience-must-match-resource")]
    public async Task VerifyAsync_InvalidAudience_ThrowsInvalidClaimsException()
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
            audience: "https://other.example.com",
            expires: DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime);

        await Assert.ThrowsAsync<InvalidClaimsException>(() => verifier.VerifyAsync(token));
    }

    [Fact]
    [Conformance("rfc9068-signature-failure-must-reject-token")]
    public async Task VerifyAsync_InvalidSignature_ThrowsInvalidSignatureException()
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = MintToken(
            signingKey: otherKey,
            kid: _kid,
            issuer: _issuer,
            audience: _resource,
            expires: DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime);

        await Assert.ThrowsAsync<InvalidSignatureException>(() => verifier.VerifyAsync(token));
    }

    private static string MintToken(
        ECDsa signingKey,
        string kid,
        string issuer,
        string audience,
        DateTime expires,
        DateTime? notBefore = null)
    {
        var handler = new JwtSecurityTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var creds = new SigningCredentials(new ECDsaSecurityKey(signingKey) { KeyId = kid }, SecurityAlgorithms.EcdsaSha256);
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
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = creds,
            TokenType = "at+jwt",
            Subject = new System.Security.Claims.ClaimsIdentity(claims),
            Expires = expires,
            NotBefore = notBefore ?? now.AddSeconds(-10).UtcDateTime,
        };

        return handler.WriteToken(handler.CreateToken(descriptor));
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
