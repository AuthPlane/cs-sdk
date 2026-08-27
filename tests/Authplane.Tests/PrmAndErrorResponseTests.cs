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
/// Group 7: Protected Resource Metadata (RFC 9728), error responses (RFC 6750),
/// and Authplane-specific claims.
/// </summary>
public sealed class PrmAndErrorResponseTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly string _resource = "https://api.example.com";
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _kid = "kid_prm";

    public PrmAndErrorResponseTests()
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
    }

    // -----------------------------------------------------------------------
    // RFC 9728 — Protected Resource Metadata
    // -----------------------------------------------------------------------

    [Fact]
    [Conformance("rfc9728-prm-supported-bearer-methods-should-be-stable")]
    public async Task Prm_BearerMethodsSupported_ContainsHeader()
    {
        var resource = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var prm = resource.GetProtectedResourceMetadata();
        var json = prm.ToRfc9728Json();

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("bearer_methods_supported", out var bearerMethods));
        Assert.Equal(JsonValueKind.Array, bearerMethods.ValueKind);

        var methods = new List<string>();
        foreach (var el in bearerMethods.EnumerateArray())
        {
            if (el.ValueKind == JsonValueKind.String)
            {
                methods.Add(el.GetString()!);
            }
        }

        Assert.Contains("header", methods);
        await resource.DisposeAsync();
    }

    [Fact]
    [Conformance("rfc9728-prm-dpop-fields-should-be-advertised-when-dpop-is-supported")]
    public void Prm_DPoPFields_AdvertisedWhenConfigured()
    {
        // When DPoP signing alg values are provided, they should appear in the PRM JSON.
        var prm = ProtectedResourceMetadata.Build(
            issuer: "https://auth.example.com",
            resource: _resource,
            scopes: new[] { "tools/add" },
            dpopSigningAlgValuesSupported: new[] { "ES256" });

        var json = prm.ToRfc9728Json();

        Assert.Contains("dpop_signing_alg_values_supported", json);
        Assert.Contains("resource_signing_alg_values_supported", json);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("dpop_signing_alg_values_supported", out var dpopAlgs));
        Assert.Equal(JsonValueKind.Array, dpopAlgs.ValueKind);

        var algList = new List<string>();
        foreach (var el in dpopAlgs.EnumerateArray())
        {
            if (el.ValueKind == JsonValueKind.String)
            {
                algList.Add(el.GetString()!);
            }
        }
        Assert.Contains("ES256", algList);
    }

    // No [Conformance] marker: the catalog has a case for advertising the DPoP fields when DPoP
    // *is* configured, but none for omitting them when it is not. This test guards the omission
    // side as a plain unit test. Add the marker if the catalog grows a matching case.
    [Fact]
    public void Prm_DPoPFields_OmittedWhenNotConfigured()
    {
        // When no DPoP signing alg values are provided, the field should be absent.
        var prm = ProtectedResourceMetadata.Build(
            issuer: "https://auth.example.com",
            resource: _resource,
            scopes: new[] { "tools/add" });

        var json = prm.ToRfc9728Json();
        Assert.DoesNotContain("dpop_signing_alg_values_supported", json);
    }

    // -----------------------------------------------------------------------
    // RFC 6750 — Error Response
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ErrorResponse_OAuthErrorCodes_Mapped()
    {
        // Test that various OAuth error codes are preserved in the exception.
        using var server = CreateOneShotServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"error\":\"invalid_token\"}");
            ctx.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var ex = await Assert.ThrowsAsync<AuthplaneTokenRequestException>(() =>
            client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None));

        Assert.Equal("invalid_token", ex.OAuthError);
        Assert.Equal(401, ex.HttpStatus);
    }

    // -----------------------------------------------------------------------
    // Authplane — Typed claims
    // -----------------------------------------------------------------------

    [Fact]
    [Conformance("authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims")]
    public async Task VerifiedClaims_NbfExposed()
    {
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var now = DateTimeOffset.UtcNow;
        var nbfTime = now.AddSeconds(-5);
        var token = MintToken(
            signingKey: _signingKey,
            kid: _kid,
            issuer: _issuer,
            audience: _resource,
            expires: now.AddMinutes(5).UtcDateTime,
            notBefore: nbfTime.UtcDateTime);

        var claims = await verifier.VerifyAsync(token);

        // NotBefore should be exposed as a typed long on VerifiedClaims
        Assert.True(claims.NotBefore > 0);
        // Should be close to our nbf time (within clock skew)
        var diff = Math.Abs(claims.NotBefore - nbfTime.ToUnixTimeSeconds());
        Assert.True(diff <= 2, $"NotBefore should be close to expected value; diff={diff}");

        // Also check it's in the raw dictionary
        Assert.True(claims.Raw.ContainsKey("nbf"));

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
        DateTime expires,
        DateTime? notBefore = null)
    {
        var handler = new JwtSecurityTokenHandler();
        var now = DateTimeOffset.UtcNow;
        var creds = new SigningCredentials(
            new ECDsaSecurityKey(signingKey) { KeyId = kid },
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

    private static OneShotServer CreateOneShotServer(Func<HttpListenerContext, Task> handler)
    {
        return new OneShotServer(handler);
    }

    private sealed class OneShotServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loop;
        public string IssuerUrl { get; }

        public OneShotServer(Func<HttpListenerContext, Task> handler)
        {
            (IssuerUrl, _listener) = LoopbackHttpListener.Start();

            _loop = Task.Run(async () =>
            {
                try
                {
                    var ctx = await _listener.GetContextAsync();
                    await handler(ctx);
                }
                catch { /* ignore */ }
            });
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { /* ignore */ }
            try { _loop.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
        }
    }
}
