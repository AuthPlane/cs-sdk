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
/// Covers the three RFC 9449 §7 / RFC 9728 §2 modes for inbound DPoP: Mode 1
/// (required), Mode 2 (supported), Mode 3 (not configured).
/// </summary>
public sealed class InboundDPoPModeTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly int _port;
    private readonly string _issuer;
    private readonly string _resource;
    private readonly string _kid;

    public InboundDPoPModeTests()
    {
        (_issuer, _listener) = LoopbackHttpListener.Start();
        _port = new Uri(_issuer).Port;
        _resource = "https://api.example.com";
        _kid = "kid_1";
    }

    public void Dispose()
    {
        try
        {
            if (_listener.IsListening)
            {
                _listener.Stop();
            }
        }
        catch
        {
            // ignore
        }
    }

    [Fact]
    [Conformance("rfc9449-verifier-must-reject-bearer-only-token-when-resource-requires-dpop")]
    public async Task ResourceRequiringDPoP_RejectsBearerOnlyToken()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = JwksForEs256(ecdsa, _kid);
        var verifier = await CreateResourceAsync(
            jwks, ecdsa,
            inboundDpop: new InboundDPoPOptions(required: true));

        // Mint a token WITHOUT cnf.jkt — pure bearer.
        var token = await MintAccessTokenAsync(ecdsa, _kid, cnfJkt: null);

        var ex = await Assert.ThrowsAsync<DPoPBindingMismatchException>(
            () => verifier.VerifyAsync(token, dpopRequest: null, CancellationToken.None));
        Assert.Contains("requires DPoP-bound", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Conformance("rfc9449-verifier-must-reject-dpop-bound-token-when-resource-does-not-support-dpop")]
    public async Task ResourceNotConfiguredForDPoP_RejectsDPoPBoundToken()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = JwksForEs256(ecdsa, _kid);
        var verifier = await CreateResourceAsync(jwks, ecdsa, inboundDpop: null);

        // Mint a DPoP-bound token (carries cnf.jkt).
        var token = await MintAccessTokenAsync(ecdsa, _kid, cnfJkt: "test-jkt");

        var ex = await Assert.ThrowsAsync<DPoPNotSupportedException>(
            () => verifier.VerifyAsync(token, dpopRequest: null, CancellationToken.None));
        Assert.Contains("not configured for DPoP", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Conformance("rfc9449-verifier-must-reject-dpop-proof-when-access-token-is-not-dpop-bound")]
    public async Task ResourceSupportsDPoP_RejectsProofAttachedToBearerOnlyToken()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwks = JwksForEs256(ecdsa, _kid);
        var verifier = await CreateResourceAsync(
            jwks, ecdsa,
            inboundDpop: new InboundDPoPOptions(required: false));

        var token = await MintAccessTokenAsync(ecdsa, _kid, cnfJkt: null);

        // Construct a DPoP proof and attach it to a bearer-only token. The
        // proof has no binding to attach to (`ath` would hash a non-bound
        // token) — verifier must reject as malformed before signature check.
        var proof = "dummy-proof-not-validated-due-to-early-rejection";
        var dpopCtx = new DPoPRequestContext(
            method: "POST",
            url: "http://localhost:8080/mcp",
            proof: proof);

        var ex = await Assert.ThrowsAsync<DPoPBindingMismatchException>(
            () => verifier.VerifyAsync(token, dpopCtx, CancellationToken.None));
        Assert.Contains("not DPoP-bound", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Conformance("rfc9728-prm-must-advertise-dpop-required-when-resource-requires-dpop")]
    public void Prm_AdvertisesDpopRequired_WhenResourceRequiresDpop()
    {
        // No network needed — PRM build is pure.
        var metadata = ProtectedResourceMetadata.Build(
            issuer: "https://issuer.example.com",
            resource: "https://api.example.com",
            scopes: new[] { "tools/add" },
            dpopSigningAlgValuesSupported: new[] { "ES256", "RS256" },
            dpopBoundAccessTokensRequired: true);

        var json = metadata.ToRfc9728Json();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("dpop_bound_access_tokens_required", out var required),
            "PRM JSON must contain dpop_bound_access_tokens_required when required=true");
        Assert.Equal(JsonValueKind.True, required.ValueKind);

        Assert.True(root.TryGetProperty("dpop_signing_alg_values_supported", out var algs),
            "PRM JSON must contain dpop_signing_alg_values_supported alongside required flag");
        Assert.Equal(JsonValueKind.Array, algs.ValueKind);

        // When DPoP is configured but bearer is still accepted (Mode 2), emit
        // the flag explicitly with `false` so discovery clients don't have to
        // infer it from absence. The flag is
        // only omitted when DPoP itself is not configured.
        var notRequired = ProtectedResourceMetadata.Build(
            issuer: "https://issuer.example.com",
            resource: "https://api.example.com",
            scopes: new[] { "tools/add" },
            dpopSigningAlgValuesSupported: new[] { "ES256", "RS256" },
            dpopBoundAccessTokensRequired: false);
        using var doc2 = JsonDocument.Parse(notRequired.ToRfc9728Json());
        Assert.True(doc2.RootElement.TryGetProperty("dpop_bound_access_tokens_required", out var notRequiredProp),
            "PRM JSON must emit dpop_bound_access_tokens_required:false when DPoP is configured but bearer is also accepted");
        Assert.Equal(JsonValueKind.False, notRequiredProp.ValueKind);

        // When DPoP is NOT configured at all (no algs), the flag is omitted.
        var noDpop = ProtectedResourceMetadata.Build(
            issuer: "https://issuer.example.com",
            resource: "https://api.example.com",
            scopes: new[] { "tools/add" });
        using var doc3 = JsonDocument.Parse(noDpop.ToRfc9728Json());
        Assert.False(doc3.RootElement.TryGetProperty("dpop_bound_access_tokens_required", out _),
            "PRM JSON omits the flag entirely when DPoP is not configured");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private async Task<AuthplaneResource> CreateResourceAsync(
        string jwksJson,
        ECDsa ecdsa,
        InboundDPoPOptions? inboundDpop)
    {
        _ = ecdsa;
        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().WaitAsync(TimeSpan.FromSeconds(1));
                }
                catch
                {
                    continue;
                }

                if (ctx is null)
                {
                    continue;
                }
                try
                {
                    var path = ctx.Request.Url?.AbsolutePath.TrimEnd('/') ?? string.Empty;
                    if (string.Equals(path, "/.well-known/jwks.json", StringComparison.Ordinal))
                    {
                        var bytes = Encoding.UTF8.GetBytes(jwksJson);
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                    }
                    else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                             path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        var meta = $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";
                        var bytes = Encoding.UTF8.GetBytes(meta);
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

        return await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            inboundDpop: inboundDpop,
            cancellationToken: CancellationToken.None);
    }

    private Task<string> MintAccessTokenAsync(ECDsa ecdsa, string kid, string? cnfJkt)
    {
        var handler = new JwtSecurityTokenHandler();
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var ecdsaKey = new ECDsaSecurityKey(ecdsa) { KeyId = kid };
        var creds = new SigningCredentials(ecdsaKey, SecurityAlgorithms.EcdsaSha256);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = _resource,
            Expires = DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime,
            NotBefore = DateTimeOffset.UtcNow.AddSeconds(-10).UtcDateTime,
            SigningCredentials = creds,
            TokenType = "at+jwt",
            Subject = new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", "user_1"),
                new System.Security.Claims.Claim("client_id", "client_1"),
                new System.Security.Claims.Claim("scope", "tools/add"),
                new System.Security.Claims.Claim("jti", Guid.NewGuid().ToString("n")),
                new System.Security.Claims.Claim("iat", iat.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            }),
        };

        var token = handler.CreateToken(descriptor);
        if (cnfJkt is not null && token is JwtSecurityToken jwt)
        {
            jwt.Payload["cnf"] = new Dictionary<string, object> { ["jkt"] = cnfJkt };
        }

        return Task.FromResult(handler.WriteToken(token));
    }


    private static string JwksForEs256(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);
        static string B64U(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var x = B64U(p.Q!.X!);
        var y = B64U(p.Q!.Y!);

        return $@"{{""keys"":[{{""kty"":""EC"",""crv"":""P-256"",""kid"":""{kid}"",""use"":""sig"",""alg"":""ES256"",""x"":""{x}"",""y"":""{y}""}}]}}";
    }
}
