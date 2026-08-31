using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Authplane.Mcp.Tests;

/// <summary>
/// End-to-end RFC 9449 §9 nonce choreography through the MCP middleware:
/// 401 `use_dpop_nonce` + `DPoP-Nonce` header on a missing/stale nonce, the
/// nonce-carrying retry succeeding, and §8.2 rotation on success responses.
/// </summary>
public sealed class AuthplaneMcpAuthNonceTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly string _resource;
    private readonly string _kid;
    private readonly ECDsa _ecdsa;

    public AuthplaneMcpAuthNonceTests()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        (_issuer, _listener) = LoopbackHttpListener.Start();
        _resource = "http://localhost:8080/mcp";
        _kid = "kid_1";

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
                    if (ctx.Request.Url is null)
                    {
                        ctx.Response.StatusCode = 404;
                        continue;
                    }

                    var path = ctx.Request.Url.AbsolutePath.TrimEnd('/');
                    if (string.Equals(path, "/.well-known/jwks.json", StringComparison.Ordinal))
                    {
                        var jwks = JwksForEs256(_ecdsa, _kid);
                        var bytes = Encoding.UTF8.GetBytes(jwks);
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

        _ecdsa.Dispose();
    }

    [Fact]
    public async Task NoncePolicyOff_ValidProof_Returns200_WithoutDPoPNonceHeader()
    {
        // Enforcement off (the default): the success response carries no
        // DPoP-Nonce header — the wire shape is unchanged from before the
        // nonce feature existed.
        var (pipeline, provider, accessToken, dpopProvider) =
            await BuildDpopPipelineAsync(nonceIssuer: null);

        var proof = await dpopProvider.GenerateProofAsync(
            "POST", _resource,
            new DPoPProofOptions(accessToken: accessToken),
            CancellationToken.None);

        var ctx = await InvokeWithDpopAsync(pipeline, provider, accessToken, proof);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.False(ctx.Response.Headers.ContainsKey("DPoP-Nonce"));
    }

    [Fact]
    public async Task NoncePolicyOn_ProofWithoutNonce_Returns401UseDpopNonce_ThenRetrySucceeds()
    {
        var (pipeline, provider, accessToken, dpopProvider) =
            await BuildDpopPipelineAsync(HmacDPoPNonceIssuer.CreateEphemeral());

        // First contact: proof without a nonce.
        var proofNoNonce = await dpopProvider.GenerateProofAsync(
            "POST", _resource,
            new DPoPProofOptions(accessToken: accessToken),
            CancellationToken.None);

        var challengeCtx = await InvokeWithDpopAsync(pipeline, provider, accessToken, proofNoNonce);

        Assert.Equal(StatusCodes.Status401Unauthorized, challengeCtx.Response.StatusCode);
        var www = challengeCtx.Response.Headers.WWWAuthenticate.ToString();
        Assert.StartsWith("DPoP", www, StringComparison.Ordinal);
        Assert.Contains("error=\"use_dpop_nonce\"", www, StringComparison.Ordinal);

        var issuedNonce = challengeCtx.Response.Headers["DPoP-Nonce"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(issuedNonce));

        // Retry with the server-issued nonce in the proof — the RFC 9449 §9
        // round trip a conformant client performs.
        var proofWithNonce = await dpopProvider.GenerateProofAsync(
            "POST", _resource,
            new DPoPProofOptions(nonce: issuedNonce, accessToken: accessToken),
            CancellationToken.None);

        var retryCtx = await InvokeWithDpopAsync(pipeline, provider, accessToken, proofWithNonce);

        Assert.Equal(StatusCodes.Status200OK, retryCtx.Response.StatusCode);
        // Fresh nonce, first half of its lifetime: no rotation hint yet.
        Assert.False(retryCtx.Response.Headers.ContainsKey("DPoP-Nonce"));
    }

    [Fact]
    public async Task NoncePolicyOn_StaleNonce_Returns401UseDpopNonce_NotInvalidToken()
    {
        // Nonce minted 400s in the past under the same key: expired. The
        // challenge must be use_dpop_nonce with a fresh DPoP-Nonce — not the
        // invalid_token / invalid_dpop_proof family, which would tell the
        // client its proof (rather than its nonce) is the problem.
        var key = RandomNumberGenerator.GetBytes(32);
        var staleClock = new FixedTimeProvider(DateTimeOffset.UtcNow.AddSeconds(-400));
        var staleIssuer = new HmacDPoPNonceIssuer(key, timeProvider: staleClock);
        var staleNonce = staleIssuer.Issue();

        var (pipeline, provider, accessToken, dpopProvider) =
            await BuildDpopPipelineAsync(new HmacDPoPNonceIssuer(key));

        var proof = await dpopProvider.GenerateProofAsync(
            "POST", _resource,
            new DPoPProofOptions(nonce: staleNonce, accessToken: accessToken),
            CancellationToken.None);

        var ctx = await InvokeWithDpopAsync(pipeline, provider, accessToken, proof);

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.Contains("error=\"use_dpop_nonce\"", www, StringComparison.Ordinal);
        Assert.DoesNotContain("invalid_token", www, StringComparison.Ordinal);
        Assert.DoesNotContain("invalid_dpop_proof", www, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(ctx.Response.Headers["DPoP-Nonce"].ToString()));
    }

    [Fact]
    public async Task NoncePolicyOn_MisbehavingIssuer_Returns500_WithoutWwwAuthenticate()
    {
        // An issuer emitting a non-NQCHAR nonce breaks a server-side contract.
        // The response must say so: 500, no WWW-Authenticate — a 401 challenge
        // would send a conformant client into a re-authenticate loop against
        // an AS that is perfectly healthy.
        var (pipeline, provider, accessToken, dpopProvider) =
            await BuildDpopPipelineAsync(new MisbehavingNonceIssuer());

        var proof = await dpopProvider.GenerateProofAsync(
            "POST", _resource,
            new DPoPProofOptions(accessToken: accessToken),
            CancellationToken.None);

        var ctx = await InvokeWithDpopAsync(pipeline, provider, accessToken, proof);

        Assert.Equal(StatusCodes.Status500InternalServerError, ctx.Response.StatusCode);
        Assert.False(ctx.Response.Headers.ContainsKey("WWW-Authenticate"));
        Assert.False(ctx.Response.Headers.ContainsKey("DPoP-Nonce"));
    }

    private sealed class MisbehavingNonceIssuer : IDPoPNonceIssuer
    {
        public string Issue() => "bad nonce";

        public DPoPNonceValidationResult Validate(string nonce) => DPoPNonceValidationResult.Invalid;
    }

    [Fact]
    public async Task NoncePolicyOn_RotationDueNonce_Returns200_WithFreshDPoPNonceHeader()
    {
        // RFC 9449 §8.2 on the success path: a nonce past half its lifetime
        // is still accepted, and the 200 carries the next nonce so an active
        // client rotates without a 401 round trip.
        var key = RandomNumberGenerator.GetBytes(32);
        var agingClock = new FixedTimeProvider(DateTimeOffset.UtcNow.AddSeconds(-200));
        var agingIssuer = new HmacDPoPNonceIssuer(key, timeProvider: agingClock);
        var agingNonce = agingIssuer.Issue();

        var serverIssuer = new HmacDPoPNonceIssuer(key);
        var (pipeline, provider, accessToken, dpopProvider) =
            await BuildDpopPipelineAsync(serverIssuer);

        var proof = await dpopProvider.GenerateProofAsync(
            "POST", _resource,
            new DPoPProofOptions(nonce: agingNonce, accessToken: accessToken),
            CancellationToken.None);

        var ctx = await InvokeWithDpopAsync(pipeline, provider, accessToken, proof);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        var rotated = ctx.Response.Headers["DPoP-Nonce"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(rotated));
        Assert.Equal(DPoPNonceValidationResult.Valid, serverIssuer.Validate(rotated));
    }

    [Fact]
    public async Task NoncePolicyOn_RotationDueNonce_InsufficientScope403_StillCarriesDPoPNonce()
    {
        // RFC 9449 §8.2 supplies a nonce on any response. The proof (and its
        // rotation-due nonce) was accepted before the scope check failed, so
        // the 403 must not drop the hint — otherwise the client pays the 401
        // round trip on its next call.
        var key = RandomNumberGenerator.GetBytes(32);
        var agingClock = new FixedTimeProvider(DateTimeOffset.UtcNow.AddSeconds(-200));
        var agingIssuer = new HmacDPoPNonceIssuer(key, timeProvider: agingClock);
        var agingNonce = agingIssuer.Issue();

        var serverIssuer = new HmacDPoPNonceIssuer(key);
        var (pipeline, provider, accessToken, dpopProvider) =
            await BuildDpopPipelineAsync(serverIssuer);

        var proof = await dpopProvider.GenerateProofAsync(
            "POST", _resource,
            new DPoPProofOptions(nonce: agingNonce, accessToken: accessToken),
            CancellationToken.None);

        // The token carries only tools/add; requiring a scope it lacks turns
        // an otherwise-accepted request into the insufficient_scope 403.
        var ctx = await InvokeWithDpopAsync(pipeline, provider, accessToken, proof,
            requiredScopesHeader: "tools/other");

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.Contains("insufficient_scope",
            ctx.Response.Headers.WWWAuthenticate.ToString(), StringComparison.Ordinal);
        var rotated = ctx.Response.Headers["DPoP-Nonce"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(rotated));
        Assert.Equal(DPoPNonceValidationResult.Valid, serverIssuer.Validate(rotated));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _now;
        public FixedTimeProvider(DateTimeOffset now) => _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
    }

    private async Task<(RequestDelegate Pipeline, ServiceProvider Provider, string AccessToken, DPoPProvider DpopProvider)>
        BuildDpopPipelineAsync(IDPoPNonceIssuer? nonceIssuer)
    {
        var keyMaterial = DPoPKeyMaterial.CreateES256();
        var dpopProvider = new DPoPProvider(keyMaterial);

        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            inboundDpop: new InboundDPoPOptions(required: true, nonceIssuer: nonceIssuer),
            cancellationToken: CancellationToken.None);

        var accessToken = MintAccessToken(cnfJkt: keyMaterial.Thumbprint);

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        services.AddSingleton<IDPoPReplayStore, InMemoryDPoPReplayStore>();
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);

        var builder = new ApplicationBuilder(provider);
        builder.UseAuthplaneMcpAuth(options);
        builder.Run(httpCtx =>
        {
            httpCtx.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        });

        return (builder.Build(), provider, accessToken, dpopProvider);
    }

    private static async Task<HttpContext> InvokeWithDpopAsync(
        RequestDelegate pipeline,
        ServiceProvider provider,
        string token,
        string dpopProof,
        string? requiredScopesHeader = null)
    {
        var ctx = new DefaultHttpContext { RequestServices = provider };
        ctx.Request.Scheme = "http";
        ctx.Request.Host = new HostString("localhost", 8080);
        ctx.Request.PathBase = PathString.Empty;
        ctx.Request.Path = "/mcp";
        ctx.Request.Method = "POST";
        ctx.Request.ContentType = "application/json";
        ctx.Request.Headers["Authorization"] = $"DPoP {token}";
        ctx.Request.Headers["DPoP"] = dpopProof;
        if (requiredScopesHeader is not null)
        {
            ctx.Request.Headers["x-authplane-required-scopes"] = requiredScopesHeader;
        }

        var bodyJson = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"add\",\"arguments\":{\"a\":2,\"b\":3}}}";
        ctx.Request.Body = new System.IO.MemoryStream(Encoding.UTF8.GetBytes(bodyJson));
        ctx.Response.Body = new System.IO.MemoryStream();

        await pipeline(ctx);
        return ctx;
    }

    private string MintAccessToken(string cnfJkt)
    {
        var handler = new JwtSecurityTokenHandler();

        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var ecdsaKey = new ECDsaSecurityKey(_ecdsa) { KeyId = _kid };
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
        if (token is JwtSecurityToken jwt)
        {
            jwt.Payload["cnf"] = new Dictionary<string, object> { ["jkt"] = cnfJkt };
        }

        return handler.WriteToken(token);
    }

    private static string JwksForEs256(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);

        static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        var x = Base64UrlEncode(p.Q!.X!);
        var y = Base64UrlEncode(p.Q!.Y!);

        return $@"{{""keys"":[{{""kty"":""EC"",""crv"":""P-256"",""kid"":""{kid}"",""use"":""sig"",""alg"":""ES256"",""x"":""{x}"",""y"":""{y}""}}]}}";
    }
}
