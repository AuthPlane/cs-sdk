using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

public sealed class DPoPInboundTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly int _port;
    private readonly string _issuer;
    private readonly string _resource;
    private readonly string _kid;

    public DPoPInboundTests()
    {
        var listener = new HttpListener();
        var port = GetFreePort();
        _port = port;
        _listener = listener;

        _issuer = $"http://localhost:{_port}";
        _resource = "https://api.example.com";
        _kid = "kid_1";

        _listener.Prefixes.Add($"http://localhost:{_port}/");
        _listener.Start();
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
    [Conformance("rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path")]
    public async Task DPoPBoundToken_MissingProof_ThrowsProofMissing()
    {
        using var ecdsa = Ecdsa.GenerateP256();
        var jwks = JwksForEs256(ecdsa, _kid);
        var verifier = await CreateResourceAsync(jwks, ecdsa, cnfJkt: "test-jkt");

        var accessToken = await MintAccessTokenAsync(
            issuer: _issuer,
            audience: _resource,
            ecdsa: ecdsa,
            kid: _kid,
            cnfJkt: "test-jkt",
            scope: "tools/add");

        var dpopCtx = new DPoPRequestContext(
            method: "POST",
            url: "http://localhost:8080/mcp",
            proof: null);

        await Assert.ThrowsAsync<DPoPProofMissingException>(
            () => verifier.VerifyAsync(accessToken, dpopCtx, CancellationToken.None));
    }

    [Fact]
    [Conformance("rfc9449-dpop-proof-header-typ-must-be-dpop-jwt")]
    public async Task DPoPProof_TypMismatch_ThrowsInvalidProof()
    {
        using var ecdsa = Ecdsa.GenerateP256();
        var jwks = JwksForEs256(ecdsa, _kid);
        var verifier = await CreateResourceAsync(jwks, ecdsa, cnfJkt: "test-jkt");

        var accessToken = await MintAccessTokenAsync(
            issuer: _issuer,
            audience: _resource,
            ecdsa: ecdsa,
            kid: _kid,
            cnfJkt: "test-jkt",
            scope: "tools/add");

        // Proof header typ MUST be dpop+jwt, but we set typ=JWT to force rejection.
        var proof = MakeUnsignedJwt(
            header: new Dictionary<string, object>
            {
                ["typ"] = "JWT"
            },
            payload: new Dictionary<string, object>
            {
                ["htm"] = "POST",
                ["htu"] = "http://localhost:8080/mcp",
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["jti"] = Guid.NewGuid().ToString("n"),
            });

        var dpopCtx = new DPoPRequestContext(
            method: "POST",
            url: "http://localhost:8080/mcp",
            proof: proof);

        await Assert.ThrowsAsync<InvalidDPoPProofException>(
            () => verifier.VerifyAsync(accessToken, dpopCtx, CancellationToken.None));
    }

    private async Task<AuthplaneResource> CreateResourceAsync(string jwksJson, ECDsa ecdsa, string cnfJkt)
    {
        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx = null;
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
                    if (ctx.Request.Url is not null)
                    {
                        var path = ctx.Request.Url.AbsolutePath.TrimEnd('/');
                        if (string.Equals(path, "/.well-known/jwks.json", StringComparison.Ordinal))
                        {
                            ctx.Response.ContentType = "application/json";
                            var bytes = Encoding.UTF8.GetBytes(jwksJson);
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
            inboundDpop: new InboundDPoPOptions(),
            cancellationToken: CancellationToken.None);
    }

    private async Task<string> MintAccessTokenAsync(
        string issuer,
        string audience,
        ECDsa ecdsa,
        string kid,
        string cnfJkt,
        string scope)
    {
        var handler = new JwtSecurityTokenHandler();

        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString("n");
        var exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();

        var ecdsaKey = new ECDsaSecurityKey(ecdsa)
        {
            KeyId = kid
        };

        var signingCredentials = new SigningCredentials(ecdsaKey, SecurityAlgorithms.EcdsaSha256);

        var subjectClaims = new List<System.Security.Claims.Claim>
        {
            new("sub", "user_1"),
            new("client_id", "client_1"),
            new("scope", scope),
            new("jti", jti),
            new("iat", iat.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime,
            NotBefore = DateTimeOffset.FromUnixTimeSeconds(iat).AddSeconds(-10).UtcDateTime,
            SigningCredentials = signingCredentials,
            TokenType = "at+jwt",
            Subject = new System.Security.Claims.ClaimsIdentity(subjectClaims)
        };

        var token = handler.CreateToken(descriptor);
        // Set cnf as a proper JSON object per RFC 7800.
        if (token is JwtSecurityToken jwt)
        {
            jwt.Payload["cnf"] = new Dictionary<string, object> { ["jkt"] = cnfJkt };
        }
        return handler.WriteToken(token);
    }

    private static string MakeUnsignedJwt(Dictionary<string, object> header, Dictionary<string, object> payload)
    {
        static string Base64UrlEncode(byte[] bytes)
        {
            var b64 = Convert.ToBase64String(bytes);
            return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        static string ToJson(Dictionary<string, object> map)
        {
            var json = JsonSerializer.Serialize(map);
            return json;
        }

        var headerJson = ToJson(header);
        var payloadJson = ToJson(payload);

        var headerSeg = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadSeg = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        return $"{headerSeg}.{payloadSeg}.x";
    }

    private static int GetFreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string JwksForEs256(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);

        string Base64UrlEncode(byte[] bytes)
        {
            var b64 = Convert.ToBase64String(bytes);
            return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        var x = Base64UrlEncode(p.Q!.X!);
        var y = Base64UrlEncode(p.Q!.Y!);

        // ES256 over P-256.
        return $@"{{
  ""keys"": [
    {{
      ""kty"": ""EC"",
      ""crv"": ""P-256"",
      ""kid"": ""{kid}"",
      ""use"": ""sig"",
      ""alg"": ""ES256"",
      ""x"": ""{x}"",
      ""y"": ""{y}""
    }}
  ]
}}";
    }

    private static class Ecdsa
    {
        public static ECDsa GenerateP256()
        {
            return ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }
    }
}

