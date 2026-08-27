using System.Net;
using System.Text;
using System.Text.Json;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

public class AuthplaneVerifierTests
{
    [Fact]
    public async Task CreateAsync_InitializesBasicProperties()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await Authplane.AuthplaneResource.CreateAsync(
            issuer: server.IssuerUrl,
            resource: "https://api.example.com",
            scopes: new[] { "read:data" },
            fetchSettings: FetchSettings.FromDevMode(true));

        Assert.Equal(server.IssuerUrl, resource.Issuer);
        Assert.Equal("https://api.example.com", resource.Resource);
        Assert.Contains("read:data", resource.Scopes);
    }

    [Fact]
    public async Task CreateAsync_RejectsInvalidArguments()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Authplane.AuthplaneResource.CreateAsync("", "https://api.example.com", new[] { "read:data" }));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Authplane.AuthplaneResource.CreateAsync("https://auth.example.com", "", new[] { "read:data" }));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Authplane.AuthplaneResource.CreateAsync("https://auth.example.com", "https://api.example.com", null!));
    }

    [Fact]
    public async Task CreateResourceAsync_FragmentInResource_Throws()
    {
        // Exercises the authoritative gate in the AuthplaneResource constructor
        // rather than the early copy in CreateAsync: this path shares an already
        // built client and performs no fetch of its own.
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        await using var client = await AuthplaneClient.CreateAsync(
            server.IssuerUrl, FetchSettings.FromDevMode(true));

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await client.CreateResourceAsync("https://api.example.com/mcp#frag", new[] { "read:data" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("fragment", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateResourceAsync_InvalidQuery_Throws()
    {
        // Same path as the fragment case above, for the query gate: this is the
        // one construction path that reaches the constructor without passing the
        // early copy in CreateAsync, so it is where the constructor's gate is
        // the only thing standing.
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        await using var client = await AuthplaneClient.CreateAsync(
            server.IssuerUrl, FetchSettings.FromDevMode(true));

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await client.CreateResourceAsync("https://api.example.com/mcp?a=\"b\"", new[] { "read:data" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("query", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateResourceAsync_NonUrlResource_Rejected()
    {
        // A bare URN has a scheme but no host, so RFC 9728 §3 gives it no
        // derivable metadata URL — this identifier used to be accepted and
        // quietly derived the garbage
        // `/.well-known/oauth-protected-resourceexample:api`. Exercises the
        // authoritative gate in the AuthplaneResource constructor: this path
        // shares an already built client and performs no fetch of its own.
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        await using var client = await AuthplaneClient.CreateAsync(
            server.IssuerUrl, FetchSettings.FromDevMode(true));

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await client.CreateResourceAsync("urn:example:api", new[] { "read:data" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateResourceAsync_HttpLocalhostResource_StillAccepted()
    {
        // Pins the deliberate profile relaxation: the absolute-URL gate
        // requires a scheme and a host, not a particular scheme, so an `http`
        // host keeps working for local development.
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        await using var client = await AuthplaneClient.CreateAsync(
            server.IssuerUrl, FetchSettings.FromDevMode(true));

        await using var resource = await client.CreateResourceAsync(
            "http://localhost:8080/mcp", new[] { "read:data" });

        Assert.Equal("http://localhost:8080/mcp", resource.Resource);
    }

    [Fact]
    [Conformance("rfc9728-prm-must-contain-required-fields")]
    [Conformance("rfc9728-prm-authorization-servers-must-list-the-issuer")]
    public async Task GetProtectedResourceMetadata_ReturnsExpectedValues()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await Authplane.AuthplaneResource.CreateAsync(
            issuer: server.IssuerUrl,
            resource: "https://api.example.com",
            scopes: new[] { "tools/add", "tools/multiply" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var prm = resource.GetProtectedResourceMetadata();

        Assert.Equal("https://api.example.com", prm.Resource);
        Assert.Equal(server.IssuerUrl, prm.Issuer);
        Assert.Contains("tools/add", prm.Scopes);
        Assert.Contains("tools/multiply", prm.Scopes);

        var json = prm.ToRfc9728Json();
        Assert.Contains("\"resource\"", json, StringComparison.Ordinal);
        Assert.Contains("\"authorization_servers\"", json, StringComparison.Ordinal);
        Assert.Contains("\"bearer_methods_supported\"", json, StringComparison.Ordinal);
        Assert.Contains("\"scopes_supported\"", json, StringComparison.Ordinal);
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource",
            resource.GetProtectedResourceMetadataDocumentUrl());
    }

    [Fact]
    public async Task VerifyAsync_EmptyToken_ThrowsTokenMissing()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await CreateTestResource(server);
        await Assert.ThrowsAsync<Authplane.TokenMissingException>(() =>
            resource.VerifyAsync(""));
    }

    [Fact]
    public async Task VerifyAsync_InvalidTokenFormat_ThrowsInvalidSignature()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await CreateTestResource(server);
        await Assert.ThrowsAsync<Authplane.InvalidSignatureException>(() =>
            resource.VerifyAsync("not-a-jwt"));
    }

    [Fact]
    [Conformance("rfc9068-token-header-must-contain-kid")]
    public async Task VerifyAsync_HeaderMissingKid_ThrowsInvalidClaims()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await CreateTestResource(server);
        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "at+jwt" },
            payload: new Dictionary<string, object>());
        await Assert.ThrowsAsync<Authplane.InvalidClaimsException>(() => resource.VerifyAsync(token));
    }

    [Fact]
    [Conformance("rfc9068-token-header-must-contain-alg")]
    public async Task VerifyAsync_HeaderMissingAlg_ThrowsInvalidClaims()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await CreateTestResource(server);
        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["kid"] = "kid1", ["typ"] = "at+jwt" },
            payload: new Dictionary<string, object>());
        await Assert.ThrowsAsync<Authplane.InvalidClaimsException>(() => resource.VerifyAsync(token));
    }

    [Fact]
    public async Task VerifyAsync_HeaderMissingTyp_ThrowsInvalidClaims()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await CreateTestResource(server);
        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["kid"] = "kid1", ["alg"] = "RS256" },
            payload: new Dictionary<string, object>());
        await Assert.ThrowsAsync<Authplane.InvalidClaimsException>(() => resource.VerifyAsync(token));
    }

    [Fact]
    [Conformance("rfc9068-typ-must-be-at-jwt")]
    public async Task VerifyAsync_TypNotAtJwt_ThrowsInvalidClaims()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await CreateTestResource(server);
        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["kid"] = "kid1", ["alg"] = "RS256", ["typ"] = "JWT" },
            payload: new Dictionary<string, object>());
        await Assert.ThrowsAsync<Authplane.InvalidClaimsException>(() => resource.VerifyAsync(token));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("hs512")]
    [InlineData("ES384")]
    [Conformance("rfc8725-allowed-jwt-algorithms-must-be-restricted")]
    public async Task VerifyAsync_DisallowedAlgorithms_ThrowInvalidClaims(string alg)
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await CreateTestResource(server);
        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["kid"] = "kid1", ["alg"] = alg, ["typ"] = "at+jwt" },
            payload: new Dictionary<string, object>());
        await Assert.ThrowsAsync<Authplane.InvalidClaimsException>(() => resource.VerifyAsync(token));
    }

    [Fact]
    public async Task VerifyAsync_JwksFetchNetworkFailure_ThrowsJwksFetchException()
    {
        // Use a server that serves metadata but points jwks_uri at an unreachable endpoint.
        using var server = new OneShotJwksServer("{\"keys\":[]}", jwksShouldFail: true);
        var resource = await CreateTestResource(server);

        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["kid"] = "kid1", ["alg"] = "RS256", ["typ"] = "at+jwt" },
            payload: new Dictionary<string, object>());

        await Assert.ThrowsAsync<Authplane.JwksFetchException>(() => resource.VerifyAsync(token));
    }

    private static async Task<Authplane.AuthplaneResource> CreateTestResource(
        OneShotJwksServer server, string[]? scopes = null)
    {
        return await Authplane.AuthplaneResource.CreateAsync(
            issuer: server.IssuerUrl,
            resource: "https://api.example.com",
            scopes: scopes ?? new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));
    }

    [Fact]
    [Conformance("rfc8725-kid-must-resolve-through-jwks-with-single-refresh-on-miss")]
    public async Task VerifyAsync_JwksMissingKid_ThrowsInvalidSignature()
    {
        using var server = new OneShotJwksServer("{\"keys\":[]}");
        var resource = await Authplane.AuthplaneResource.CreateAsync(
            issuer: server.IssuerUrl,
            resource: "https://api.example.com",
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["kid"] = "kid1", ["alg"] = "RS256", ["typ"] = "at+jwt" },
            payload: new Dictionary<string, object>());

        await Assert.ThrowsAsync<Authplane.InvalidSignatureException>(() => resource.VerifyAsync(token));
    }

    [Fact]
    public async Task VerifyAsync_JwksInvalidJson_ThrowsJwksFetchException()
    {
        using var server = new OneShotJwksServer("not-json");
        var resource = await Authplane.AuthplaneResource.CreateAsync(
            issuer: server.IssuerUrl,
            resource: "https://api.example.com",
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = MakeUnsignedJwt(
            header: new Dictionary<string, object> { ["kid"] = "kid1", ["alg"] = "RS256", ["typ"] = "at+jwt" },
            payload: new Dictionary<string, object>());

        await Assert.ThrowsAsync<Authplane.JwksFetchException>(() => resource.VerifyAsync(token));
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

    private sealed class OneShotJwksServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loopTask;
        public string IssuerUrl { get; }

        public OneShotJwksServer(string responseBody, bool jwksShouldFail = false)
        {
            (IssuerUrl, _listener) = LoopbackHttpListener.Start();

            _loopTask = Task.Run(async () =>
            {
                try
                {
                    while (_listener.IsListening)
                    {
                        HttpListenerContext ctx;
                        try
                        {
                            ctx = await _listener.GetContextAsync();
                        }
                        catch
                        {
                            break;
                        }

                        var path = ctx.Request.Url?.AbsolutePath ?? string.Empty;
                        if (path == "/.well-known/jwks.json")
                        {
                            var bytes = Encoding.UTF8.GetBytes(responseBody);
                            ctx.Response.StatusCode = 200;
                            ctx.Response.ContentType = "application/json";
                            ctx.Response.ContentLength64 = bytes.Length;
                            await ctx.Response.OutputStream.WriteAsync(bytes);
                        }
                        else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                                 path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                        {
                            var jwksUri = jwksShouldFail
                                ? "http://localhost:1/.well-known/jwks.json"
                                : $"{IssuerUrl}/.well-known/jwks.json";
                            var meta =
                                $"{{\"issuer\":\"{IssuerUrl}\",\"jwks_uri\":\"{jwksUri}\"}}";
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

                        ctx.Response.OutputStream.Close();
                    }
                }
                catch
                {
                    // ignore
                }
            });
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { /* ignore */ }
            try { _loopTask.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
        }
    }
}

