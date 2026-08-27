using System.Net;
using System.Text;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Mcp.Tests;

public sealed class AuthplaneAuthClientCoverageTests
{
    private sealed class TestServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly TaskCompletionSource _done;
        private readonly Task _loopTask;
        private readonly int _maxRequests;
        private int _requestCount;

        public int RequestCount => _requestCount;
        public string IssuerUrl { get; }

        public TestServer(Func<HttpListenerContext, Task> handler, int maxRequests)
        {
            if (handler is null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            if (maxRequests <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRequests));
            }

            _maxRequests = maxRequests;
            _done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

            (IssuerUrl, _listener) = LoopbackHttpListener.Start();

            _loopTask = Task.Run(async () =>
            {
                try
                {
                    for (var i = 0; i < _maxRequests; i++)
                    {
                        var ctx = await _listener.GetContextAsync();
                        Interlocked.Increment(ref _requestCount);
                        await handler(ctx);
                    }
                }
                catch (HttpListenerException)
                {
                    // ignore; listener may be stopped
                }
                finally
                {
                    try { _listener.Stop(); } catch { /* ignore */ }
                    _done.TrySetResult();
                }
            });
        }

        public async Task WaitAsync()
        {
            await _done.Task;
            await _loopTask;
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { /* ignore */ }
        }

    }

    private sealed class RecordingDpopSigner : IDPoPSigner
    {
        public List<string?> Nonces { get; } = new();

        public Task<string> GenerateProofAsync(
            string method,
            string url,
            DPoPProofOptions? options,
            CancellationToken cancellationToken)
        {
            Nonces.Add(options?.Nonce);
            return Task.FromResult("dpop-proof");
        }

        public string Thumbprint() => "thumb";
    }

    [Fact]
    public async Task ClientCredentialsAsync_ReturnsTokenResponse()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/token", ctx.Request.Url?.AbsolutePath);

            var body = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8)
                .ReadToEndAsync();
            Assert.Contains("grant_type=client_credentials", body);

            var payload =
                "{"
                + "\"access_token\":\"at_1\","
                + "\"token_type\":\"Bearer\","
                + "\"expires_in\":60,"
                + "\"scope\":\"tools/add\","
                + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\""
                + "}";

            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }, maxRequests: 1);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true));

        var token = await client.ClientCredentialsAsync(
            scope: "tools/add",
            resource: "https://mcp.example.com",
            cancellationToken: CancellationToken.None);

        Assert.Equal("at_1", token.AccessToken);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal(60, token.ExpiresIn);
        Assert.Equal("tools/add", token.Scope);
        Assert.Equal(
            "urn:ietf:params:oauth:token-type:access_token",
            token.IssuedTokenType);

        await server.WaitAsync();
        Assert.Equal(1, server.RequestCount);
    }

    [Fact]
    [Conformance("rfc9449-dpop-nonce-challenge-must-trigger-single-retry")]
    public async Task TokenExchangeAsync_UsesDpopNonce_WhenUseDpopNonce()
    {
        var signer = new RecordingDpopSigner();
        var callIndex = 0;

        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/token", ctx.Request.Url?.AbsolutePath);

            if (callIndex == 0)
            {
                // First token request triggers recursion.
                ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                ctx.Response.Headers.Add("DPoP-Nonce", "nonce-1");
                ctx.Response.ContentType = "application/json";

                var payload = "{\"error\":\"use_dpop_nonce\"}";
                var bytes = Encoding.UTF8.GetBytes(payload);
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.OutputStream.Close();

                callIndex++;
                return;
            }

            // Second response returns token.
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = "application/json";
            var ok =
                "{"
                + "\"access_token\":\"at_2\","
                + "\"token_type\":\"DPoP\","
                + "\"expires_in\":120,"
                + "\"scope\":\"scope_2\","
                + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\""
                + "}";
            var tokenBytes = Encoding.UTF8.GetBytes(ok);
            ctx.Response.ContentLength64 = tokenBytes.Length;
            await ctx.Response.OutputStream.WriteAsync(tokenBytes);
            ctx.Response.OutputStream.Close();

            callIndex++;
        }, maxRequests: 2);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            dpopSigner: signer);

        var opts = new TokenExchangeOptions(
            subjectToken: "sub_token_1",
            scope: "scope_2",
            resource: "https://mcp.example.com");

        var token = await client.TokenExchangeAsync(
            opts,
            cancellationToken: CancellationToken.None);

        Assert.Equal("at_2", token.AccessToken);
        Assert.Equal("DPoP", token.TokenType);
        Assert.Equal(120, token.ExpiresIn);
        Assert.Equal("scope_2", token.Scope);

        await server.WaitAsync();
        Assert.Equal(2, server.RequestCount);

        Assert.Equal(2, signer.Nonces.Count);
        Assert.Null(signer.Nonces[0]);
        Assert.Equal("nonce-1", signer.Nonces[1]);
    }

    [Fact]
    public async Task IntrospectAsync_ParsesAgentIdAndAgentChain()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/introspect", ctx.Request.Url?.AbsolutePath);

            var body = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8)
                .ReadToEndAsync();
            Assert.Contains("token=tok_1", body);
            Assert.Contains("token_type_hint=access_token", body);

            var payload = @"{
  ""active"": true,
  ""scope"": ""tools/add"",
  ""client_id"": ""client_1"",
  ""sub"": ""user_1"",
  ""token_type"": ""at+jwt"",
  ""iss"": ""https://auth.example.com"",
  ""aud"": [""aud_1"", ""aud_2""],
  ""exp"": 1700000000,
  ""iat"": 1690000000,
  ""jti"": ""jti_1"",
  ""agent_id"": ""agent_1"",
  ""agent_chain"": [""a_1"", ""a_2""]
}";

            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }, maxRequests: 1);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true));

        var result = await client.IntrospectAsync(
            token: "tok_1",
            cancellationToken: CancellationToken.None);

        Assert.True(result.Active);
        Assert.Equal("tools/add", result.Scope);
        Assert.Equal("client_1", result.ClientId);
        Assert.Equal("user_1", result.Sub);
        Assert.Equal("at+jwt", result.TokenType);
        Assert.Equal("https://auth.example.com", result.Iss);
        Assert.NotNull(result.Aud);
        Assert.Contains("aud_1", result.Aud!);
        Assert.Contains("aud_2", result.Aud!);
        Assert.Equal("agent_1", result.AgentId);
        Assert.NotNull(result.AgentChain);
        Assert.Equal(new[] { "a_1", "a_2" }, result.AgentChain);

        await server.WaitAsync();
    }
}

