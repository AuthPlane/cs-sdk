using System.Net;
using System.Text;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

public sealed class AuthplaneAuthClientTests
{
    private sealed class TestServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loopTask;
        private readonly TaskCompletionSource _done;
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

            var port = GetFreePort();
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{port}/");
            _listener.Start();

            IssuerUrl = $"http://localhost:{port}";

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
                    // Listener stopped; ignore.
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

        private static int GetFreePort()
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
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
    [Conformance("rfc6749-client-credentials-success-response")]
    [Conformance("rfc8707-client-credentials-resource-parameter-should-be-supported")]
    public async Task ClientCredentialsAsync_ReturnsTokenResponse()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/token", ctx.Request.Url?.AbsolutePath);
            Assert.Equal("POST", ctx.Request.HttpMethod);

            var body = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();
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
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", token.IssuedTokenType);

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
            Assert.Equal("POST", ctx.Request.HttpMethod);

            _ = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            if (callIndex == 0)
            {
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

            ctx.Response.StatusCode = 200;
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

    /// <summary>
    /// RFC 9449 §8 — the nonce-challenge retry is bounded to a single retry.
    /// A hostile or misbehaving AS that keeps returning <c>400 use_dpop_nonce</c>
    /// with a fresh <c>DPoP-Nonce</c> header must NOT cause unbounded recursion
    /// inside the token exchange path. The expected surface is an exception on
    /// the second response, with the server having received exactly two hits.
    /// </summary>
    [Fact]
    public async Task TokenExchangeAsync_UseDpopNonceLoop_StopsAfterOneRetry()
    {
        var signer = new RecordingDpopSigner();
        var nonceIndex = 0;

        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/token", ctx.Request.Url?.AbsolutePath);
            _ = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.Headers.Add("DPoP-Nonce", $"nonce-{++nonceIndex}");
            ctx.Response.ContentType = "application/json";

            var payload = "{\"error\":\"use_dpop_nonce\"}";
            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
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

        await Assert.ThrowsAnyAsync<AuthplaneAuthClientException>(() =>
            client.TokenExchangeAsync(opts, cancellationToken: CancellationToken.None));

        await server.WaitAsync();
        Assert.Equal(2, server.RequestCount);
    }

    [Fact]
    [Conformance("rfc7662-introspection-request-must-post-token-and-access-token-hint")]
    [Conformance("authplane-agent-id-must-be-exposed-as-first-class-field")]
    [Conformance("authplane-agent-chain-must-be-exposed-as-first-class-field")]
    public async Task IntrospectAsync_ParsesAgentIdAndAgentChain()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/introspect", ctx.Request.Url?.AbsolutePath);

            var body = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();
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

    [Fact]
    public async Task IntrospectAsync_InvalidActiveField_DefaultsToInactive()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/introspect", ctx.Request.Url?.AbsolutePath);

            var payload = @"{ ""active"": ""not-a-bool"" }";
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

        // RFC 7662 — non-boolean active field defaults to inactive (false).
        var resp = await client.IntrospectAsync(
            token: "tok_1",
            cancellationToken: CancellationToken.None);
        Assert.False(resp.Active);

        await server.WaitAsync();
    }

    [Fact]
    [Conformance("rfc6749-invalid-client-must-map-to-authentication-failure")]
    public async Task ClientCredentialsAsync_ServerError_ParsesOAuthErrorInExceptionMessage()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/token", ctx.Request.Url?.AbsolutePath);

            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = "application/json";
            var payload = @"{ ""error"": ""invalid_client"" }";
            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }, maxRequests: 1);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true));

        var ex = await Assert.ThrowsAsync<InvalidClientException>(() =>
            client.ClientCredentialsAsync(
                scope: "tools/add",
                resource: null,
                cancellationToken: CancellationToken.None));

        Assert.Contains("error=invalid_client", ex.Message);
        Assert.Equal("invalid_client", ex.OAuthError);
        await server.WaitAsync();
    }

    [Fact]
    public async Task TokenExchangeAsync_ConsentRequired_ThrowsConsentRequiredExceptionWithMetadata()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/token", ctx.Request.Url?.AbsolutePath);
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = "application/json";
            var payload = @"{
  ""error"": ""consent_required"",
  ""error_description"": ""user must grant access"",
  ""service_id"": ""calendar"",
  ""cause"": ""missing_user_consent"",
  ""consent_url"": ""https://as.example.com/consent?service=calendar""
}";
            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }, maxRequests: 1);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true));

        var ex = await Assert.ThrowsAsync<ConsentRequiredException>(() =>
            client.TokenExchangeAsync(new TokenExchangeOptions("sub_token", resource: (string?)null), CancellationToken.None));

        Assert.Equal("consent_required", ex.OAuthError);
        Assert.Equal("calendar", ex.ServiceId);
        Assert.Equal("missing_user_consent", ex.CauseDetail);
        Assert.Equal("https://as.example.com/consent?service=calendar", ex.ConsentUrl);
        await server.WaitAsync();
    }

    [Fact]
    public async Task TokenExchangeAsync_InteractionRequired_ThrowsConsentRequiredException()
    {
        using var server = new TestServer(async ctx =>
        {
            Assert.Equal("/oauth/token", ctx.Request.Url?.AbsolutePath);
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = "application/json";
            var payload = @"{
  ""error"": ""interaction_required"",
  ""error_description"": ""user interaction required"",
  ""service"": ""profile""
}";
            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }, maxRequests: 1);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true));

        var ex = await Assert.ThrowsAsync<ConsentRequiredException>(() =>
            client.TokenExchangeAsync(new TokenExchangeOptions("sub_token", resource: (string?)null), CancellationToken.None));

        Assert.Equal("interaction_required", ex.OAuthError);
        Assert.Equal("profile", ex.ServiceId);
        Assert.Equal("user interaction required", ex.CauseDetail);
        Assert.Null(ex.ConsentUrl);
        await server.WaitAsync();
    }

    [Fact]
    public async Task ClientCredentialsAsync_CircuitBreakerOpensAfterOAuthServerErrors()
    {
        using var server = new TestServer(async ctx =>
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = "application/json";
            var payload = @"{ ""error"": ""server_error"", ""error_description"": ""x"" }";
            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }, maxRequests: 2);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            resilience: new AuthplaneAuthResilienceOptions
            {
                CircuitBreakerThreshold = 2,
                CircuitBreakerCooldownSeconds = 60,
            });

        await Assert.ThrowsAsync<AuthplaneTokenRequestException>(() =>
            client.ClientCredentialsAsync("s1", (string?)null, CancellationToken.None));
        await Assert.ThrowsAsync<AuthplaneTokenRequestException>(() =>
            client.ClientCredentialsAsync("s2", (string?)null, CancellationToken.None));

        Assert.Equal(CircuitBreakerState.Open, client.CircuitBreakerState);

        await Assert.ThrowsAsync<CircuitOpenException>(() =>
            client.ClientCredentialsAsync("s3", (string?)null, CancellationToken.None));

        Assert.Equal(2, server.RequestCount);
        await server.WaitAsync();
    }

    [Fact]
    public async Task ClientCredentialsAsync_InvalidScopeDoesNotOpenCircuit()
    {
        using var server = new TestServer(async ctx =>
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = "application/json";
            var payload = @"{ ""error"": ""invalid_scope"" }";
            var bytes = Encoding.UTF8.GetBytes(payload);
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        }, maxRequests: 4);

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client_1",
            clientSecret: "secret_1",
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            resilience: new AuthplaneAuthResilienceOptions
            {
                CircuitBreakerThreshold = 2,
                CircuitBreakerCooldownSeconds = 60,
            });

        for (var i = 0; i < 4; i++)
        {
            await Assert.ThrowsAsync<InvalidScopeException>(() =>
                client.ClientCredentialsAsync("scope", (string?)null, CancellationToken.None));
        }

        Assert.NotEqual(CircuitBreakerState.Open, client.CircuitBreakerState);
        await server.WaitAsync();
    }
}

