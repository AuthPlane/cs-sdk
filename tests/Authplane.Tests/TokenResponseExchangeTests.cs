using System.Net;
using System.Text;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Group 3: Token response parsing, token exchange (RFC 6749, RFC 8693, RFC 9449 token types).
/// Exercises OAuthResponseParser and OAuthOperations via AuthplaneAuthClient.
/// </summary>
public sealed class TokenResponseExchangeTests
{
    // -----------------------------------------------------------------------
    // RFC 6749 — Token Response Parsing
    // -----------------------------------------------------------------------

    [Fact]
    [Conformance("rfc6749-token-response-must-contain-access-token")]
    public async Task TokenResponse_MissingAccessToken_ThrowsParsingException()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"token_type\":\"Bearer\",\"expires_in\":60}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await Assert.ThrowsAsync<AuthplaneTokenResponseParsingException>(() =>
            client.ClientCredentialsAsync("scope", (string?)null, CancellationToken.None));
    }

    [Fact]
    [Conformance("rfc6749-token-response-expires-in-must-be-non-negative-integer")]
    public async Task TokenResponse_NegativeExpiresIn_ThrowsParsingException()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":-5}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await Assert.ThrowsAsync<AuthplaneTokenResponseParsingException>(() =>
            client.ClientCredentialsAsync("scope", (string?)null, CancellationToken.None));
    }

    [Fact]
    public async Task TokenResponse_MissingContentType_StillParsed()
    {
        // The response Content-Type is deliberately not validated: a 2xx
        // token response with a well-formed
        // JSON body but no Content-Type header must succeed.
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = null;
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var token = await client.ClientCredentialsAsync("scope", (string?)null, CancellationToken.None);
        Assert.Equal("at", token.AccessToken);
    }

    [Fact]
    [Conformance("rfc6749-basic-auth-credentials-must-be-form-urlencoded-before-base64")]
    public async Task ClientCredentials_BasicAuthHeaderIsSent()
    {
        string? capturedAuth = null;
        using var server = new TestServer(async ctx =>
        {
            capturedAuth = ctx.Request.Headers["Authorization"];

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client:id",
            clientSecret: "secret/value",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.ClientCredentialsAsync("scope", (string?)null, CancellationToken.None);

        Assert.NotNull(capturedAuth);
        Assert.StartsWith("Basic ", capturedAuth!);
        // RFC 6749 §2.3.1: credentials MUST be form-URL-encoded before base64.
        var base64Part = capturedAuth!["Basic ".Length..];
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64Part));
        Assert.Equal("client%3Aid:secret%2Fvalue", decoded);
    }

    [Fact]
    [Conformance("rfc6749-client-credentials-scopes-must-support-multiple-values")]
    public async Task ClientCredentials_MultipleScopes_SentAsSpaceSeparated()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"read write\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.ClientCredentialsAsync("read write", (string?)null, CancellationToken.None);

        Assert.NotNull(capturedBody);
        // URL-encoded space = "+" in WebUtility.UrlEncode
        Assert.Contains("scope=read+write", capturedBody!);
        Assert.Equal("read write", resp.Scope);
    }

    [Fact]
    [Conformance("rfc6749-token-response-token-type-must-be-supported")]
    public async Task TokenResponse_UnsupportedTokenType_ThrowsParsingException()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"MAC\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await Assert.ThrowsAsync<AuthplaneTokenResponseParsingException>(() =>
            client.ClientCredentialsAsync("scope", (string?)null, CancellationToken.None));
    }

    // -----------------------------------------------------------------------
    // RFC 8693 — Token Exchange
    // -----------------------------------------------------------------------

    [Fact]
    [Conformance("rfc8693-grant-type-must-be-token-exchange")]
    public async Task TokenExchange_GrantTypeIsTokenExchange()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions("sub_token", resource: (string?)null),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        Assert.Contains(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
            capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-default-subject-token-type-is-access-token")]
    public async Task TokenExchange_DefaultSubjectTokenType()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions("sub_token", resource: (string?)null),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        Assert.Contains(
            "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-actor-token-type-defaults-when-actor-token-is-present")]
    public async Task TokenExchange_ActorTokenType_DefaultsWhenActorPresent()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions("sub_token", actorToken: "actor_tok", resource: (string?)null),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        Assert.Contains("actor_token=actor_tok", capturedBody!);
        Assert.Contains(
            "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token",
            capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-resource-parameter-must-be-sent-when-configured")]
    public async Task TokenExchange_ResourceParameter_Sent()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions("sub_token", resource: "https://api.example.com"),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        Assert.Contains("resource=https", capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-audience-parameter-must-be-sent-when-configured")]
    public async Task TokenExchange_AudienceParameter_Sent()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions(
                "sub_token",
                resources: null,
                audiences: new[] { "https://audience.example.com" }),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        Assert.Contains("audience=https", capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-error-mapping-invalid-grant")]
    public async Task TokenExchange_InvalidGrant_MapsToException()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"error\":\"invalid_grant\",\"error_description\":\"subject token expired\"}");
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var ex = await Assert.ThrowsAsync<InvalidGrantException>(() =>
            client.TokenExchangeAsync(
                new TokenExchangeOptions("sub_token", resource: (string?)null),
                CancellationToken.None));

        Assert.Equal("invalid_grant", ex.OAuthError);
    }

    [Fact]
    [Conformance("rfc8693-empty-resource-and-audience-values-must-be-omitted")]
    public async Task TokenExchange_EmptyResource_OmittedFromBody()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions("sub_token", resource: (string?)null),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        Assert.DoesNotContain("resource=", capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-multiple-resource-parameters-must-be-emitted")]
    public async Task TokenExchange_MultipleResources_EmittedAsSeparateParams()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions(
                "sub_token",
                resources: new[] { "https://api1.example.com", "https://api2.example.com" },
                audiences: null),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        // Both resource values must appear as separate entries
        var resourceCount = System.Text.RegularExpressions.Regex.Count(capturedBody!, "resource=");
        Assert.Equal(2, resourceCount);
        Assert.Contains("resource=https%3A%2F%2Fapi1.example.com", capturedBody!);
        Assert.Contains("resource=https%3A%2F%2Fapi2.example.com", capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-multiple-audience-parameters-must-be-emitted")]
    public async Task TokenExchange_MultipleAudiences_EmittedAsSeparateParams()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.TokenExchangeAsync(
            new TokenExchangeOptions(
                "sub_token",
                resources: null,
                audiences: new[] { "aud1", "aud2" }),
            CancellationToken.None);

        Assert.NotNull(capturedBody);
        var audienceCount = System.Text.RegularExpressions.Regex.Count(capturedBody!, "audience=");
        Assert.Equal(2, audienceCount);
        Assert.Contains("audience=aud1", capturedBody!);
        Assert.Contains("audience=aud2", capturedBody!);
    }

    [Fact]
    [Conformance("rfc8693-success-response-must-use-access-token-issued-token-type-when-present")]
    public async Task TokenExchange_IssuedTokenType_Parsed()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60,"
                + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.TokenExchangeAsync(
            new TokenExchangeOptions("sub_token", resource: (string?)null),
            CancellationToken.None);

        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", resp.IssuedTokenType);
    }

    [Fact]
    [Conformance("rfc8693-token-exchange-response-must-contain-issued-token-type")]
    public async Task TokenExchange_MissingIssuedTokenType_ThrowsParsingException()
    {
        // RFC 8693 §2.2.1 says issued_token_type is REQUIRED in the response.
        // The SDK now enforces this and throws when the field is absent.
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await Assert.ThrowsAsync<AuthplaneTokenResponseParsingException>(() =>
            client.TokenExchangeAsync(
                new TokenExchangeOptions("sub_token", resource: (string?)null),
                CancellationToken.None));
    }

    [Fact]
    [Conformance("rfc9449-dpop-grant-token-type-must-be-dpop")]
    public async Task TokenExchange_DPoP_TokenTypeIsDPoP()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"dpop_at\",\"token_type\":\"DPoP\",\"expires_in\":120,\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        var signer = await ES256DpoPSigner.CreateAsync(CancellationToken.None);
        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true),
            dpopSigner: signer);

        var resp = await client.TokenExchangeAsync(
            new TokenExchangeOptions("sub_token", resource: (string?)null),
            CancellationToken.None);

        Assert.Equal("DPoP", resp.TokenType);
    }

    [Fact]
    [Conformance("rfc9449-token-response-token-type-dpop-must-be-accepted")]
    public async Task TokenResponse_DPoPTokenType_Accepted()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"dpop_at\",\"token_type\":\"DPoP\",\"expires_in\":60}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.ClientCredentialsAsync("scope", (string?)null, CancellationToken.None);

        Assert.Equal("DPoP", resp.TokenType);
        Assert.Equal("dpop_at", resp.AccessToken);
    }

    // -----------------------------------------------------------------------
    // Helper: one-shot test server
    // -----------------------------------------------------------------------

    private sealed class TestServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loop;
        public string IssuerUrl { get; }

        public TestServer(Func<HttpListenerContext, Task> handler)
        {
            var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            tcp.Start();
            var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            tcp.Stop();

            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{port}/");
            _listener.Start();
            IssuerUrl = $"http://localhost:{port}";

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

    // -----------------------------------------------------------------------
    // Additional missing cases
    // -----------------------------------------------------------------------

    [Fact]
    [Conformance("rfc8693-subject-token-is-required")]
    public void TokenExchange_SubjectTokenIsRequired()
    {
        // TokenExchangeOptions constructor requires non-empty subjectToken.
        Assert.Throws<ArgumentException>(() => new TokenExchangeOptions(subjectToken: "", resource: (string?)null));
        Assert.Throws<ArgumentException>(() => new TokenExchangeOptions(subjectToken: " ", resource: (string?)null));
    }

    [Fact]
    [Conformance("rfc8707-client-credentials-multiple-resource-parameters-must-be-emitted")]
    public async Task ClientCredentials_MultipleResources_EmittedAsSeparateParams()
    {
        string? capturedBody = null;
        using var server = new TestServer(async ctx =>
        {
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            var payload = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":60}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.ClientCredentialsAsync(
            "read",
            resources: new[] { "https://api1.example.com", "https://api2.example.com" },
            cancellationToken: CancellationToken.None);

        Assert.NotNull(capturedBody);
        var resourceCount = System.Text.RegularExpressions.Regex.Count(capturedBody!, "resource=");
        Assert.Equal(2, resourceCount);
        Assert.Contains("resource=https%3A%2F%2Fapi1.example.com", capturedBody!);
        Assert.Contains("resource=https%3A%2F%2Fapi2.example.com", capturedBody!);
    }
}
