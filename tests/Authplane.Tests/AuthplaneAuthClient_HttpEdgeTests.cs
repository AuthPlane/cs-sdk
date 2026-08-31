using System.Net;
using System.Text;
using Xunit;

namespace Authplane.Tests;

public sealed class AuthplaneAuthClientEdgeCoverageTests
{
    [Fact]
    public void Constructor_RejectsInvalidArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new AuthplaneAuthClient("", "c", "s"));
        Assert.Throws<ArgumentNullException>(() => new AuthplaneAuthClient("http://localhost", "", "s"));
        Assert.Throws<ArgumentNullException>(() => new AuthplaneAuthClient("http://localhost", "c", ""));
    }

    [Fact]
    public async Task ClientCredentialsAsync_NetworkFailure_ThrowsServerError()
    {
        await using var client = new AuthplaneAuthClient(
            issuerUrl: "http://localhost:1",
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: new FetchSettings(
                ssrfProtection: false,
                allowHttp: true,
                allowLocalhost: true,
                allowPrivateNetworks: true,
                timeoutSeconds: 0.5));

        await Assert.ThrowsAsync<ServerError>(() =>
            client.ClientCredentialsAsync("tools/add", "http://localhost:8080/mcp", CancellationToken.None));
    }

    [Fact]
    public async Task IntrospectAsync_RejectsEmptyToken()
    {
        await using var client = new AuthplaneAuthClient(
            issuerUrl: "http://localhost:9000",
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.IntrospectAsync("", cancellationToken: CancellationToken.None));
    }

    [Fact]
    public async Task TokenExchangeAsync_RejectsNullOptions()
    {
        await using var client = new AuthplaneAuthClient(
            issuerUrl: "http://localhost:9000",
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            client.TokenExchangeAsync(null!, CancellationToken.None));
    }

    [Fact]
    public async Task IntrospectAsync_NonSuccess_WithOAuthError_ThrowsRequestException()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"error\":\"invalid_client\"}");
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        // Introspect now routes through MapOAuthError (M2), so the body
        // `{"error":"invalid_client"}` dispatches to InvalidClientException
        // (subclass of AuthplaneTokenRequestException) — match the umbrella
        // so the typed dispatch doesn't break the test.
        var ex = await Assert.ThrowsAnyAsync<AuthplaneTokenRequestException>(() =>
            client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None));
        Assert.Contains("error=invalid_client", ex.Message);
    }

    [Fact]
    public async Task ClientCredentialsAsync_UnsupportedTokenType_ThrowsParsingException()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"access_token\":\"at\",\"token_type\":\"Unknown\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        await Assert.ThrowsAsync<AuthplaneTokenResponseParsingException>(() =>
            client.ClientCredentialsAsync("tools/add", "http://localhost:8080/mcp", CancellationToken.None));
    }

    [Fact]
    public void ErrorTypes_Constructors_PreserveMessageAndInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var tokenParsing = new AuthplaneTokenResponseParsingException("boom", inner);
        var introspectionParsing = new AuthplaneIntrospectionResponseParsingException("oops", inner);
        var serverError = new ServerError("server");

        Assert.Equal("boom", tokenParsing.Message);
        Assert.Same(inner, tokenParsing.InnerException);
        Assert.Equal("oops", introspectionParsing.Message);
        Assert.Same(inner, introspectionParsing.InnerException);
        Assert.Equal("server", serverError.Message);
    }

    private sealed class TestServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loop;
        public string IssuerUrl { get; }

        public TestServer(Func<HttpListenerContext, Task> handler)
        {
            (IssuerUrl, _listener) = LoopbackHttpListener.Start();

            _loop = Task.Run(async () =>
            {
                try
                {
                    var ctx = await _listener.GetContextAsync();
                    await handler(ctx);
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
            try { _loop.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
        }
    }
}
