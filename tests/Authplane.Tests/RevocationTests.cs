using System.Net;
using System.Text;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Group 5: Token revocation (RFC 7009).
/// </summary>
public sealed class RevocationTests
{
    [Fact]
    [Conformance("rfc7009-revocation-200-is-success-even-for-already-invalid-token")]
    public async Task Revoke_200Ok_SucceedsForAlreadyInvalidToken()
    {
        using var server = new TestServer(async ctx =>
        {
            // RFC 7009 says 200 is returned even if the token was already invalid.
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            var bytes = Encoding.UTF8.GetBytes("{}");
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        // Should not throw even though the token might be already revoked/invalid.
        await client.RevokeAsync("already_invalid_token", "access_token", CancellationToken.None);
    }

    [Fact]
    [Conformance("rfc7009-revocation-request-must-post-token-and-token-type-hint")]
    public async Task Revoke_PostsTokenAndHint()
    {
        string? capturedBody = null;
        string? capturedMethod = null;
        using var server = new TestServer(async ctx =>
        {
            capturedMethod = ctx.Request.HttpMethod;
            capturedBody = await new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEndAsync();

            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            var bytes = Encoding.UTF8.GetBytes("{}");
            ctx.Response.ContentLength64 = bytes.Length;
            await ctx.Response.OutputStream.WriteAsync(bytes);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.RevokeAsync("my_token", "access_token", CancellationToken.None);

        Assert.Equal("POST", capturedMethod);
        Assert.NotNull(capturedBody);
        Assert.Contains("token=my_token", capturedBody!);
        Assert.Contains("token_type_hint=access_token", capturedBody!);
    }

    [Fact]
    [Conformance("rfc7009-revocation-server-errors-must-surface")]
    public async Task Revoke_ServerError_ThrowsException()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"error\":\"server_error\",\"error_description\":\"internal failure\"}");
            ctx.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        // After M3 (MapOAuthError adds 5xx → ServerError fallback) a 500 from
        // the revocation endpoint surfaces as ServerError regardless of the
        // (often-misleading) OAuth error code in the body.
        // The wire error stays in the message.
        var ex = await Assert.ThrowsAsync<ServerError>(() =>
            client.RevokeAsync("tok_1", "access_token", CancellationToken.None));

        Assert.Contains("500", ex.Message, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

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
