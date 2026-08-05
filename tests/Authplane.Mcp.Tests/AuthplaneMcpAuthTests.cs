using System.Net;
using System.Text;
using Xunit;

namespace Authplane.Mcp.Tests;

public class AuthplaneMcpAuthTests
{
    [Fact]
    public async Task CreateVerifierAsync_UsesOptionsValues()
    {
        using var server = new MockJwksServer();
        var options = new AuthplaneMcpAuth.Options(
            issuer: server.IssuerUrl,
            resource: "https://mcp.example.com",
            scopes: new[] { "tools/query" },
            devMode: true);

        var verifier = await AuthplaneMcpAuth.CreateVerifierAsync(options);

        Assert.Equal(server.IssuerUrl, verifier.Issuer);
        Assert.Equal("https://mcp.example.com", verifier.Resource);
        Assert.Contains("tools/query", verifier.Scopes);
    }

    [Fact]
    public async Task CreateResourceAsync_UsesOptionsValues_DevModeFalse()
    {
        // DevMode=false requires HTTPS which our mock server can't provide.
        // Verify the FetchSettings are set correctly by checking the exception
        // (metadata discovery will fail against an unreachable HTTPS endpoint).
        var options = new AuthplaneMcpAuth.Options(
            issuer: "https://unreachable.authplane.test",
            resource: "https://mcp.example.com",
            scopes: new[] { "tools/query" },
            devMode: false);

        // MissingMetadataEndpointException is the typed subtype now thrown by
        // discovery failures — accept the base type so the assertion is tolerant
        // of either.
        var ex = await Assert.ThrowsAnyAsync<AuthplaneException>(() =>
            AuthplaneMcpAuth.CreateResourceAsync(options));
        Assert.Contains("Failed to discover JWKS URI", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateResourceAsync_UsesOptionsValues_DevModeTrue()
    {
        using var server = new MockJwksServer();
        var options = new AuthplaneMcpAuth.Options(
            issuer: server.IssuerUrl,
            resource: "https://mcp.example.com",
            scopes: new[] { "tools/query" },
            devMode: true);

        var resource = await AuthplaneMcpAuth.CreateResourceAsync(options);

        Assert.Equal(server.IssuerUrl, resource.Issuer);
        Assert.Equal("https://mcp.example.com", resource.Resource);
        Assert.Contains("tools/query", resource.Scopes);

        // FetchSettings.FromDevMode(true)
        Assert.False(resource.FetchSettings.SsrfProtection);
        Assert.True(resource.FetchSettings.AllowHttp);
        Assert.True(resource.FetchSettings.AllowLocalhost);
        Assert.True(resource.FetchSettings.AllowPrivateNetworks);
        Assert.Equal(10.0, resource.FetchSettings.TimeoutSeconds);
    }

    [Fact]
    public void Options_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AuthplaneMcpAuth.Options(
                issuer: null!,
                resource: "https://mcp.example.com",
                scopes: new[] { "tools/query" }));

        Assert.Throws<ArgumentNullException>(() =>
            new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: null!,
                scopes: new[] { "tools/query" }));

        Assert.Throws<ArgumentNullException>(() =>
            new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: "https://mcp.example.com",
                scopes: null!));
    }

    [Fact]
    public async Task CreateResourceAsync_NullOptions_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            AuthplaneMcpAuth.CreateResourceAsync(null!));
    }

    private sealed class MockJwksServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loopTask;
        public string IssuerUrl { get; }

        public MockJwksServer()
        {
            var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            tcp.Start();
            var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            tcp.Stop();

            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{port}/");
            _listener.Start();
            IssuerUrl = $"http://localhost:{port}";

            _loopTask = Task.Run(async () =>
            {
                try
                {
                    while (_listener.IsListening)
                    {
                        HttpListenerContext ctx;
                        try { ctx = await _listener.GetContextAsync(); }
                        catch { break; }

                        var path = ctx.Request.Url?.AbsolutePath ?? string.Empty;
                        if (path == "/.well-known/jwks.json")
                        {
                            var bytes = Encoding.UTF8.GetBytes("{\"keys\":[]}");
                            ctx.Response.StatusCode = 200;
                            ctx.Response.ContentType = "application/json";
                            ctx.Response.ContentLength64 = bytes.Length;
                            await ctx.Response.OutputStream.WriteAsync(bytes);
                        }
                        else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                                 path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                        {
                            var meta = $"{{\"issuer\":\"{IssuerUrl}\",\"jwks_uri\":\"{IssuerUrl}/.well-known/jwks.json\"}}";
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
                catch { /* ignore */ }
            });
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { /* ignore */ }
            try { _loopTask.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
        }
    }
}
