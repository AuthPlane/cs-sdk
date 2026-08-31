using System.Net;
using System.Text;
using Xunit;

namespace Authplane.Tests;

public sealed class TransportSecurityTests
{
    [Fact]
    public void AuthClientCtor_BlocksLocalhostInProdMode()
    {
        var ex = Assert.Throws<AuthplaneException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "http://localhost:9000",
                clientId: "client",
                clientSecret: "secret",
                fetchSettings: new FetchSettings(
                    ssrfProtection: true,
                    allowHttp: true,
                    allowLocalhost: false,
                    allowPrivateNetworks: false,
                    timeoutSeconds: 10)));
        Assert.Contains("localhost policy", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthClientCtor_BlocksPrivateNetworkInProdMode()
    {
        var ex = Assert.Throws<AuthplaneException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "http://10.0.0.5:9000",
                clientId: "client",
                clientSecret: "secret",
                fetchSettings: new FetchSettings(
                    ssrfProtection: true,
                    allowHttp: true,
                    allowLocalhost: false,
                    allowPrivateNetworks: false,
                    timeoutSeconds: 10)));
        Assert.Contains("network policy", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResourceCreate_DevModeAllowsLocalhostHttp()
    {
        // Asserts that dev-mode FetchSettings permits an http://localhost issuer
        // through TransportSecurity. Spins up a minimal AS metadata + JWKS
        // listener so the assertion is about the policy check, not the absence
        // of a server.
        var (issuer, httpListener) = LoopbackHttpListener.Start();
        using var listener = httpListener;

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var loop = Task.Run(async () =>
        {
            while (listener.IsListening && !cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await listener.GetContextAsync().WaitAsync(cts.Token);
                }
                catch
                {
                    return;
                }

                try
                {
                    var path = ctx.Request.Url?.AbsolutePath.TrimEnd('/') ?? string.Empty;
                    string body;
                    if (path == "/.well-known/jwks.json")
                    {
                        body = "{\"keys\":[]}";
                    }
                    else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                             path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        body = $"{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"{issuer}/.well-known/jwks.json\"}}";
                    }
                    else
                    {
                        ctx.Response.StatusCode = 404;
                        continue;
                    }

                    var bytes = Encoding.UTF8.GetBytes(body);
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes, cts.Token);
                }
                finally
                {
                    ctx.Response.OutputStream.Close();
                }
            }
        });

        var resource = await AuthplaneResource.CreateAsync(
            issuer: issuer,
            resource: "http://localhost:8080/mcp",
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true));
        await resource.DisposeAsync();

        cts.Cancel();
        listener.Stop();
    }

}

