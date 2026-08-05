using System.Net;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Authplane.Mcp.Tests;

/// <summary>
/// Covers the <see cref="AuthplaneMcpAuth.SetupAsync"/> factory and the
/// <see cref="AuthplaneMcpAuth.AuthplaneMcpAuthHandle"/> dispose path —
/// otherwise uncovered because the middleware tests construct the resource
/// directly.
/// </summary>
public sealed class AuthplaneMcpAuthSetupTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly ECDsa _ecdsa;

    public AuthplaneMcpAuthSetupTests()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var port = GetFreePort();
        _issuer = $"http://localhost:{port}";

        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://localhost:{port}/");
        _listener.Start();

        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx;
                try { ctx = await _listener.GetContextAsync().WaitAsync(TimeSpan.FromSeconds(1)); }
                catch { continue; }

                if (ctx is null)
                {
                    continue;
                }

                try
                {
                    var path = ctx.Request.Url?.AbsolutePath.TrimEnd('/') ?? string.Empty;
                    string body;
                    if (path == "/.well-known/jwks.json")
                    {
                        body = JwksForEs256(_ecdsa, "kid_1");
                    }
                    else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                             path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        body = $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";
                    }
                    else
                    {
                        ctx.Response.StatusCode = 404;
                        continue;
                    }

                    var bytes = Encoding.UTF8.GetBytes(body);
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes);
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
        try { if (_listener.IsListening) { _listener.Stop(); } } catch { /* ignore */ }
        _ecdsa.Dispose();
    }

    [Fact]
    public async Task SetupAsync_ReturnsHandleWithResource_AndDisposesCleanly()
    {
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: "http://localhost:8080/mcp",
            scopes: new[] { "tools/add" },
            devMode: true);

        await using var handle = await AuthplaneMcpAuth.SetupAsync(options, CancellationToken.None);

        Assert.NotNull(handle.Resource);
        Assert.Equal(_issuer, handle.Resource.Issuer);
        Assert.Equal("http://localhost:8080/mcp", handle.Resource.Resource);
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static string JwksForEs256(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);
        static string B64U(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var x = B64U(p.Q!.X!);
        var y = B64U(p.Q!.Y!);
        return $@"{{""keys"":[{{""kty"":""EC"",""crv"":""P-256"",""kid"":""{kid}"",""use"":""sig"",""alg"":""ES256"",""x"":""{x}"",""y"":""{y}""}}]}}";
    }
}
