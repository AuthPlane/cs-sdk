using System.Net;
using System.Text;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers <see cref="IAuthProvider"/>'s built-in <see cref="ClientCredentialsProvider"/>
/// and the <see cref="ASCredentials"/> record + its <c>ToAuthProvider</c> bridge.
/// Both surfaces were unreferenced in tests despite being public API.
/// </summary>
public sealed class AuthProviderAndAsCredentialsTests
{
    [Fact]
    public void ClientCredentialsProvider_BuildsHttpBasicHeader()
    {
        var provider = new ClientCredentialsProvider("client", "s3cr3t");
        var headers = provider.AuthHeaders();

        Assert.True(headers.ContainsKey("Authorization"));
        var value = headers["Authorization"];
        Assert.StartsWith("Basic ", value, StringComparison.Ordinal);
    }

    [Fact]
    public void ClientCredentialsProvider_FormUrlEncodesId_AndSecret_PerRfc6749Section231()
    {
        // RFC 6749 §2.3.1: each credential is form-URL-encoded before being
        // joined with `:` and base64-encoded. Reserved characters must round-trip.
        var provider = new ClientCredentialsProvider("client&id", "p%ss/word");
        var value = provider.AuthHeaders()["Authorization"];

        // Decode the base64 portion and verify the inner shape is
        // "url-encoded-id:url-encoded-secret".
        var b64 = value["Basic ".Length..];
        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        Assert.Equal("client%26id:p%25ss%2Fword", decoded);
    }

    [Fact]
    public void ClientCredentialsProvider_BlankClientId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ClientCredentialsProvider("", "s"));
        Assert.Throws<ArgumentException>(() => new ClientCredentialsProvider("   ", "s"));
    }

    [Fact]
    public void ClientCredentialsProvider_BlankClientSecret_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ClientCredentialsProvider("id", ""));
        Assert.Throws<ArgumentException>(() => new ClientCredentialsProvider("id", "  "));
    }

    [Fact]
    public void ASCredentials_RecordExposesValues()
    {
        var creds = new ASCredentials("client", "secret");
        Assert.Equal("client", creds.ClientId);
        Assert.Equal("secret", creds.ClientSecret);
    }

    [Fact]
    public void ASCredentials_ToAuthProvider_ReturnsClientCredentialsProvider()
    {
        var creds = new ASCredentials("client", "secret");
        var provider = creds.ToAuthProvider();
        Assert.IsType<ClientCredentialsProvider>(provider);
        Assert.True(provider.AuthHeaders().ContainsKey("Authorization"));
    }

    [Fact]
    public void ASCredentials_RecordEqualityByValue()
    {
        var a = new ASCredentials("c", "s");
        var b = new ASCredentials("c", "s");
        var c = new ASCredentials("c", "other");
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
    }

    [Fact]
    public async Task ASCredentials_AuthorizationHeader_LandsOnIntrospectWire()
    {
        // End-to-end: an AuthplaneAuthClient constructed from ASCredentials
        // must put the Basic-encoded credential on the actual wire request,
        // not just through AuthHeaders() in isolation. Captures the
        // Authorization header value the AS would see.
        var captured = new List<KeyValuePair<string, string>>();
        using var server = new RequestCapturingServer(captured, async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"active\":true}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        var creds = new ASCredentials("my-client", "s3cr3t");
        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            asCredentials: creds,
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);
        Assert.True(resp.Active);

        var authHeader = captured.Find(kv => string.Equals(kv.Key, "Authorization", StringComparison.OrdinalIgnoreCase));
        Assert.False(string.IsNullOrEmpty(authHeader.Value), "Authorization header missing from introspect request");
        Assert.StartsWith("Basic ", authHeader.Value, StringComparison.Ordinal);

        var b64 = authHeader.Value["Basic ".Length..];
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        Assert.Equal("my-client:s3cr3t", decoded);
    }

    [Fact]
    public async Task ASCredentials_AuthorizationHeader_LandsOnRevokeWire()
    {
        // Same E2E for revocation — the IAuthProvider must be wired into the
        // /oauth/revoke path as well as /oauth/introspect.
        var captured = new List<KeyValuePair<string, string>>();
        using var server = new RequestCapturingServer(captured, async ctx =>
        {
            // RFC 7009: 200 OK on success, empty body.
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentLength64 = 0;
            ctx.Response.OutputStream.Close();
            await Task.CompletedTask;
        });

        var creds = new ASCredentials("rev-client", "rev-secret");
        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            asCredentials: creds,
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.RevokeAsync("tok_2", cancellationToken: CancellationToken.None);

        var authHeader = captured.Find(kv => string.Equals(kv.Key, "Authorization", StringComparison.OrdinalIgnoreCase));
        Assert.False(string.IsNullOrEmpty(authHeader.Value), "Authorization header missing from revoke request");
        var b64 = authHeader.Value["Basic ".Length..];
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        Assert.Equal("rev-client:rev-secret", decoded);
    }

    // -----------------------------------------------------------------------
    // Helper: one-shot HTTP listener that captures the incoming request's
    // Authorization header before invoking the response handler.
    // -----------------------------------------------------------------------

    private sealed class RequestCapturingServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loop;
        public string IssuerUrl { get; }

        public RequestCapturingServer(
            List<KeyValuePair<string, string>> captured,
            Func<HttpListenerContext, Task> handler)
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
                    foreach (var name in ctx.Request.Headers.AllKeys)
                    {
                        if (name is null)
                        {
                            continue;
                        }
                        captured.Add(new KeyValuePair<string, string>(name, ctx.Request.Headers[name] ?? string.Empty));
                    }
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
