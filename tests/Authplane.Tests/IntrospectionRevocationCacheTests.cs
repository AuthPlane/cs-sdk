using System.Net;
using System.Text;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers <see cref="IntrospectionRevocation"/>'s SHA-256 cache-key path:
/// a second call for the same token must hit the cache (not the AS), which
/// is only true if the read and write paths produce the same digest. A bug
/// drifting the read key away from the write key would silently re-issue an
/// introspection per call.
/// </summary>
public sealed class IntrospectionRevocationCacheTests
{
    [Fact]
    public async Task IsRevokedAsync_RepeatCallForSameToken_HitsCacheOnSecondCall()
    {
        using var server = new CountingTestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"active\":true}");
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

        var checker = new IntrospectionRevocation(client);

        var first = await checker.IsRevokedAsync("tok_repeat", CancellationToken.None);
        var second = await checker.IsRevokedAsync("tok_repeat", CancellationToken.None);

        Assert.False(first);
        Assert.False(second);

        // The cache key is a SHA-256 fingerprint of the token. If the read
        // and write keys ever drift apart (e.g. a future change to the
        // CacheKey helper that's only applied on one side) the second call
        // would re-hit the AS. Pinning the introspection hit count at 1
        // catches that drift.
        Assert.Equal(1, server.HitCount);
    }

    [Fact]
    public async Task IsRevokedAsync_DistinctTokens_DoNotCollideOnCache()
    {
        using var server = new CountingTestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"active\":true}");
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

        var checker = new IntrospectionRevocation(client);

        await checker.IsRevokedAsync("tok_a", CancellationToken.None);
        await checker.IsRevokedAsync("tok_b", CancellationToken.None);

        // Two distinct tokens must produce distinct digests (SHA-256 is
        // collision-resistant), so each pays one introspection hit.
        Assert.Equal(2, server.HitCount);
    }

    // -----------------------------------------------------------------------
    // Helper — a TestServer variant that handles multiple requests and
    // exposes a hit count, which the local IntrospectionEdgeCaseTests'
    // single-shot server doesn't.
    // -----------------------------------------------------------------------

    private sealed class CountingTestServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loop;
        private int _hits;

        public string IssuerUrl { get; }

        public int HitCount => Volatile.Read(ref _hits);

        public CountingTestServer(Func<HttpListenerContext, Task> handler)
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
                while (_listener.IsListening)
                {
                    HttpListenerContext ctx;
                    try
                    {
                        ctx = await _listener.GetContextAsync();
                    }
                    catch
                    {
                        return;
                    }

                    Interlocked.Increment(ref _hits);
                    try { await handler(ctx); }
                    catch { /* ignore */ }
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
