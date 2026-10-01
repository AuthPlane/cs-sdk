using System.Net;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// <see cref="AuthplaneClient.CreateAsync"/> constructs the client before it primes the
/// metadata cache, so it owns that client until it returns one. Every way the priming
/// fetch can fail is a path that used to abandon it: the <see cref="HttpClient"/> and its
/// handler and connection pool, the metadata cache's semaphore and background refresh, and
/// the JWKS cache's gate are released only by <c>DisposeAsync</c>, and nothing can reach
/// them once the call has thrown.
///
/// This is the likelier trigger than the constructor-argument paths its sibling class
/// pins: an authorization server that is down at process start is a transient condition
/// callers retry, and each attempt used to strand one full set.
/// </summary>
public sealed class AuthplaneClientCreateOwnershipTests
{
    /// <summary>
    /// A listener that answers every request with the given status, or holds the request
    /// open until teardown when <paramref name="hangForever"/> is set.
    /// </summary>
    private static (string Issuer, IDisposable Server) StartListener(
        HttpStatusCode status = HttpStatusCode.InternalServerError,
        bool hangForever = false)
    {
        var (issuer, listener) = LoopbackHttpListener.Start();
        var shutdown = new CancellationTokenSource();

        var loop = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await listener.GetContextAsync().ConfigureAwait(false);
                }
                catch
                {
                    return;
                }

                try
                {
                    if (hangForever)
                    {
                        // Never answered while the test runs: the only thing that ends
                        // the request is the caller's cancellation token, which is what
                        // the test asserts on. Teardown releases it so the loop does not
                        // outlive the test.
                        await Task.Delay(Timeout.Infinite, shutdown.Token).ConfigureAwait(false);
                    }

                    ctx.Response.StatusCode = (int)status;
                }
                catch
                {
                    // Client went away or the listener is shutting down; neither affects
                    // the assertion under test.
                }
                finally
                {
                    try
                    {
                        ctx.Response.Close();
                    }
                    catch
                    {
                        // Already torn down.
                    }
                }
            }
        });

        return (issuer, new Stopper(listener, loop, shutdown));
    }

    private sealed class Stopper(HttpListener listener, Task loop, CancellationTokenSource shutdown)
        : IDisposable
    {
        public void Dispose()
        {
            shutdown.Cancel();
            listener.Stop();
            listener.Close();
            try
            {
                loop.Wait(TimeSpan.FromSeconds(5));
            }
            catch
            {
                // The loop exits through its own exception path when the listener closes.
            }

            shutdown.Dispose();
        }
    }

    /// <summary>
    /// The AS answers, but neither discovery endpoint yields a metadata document — the
    /// startup shape of a misconfigured or half-deployed authorization server.
    /// </summary>
    [Fact]
    public async Task MetadataFetchFails_ReleasesTheClientItBuilt()
    {
        var (issuer, server) = StartListener();
        using (server)
        {
            var probe = new AuthplaneClient.LifetimeProbe();
            AuthplaneClient.Probe.Value = probe;
            try
            {
                await Assert.ThrowsAnyAsync<AuthplaneException>(() =>
                    AuthplaneClient.CreateAsync(issuer, FetchSettings.FromDevMode(true)));
            }
            finally
            {
                AuthplaneClient.Probe.Value = null;
            }

            // Without the first assertion the second passes vacuously: the probe would
            // read 0/0 if the call had failed before ever constructing a client.
            Assert.Equal(1, probe.Constructed);
            Assert.Equal(0, probe.Live);
        }
    }

    /// <summary>
    /// The retry loop is what turns one stranded client into a leak that matters, and a
    /// flapping AS fails identically on every attempt.
    /// </summary>
    [Fact]
    public async Task RepeatedMetadataFailure_AccumulatesNoClients()
    {
        var (issuer, server) = StartListener();
        using (server)
        {
            var probe = new AuthplaneClient.LifetimeProbe();
            AuthplaneClient.Probe.Value = probe;
            try
            {
                for (var i = 0; i < 5; i++)
                {
                    await Assert.ThrowsAnyAsync<AuthplaneException>(() =>
                        AuthplaneClient.CreateAsync(issuer, FetchSettings.FromDevMode(true)));
                }
            }
            finally
            {
                AuthplaneClient.Probe.Value = null;
            }

            Assert.Equal(5, probe.Constructed);
            Assert.Equal(0, probe.Live);
        }
    }

    /// <summary>
    /// The cancellation arm: the caller's token, not a server response, ends the fetch.
    /// It leaves by a different exception type and so needs its own row.
    /// </summary>
    [Fact]
    public async Task CancelledDuringMetadataFetch_ReleasesTheClientItBuilt()
    {
        var (issuer, server) = StartListener(hangForever: true);
        using (server)
        {
            var probe = new AuthplaneClient.LifetimeProbe();
            AuthplaneClient.Probe.Value = probe;
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            try
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    AuthplaneClient.CreateAsync(issuer, FetchSettings.FromDevMode(true), cts.Token));
            }
            finally
            {
                AuthplaneClient.Probe.Value = null;
            }

            Assert.Equal(1, probe.Constructed);
            Assert.Equal(0, probe.Live);
        }
    }

    /// <summary>
    /// The same two arms one frame up, through <see cref="AuthplaneResource.CreateAsync"/>,
    /// which builds its client by calling <see cref="AuthplaneClient.CreateAsync"/> and so
    /// never reaches the try/catch that guards its own constructor.
    /// </summary>
    [Fact]
    public async Task ResourceCreateAsync_MetadataFetchFails_ReleasesTheClient()
    {
        var (issuer, server) = StartListener();
        using (server)
        {
            var probe = new AuthplaneClient.LifetimeProbe();
            AuthplaneClient.Probe.Value = probe;
            try
            {
                await Assert.ThrowsAnyAsync<AuthplaneException>(() =>
                    AuthplaneResource.CreateAsync(
                        issuer: issuer,
                        resource: "https://api.example.com/mcp",
                        scopes: new[] { "read" },
                        fetchSettings: FetchSettings.FromDevMode(true)));
            }
            finally
            {
                AuthplaneClient.Probe.Value = null;
            }

            Assert.Equal(1, probe.Constructed);
            Assert.Equal(0, probe.Live);
        }
    }

    [Fact]
    public async Task ResourceCreateAsync_Cancelled_ReleasesTheClient()
    {
        var (issuer, server) = StartListener(hangForever: true);
        using (server)
        {
            var probe = new AuthplaneClient.LifetimeProbe();
            AuthplaneClient.Probe.Value = probe;
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            try
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    AuthplaneResource.CreateAsync(
                        issuer: issuer,
                        resource: "https://api.example.com/mcp",
                        scopes: new[] { "read" },
                        fetchSettings: FetchSettings.FromDevMode(true),
                        cancellationToken: cts.Token));
            }
            finally
            {
                AuthplaneClient.Probe.Value = null;
            }

            Assert.Equal(1, probe.Constructed);
            Assert.Equal(0, probe.Live);
        }
    }
}
