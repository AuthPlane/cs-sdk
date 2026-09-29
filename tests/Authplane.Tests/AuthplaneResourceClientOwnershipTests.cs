using System.Net;
using System.Text;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// <see cref="AuthplaneResource.CreateAsync"/> builds the <see cref="AuthplaneClient"/> it
/// hands to the resource, so it owns that client until the constructor returns and
/// ownership transfers. These tests pin that every rejecting exit from the constructor
/// still releases it: an abandoned client keeps an <see cref="HttpClient"/> and the JWKS
/// refresh state alive with nothing able to reach them, and a caller that retries a
/// misconfiguration in a loop accumulates one set per attempt.
/// </summary>
public sealed class AuthplaneResourceClientOwnershipTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly Task _serverLoop;

    public AuthplaneResourceClientOwnershipTests()
    {
        (_issuer, _listener) = LoopbackHttpListener.Start();

        _serverLoop = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch
                {
                    return;
                }

                try
                {
                    var path = ctx.Request.Url?.AbsolutePath ?? "";
                    var body = path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal)
                            || path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal)
                        ? $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}"
                        : "{\"keys\":[]}";

                    var bytes = Encoding.UTF8.GetBytes(body);
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                }
                catch
                {
                    // Client went away mid-response; the assertion under test does not care.
                }
                finally
                {
                    ctx.Response.Close();
                }
            }
        });
    }

    /// <summary>
    /// The metadata fetch has to succeed for the client to exist at all, which is what makes
    /// these the leaking paths: the constructor runs only after a client has been built.
    /// </summary>
    private async Task<AuthplaneClient.LifetimeProbe> AssertClientReleasedAsync<TException>(
        Func<Task> createAsync)
        where TException : Exception
    {
        var probe = new AuthplaneClient.LifetimeProbe();
        AuthplaneClient.Probe.Value = probe;
        try
        {
            await Assert.ThrowsAsync<TException>(createAsync);
        }
        finally
        {
            AuthplaneClient.Probe.Value = null;
        }

        // The probe is only meaningful if the run actually got past the metadata fetch and
        // built a client. Without this the whole assertion passes vacuously.
        Assert.Equal(1, probe.Constructed);
        Assert.Equal(0, probe.Live);
        return probe;
    }

    [Fact]
    public async Task NegativeClockSkew_ReleasesTheClientItBuilt()
    {
        await AssertClientReleasedAsync<ArgumentOutOfRangeException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com/mcp",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true),
                clockSkewSeconds: -1));
    }

    [Fact]
    public async Task EmptyAllowedAlgorithms_ReleasesTheClientItBuilt()
    {
        await AssertClientReleasedAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com/mcp",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true),
                allowedAlgorithms: Array.Empty<string>()));
    }

    [Fact]
    public async Task UnsupportedAllowedAlgorithm_ReleasesTheClientItBuilt()
    {
        await AssertClientReleasedAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com/mcp",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true),
                allowedAlgorithms: new[] { "HS256" }));
    }

    /// <summary>
    /// A caller retrying a misconfiguration must not accumulate clients — the failure mode
    /// that makes the single-instance leak matter in a hosted process.
    /// </summary>
    [Fact]
    public async Task RepeatedRejection_AccumulatesNoClients()
    {
        var probe = new AuthplaneClient.LifetimeProbe();
        AuthplaneClient.Probe.Value = probe;
        try
        {
            for (var i = 0; i < 5; i++)
            {
                await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
                    AuthplaneResource.CreateAsync(
                        issuer: _issuer,
                        resource: "https://api.example.com/mcp",
                        scopes: new[] { "read" },
                        fetchSettings: FetchSettings.FromDevMode(true),
                        clockSkewSeconds: -1));
            }
        }
        finally
        {
            AuthplaneClient.Probe.Value = null;
        }

        Assert.Equal(5, probe.Constructed);
        Assert.Equal(0, probe.Live);
    }

    /// <summary>
    /// The happy path must not release the client: the resource is constructed with
    /// <c>ownsClient: true</c> and releases it from its own DisposeAsync.
    /// </summary>
    [Fact]
    public async Task SuccessfulCreate_TransfersOwnershipAndDisposesOnce()
    {
        var probe = new AuthplaneClient.LifetimeProbe();
        AuthplaneClient.Probe.Value = probe;
        try
        {
            var resource = await AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com/mcp",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true));

            Assert.Equal(1, probe.Constructed);
            Assert.Equal(1, probe.Live);

            await resource.DisposeAsync();
            Assert.Equal(0, probe.Live);

            // Disposing the resource twice must not double-release the client underneath.
            await resource.DisposeAsync();
            Assert.Equal(1, probe.Disposed);
        }
        finally
        {
            AuthplaneClient.Probe.Value = null;
        }
    }

    /// <summary>
    /// A client the caller owns is never released by the resource, whether the identifier is
    /// accepted or rejected — only the overload that builds its own client disposes it.
    /// </summary>
    [Fact]
    public async Task CallerOwnedClient_IsNotReleasedByARejectedResource()
    {
        var probe = new AuthplaneClient.LifetimeProbe();
        AuthplaneClient.Probe.Value = probe;
        try
        {
            await using var client = await AuthplaneClient.CreateAsync(
                _issuer, FetchSettings.FromDevMode(true));

            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
                client.CreateResourceAsync(
                    resource: "https://api.example.com/mcp",
                    scopes: new[] { "read" },
                    clockSkewSeconds: -1));

            Assert.Equal(1, probe.Constructed);
            Assert.Equal(1, probe.Live);
        }
        finally
        {
            AuthplaneClient.Probe.Value = null;
        }
    }

    public void Dispose()
    {
        _listener.Stop();
        _listener.Close();
        try
        {
            _serverLoop.Wait(TimeSpan.FromSeconds(5));
        }
        catch
        {
            // Server loop exits via the exception path when the listener closes.
        }
    }
}
