using System.Net;
using System.Text;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers the new TokenCache opt-out / invalidate / clear surface plus the
/// ASCredentials ctor overloads on <see cref="AuthplaneAuthClient"/>.
/// </summary>
public sealed class AuthplaneAuthClient_CacheControlTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly Task _loop;
    private readonly CancellationTokenSource _cts;
    private int _requestCount;
    public string IssuerUrl { get; }

    public AuthplaneAuthClient_CacheControlTests()
    {
        (IssuerUrl, _listener) = LoopbackHttpListener.Start();
        _cts = new CancellationTokenSource();

        _loop = Task.Run(async () =>
        {
            while (_listener.IsListening && !_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync().WaitAsync(_cts.Token); }
                catch { return; }

                Interlocked.Increment(ref _requestCount);

                var body = "{\"access_token\":\"tok-" + _requestCount + "\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
                var bytes = Encoding.UTF8.GetBytes(body);
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                try
                {
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                    ctx.Response.OutputStream.Close();
                }
                catch { /* ignore */ }
            }
        });
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* ignore */ }
        try { _loop.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
        _cts.Dispose();
    }

    [Fact]
    public async Task ClientCredentials_DefaultUseCache_HitsAsOnce()
    {
        await using var client = new AuthplaneAuthClient(
            issuerUrl: IssuerUrl,
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        var t1 = await client.ClientCredentialsAsync("tools/add", "res");
        var t2 = await client.ClientCredentialsAsync("tools/add", "res");

        Assert.Equal(t1.AccessToken, t2.AccessToken);
        Assert.Equal(1, _requestCount);
    }

    [Fact]
    public async Task ClientCredentials_UseCacheFalse_BypassesCache_OnBothCalls()
    {
        await using var client = new AuthplaneAuthClient(
            issuerUrl: IssuerUrl,
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        var t1 = await client.ClientCredentialsAsync("tools/add", "res", useCache: false);
        var t2 = await client.ClientCredentialsAsync("tools/add", "res", useCache: false);

        Assert.NotEqual(t1.AccessToken, t2.AccessToken);
        Assert.Equal(2, _requestCount);
    }

    [Fact]
    public async Task ClientCredentials_InvalidateCache_ForcesRefresh()
    {
        await using var client = new AuthplaneAuthClient(
            issuerUrl: IssuerUrl,
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.ClientCredentialsAsync("tools/add", "res");
        client.InvalidateClientCredentialsCache("tools/add", "res");
        await client.ClientCredentialsAsync("tools/add", "res");

        Assert.Equal(2, _requestCount);
    }

    [Fact]
    public async Task ClientCredentials_Clear_DropsAllEntries()
    {
        await using var client = new AuthplaneAuthClient(
            issuerUrl: IssuerUrl,
            clientId: "client",
            clientSecret: "secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.ClientCredentialsAsync("a", "r1");
        await client.ClientCredentialsAsync("b", "r2");
        Assert.Equal(2, _requestCount);

        client.ClearClientCredentialsCache();

        await client.ClientCredentialsAsync("a", "r1");
        await client.ClientCredentialsAsync("b", "r2");
        Assert.Equal(4, _requestCount);
    }

    [Fact]
    public void Ctor_FromASCredentials_BuildsHttpBasicEquivalent()
    {
        // Equivalent to the (issuerUrl, clientId, clientSecret) ctor; happy
        // path is just "doesn't throw and the auth client constructs cleanly".
        var creds = new ASCredentials("client", "secret");
        var c = new AuthplaneAuthClient(
            issuerUrl: IssuerUrl,
            asCredentials: creds,
            fetchSettings: FetchSettings.FromDevMode(true));
        Assert.NotNull(c);
    }

    [Fact]
    public void Ctor_FromASCredentialsWithDPoPProvider_Composes()
    {
        var creds = new ASCredentials("client", "secret");
        var dpop = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        var c = new AuthplaneAuthClient(
            issuerUrl: IssuerUrl,
            asCredentials: creds,
            dpopProvider: dpop,
            fetchSettings: FetchSettings.FromDevMode(true));
        Assert.NotNull(c);
    }

    [Fact]
    public void Ctor_FromNullASCredentials_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: IssuerUrl,
                asCredentials: null!,
                fetchSettings: FetchSettings.FromDevMode(true)));
    }

}
