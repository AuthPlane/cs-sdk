using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Mirror of <see cref="JwksCacheCoalescingTests"/> for the internal
/// <see cref="MetadataCache"/>. Both caches share the per-key re-check inside
/// the gate that 082201f introduced — without it, N concurrent cold callers
/// would serialize through N separate fetches.
///
/// JwksCache is public and already covered by a coalescing test;
/// MetadataCache is internal, exposed to this test assembly via
/// <c>InternalsVisibleTo("Authplane.Tests")</c>. Without this mirror, a
/// regression that drops the re-check in <c>MetadataCache.EnsureFetchedAsync</c>
/// alone wouldn't be caught.
/// </summary>
public sealed class MetadataCacheCoalescingTests
{
    [Fact]
    public async Task GetAsync_ConcurrentColdCallers_FetchesOnce()
    {
        var fetchCount = 0;
        var gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        Task<MetadataFetchResult> Fetch(CancellationToken ct)
        {
            Interlocked.Increment(ref fetchCount);
            return gate.Task.ContinueWith(
                _ => new MetadataFetchResult(
                    new MetadataDocument(
                        Issuer: "https://issuer.example.com",
                        JwksUri: "https://issuer.example.com/.well-known/jwks.json")),
                TaskScheduler.Default);
        }

        await using var cache = new MetadataCache(
            fetcher: Fetch,
            refreshInterval: TimeSpan.FromMinutes(5));

        const int callers = 16;
        var tasks = new Task<MetadataDocument>[callers];
        for (var i = 0; i < callers; i++)
        {
            tasks[i] = cache.GetAsync(CancellationToken.None);
        }

        gate.SetResult(true);
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, fetchCount);
        foreach (var doc in results)
        {
            Assert.Equal("https://issuer.example.com", doc.Issuer);
        }
    }

    /// <summary>
    /// L-12 regression: see <see cref="JwksCacheCoalescingTests"/> for the full
    /// rationale. Both caches share the same Task.Run pattern in the
    /// background-refresh branch; a cancelled caller CT at schedule time used
    /// to pin <c>_backgroundRefresh</c> forever. The fix passes
    /// <c>CancellationToken.None</c> to Task.Run on both caches; this mirror
    /// test covers MetadataCache directly.
    /// </summary>
    [Fact]
    public async Task GetAsync_CallerCancelsAtBackgroundRefreshSchedule_DoesNotPinBackgroundRefresh()
    {
        var fetchCount = 0;
        var secondFetch = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        Task<MetadataFetchResult> Fetch(CancellationToken ct)
        {
            var n = Interlocked.Increment(ref fetchCount);
            if (n >= 2)
            {
                secondFetch.TrySetResult(true);
            }

            return Task.FromResult(new MetadataFetchResult(
                new MetadataDocument(
                    Issuer: "https://issuer.example.com",
                    JwksUri: "https://issuer.example.com/.well-known/jwks.json")));
        }

        await using var cache = new MetadataCache(
            fetcher: Fetch,
            refreshInterval: TimeSpan.FromMilliseconds(100));

        _ = await cache.GetAsync(CancellationToken.None);
        Assert.Equal(1, fetchCount);

        await Task.Delay(TimeSpan.FromMilliseconds(120));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        _ = await cache.GetAsync(cts.Token);

        var completed = await Task.WhenAny(
            secondFetch.Task,
            Task.Delay(TimeSpan.FromSeconds(3)));
        Assert.Same(secondFetch.Task, completed);
    }
}
