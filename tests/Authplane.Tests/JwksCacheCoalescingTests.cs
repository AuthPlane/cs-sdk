using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Locks the per-key re-check inside the gate that 082201f added to
/// <see cref="JwksCache"/>: N concurrent cold callers all acquire the gate
/// sequentially, and without the re-check each would serialize through its own
/// fetch. With the re-check, only the first caller fetches; the rest see a
/// populated cache and skip out. A regression that drops the re-check would
/// make the underlying fetcher run N times.
///
/// Same contract applies to <c>MetadataCache</c>, but that type is internal —
/// JwksCache (public) exercises the identical pattern.
/// </summary>
public sealed class JwksCacheCoalescingTests
{
    [Fact]
    public async Task GetAsync_ConcurrentColdCallers_FetchesOnce()
    {
        var fetchCount = 0;
        var gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        Task<JwksFetchResult> Fetch(CancellationToken ct)
        {
            Interlocked.Increment(ref fetchCount);
            return gate.Task.ContinueWith(
                _ => new JwksFetchResult(new JsonWebKeySet()),
                TaskScheduler.Default);
        }

        await using var cache = new JwksCache(
            fetcher: Fetch,
            refreshInterval: TimeSpan.FromMinutes(5));

        const int callers = 16;
        var tasks = new Task<JsonWebKeySet>[callers];
        for (var i = 0; i < callers; i++)
        {
            tasks[i] = cache.GetAsync(CancellationToken.None);
        }

        // Let the cold fetch resolve. All N callers should observe the same result.
        gate.SetResult(true);
        await Task.WhenAll(tasks);

        Assert.Equal(1, fetchCount);
    }

    /// <summary>
    /// L-12 regression: when GetAsync's caller had a cancelled CT and age was
    /// past the 80% background-refresh threshold, the previous code passed the
    /// caller's CT to <c>Task.Run</c>. Task.Run sees the cancelled token at
    /// schedule time and creates a Task already in Canceled state — the body
    /// never runs, the <c>finally{}</c> never clears <c>_backgroundRefresh</c>,
    /// and the sentinel Task stays pinned forever. From that point on,
    /// <c>Volatile.Read(ref _backgroundRefresh) is null</c> always returns
    /// false and the cache never refreshes in background again. The fix is to
    /// pass <c>CancellationToken.None</c> to Task.Run; the body already uses
    /// None internally for EnsureFetchedAsync, which is the design intent.
    /// </summary>
    [Fact]
    public async Task GetAsync_CallerCancelsAtBackgroundRefreshSchedule_DoesNotPinBackgroundRefresh()
    {
        var fetchCount = 0;
        var secondFetch = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        Task<JwksFetchResult> Fetch(CancellationToken ct)
        {
            var n = Interlocked.Increment(ref fetchCount);
            if (n >= 2)
            {
                secondFetch.TrySetResult(true);
            }

            return Task.FromResult(new JwksFetchResult(new JsonWebKeySet()));
        }

        await using var cache = new JwksCache(
            fetcher: Fetch,
            refreshInterval: TimeSpan.FromMilliseconds(100));

        // 1. Cold fetch — populates the cache.
        _ = await cache.GetAsync(CancellationToken.None);
        Assert.Equal(1, fetchCount);

        // 2. Push age past 80% of the refresh interval so the next GetAsync
        //    takes the background-refresh branch.
        await Task.Delay(TimeSpan.FromMilliseconds(120));

        // 3. Caller arrives with an already-cancelled CT. The cached value is
        //    still returned (no exception thrown by GetAsync). With the bug
        //    the background body never runs.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        _ = await cache.GetAsync(cts.Token);

        // 4. With the fix, the body runs with CancellationToken.None and
        //    fetcher #2 fires. Without the fix this awaits the timeout.
        var completed = await Task.WhenAny(
            secondFetch.Task,
            Task.Delay(TimeSpan.FromSeconds(3)));
        Assert.Same(secondFetch.Task, completed);
    }
}
