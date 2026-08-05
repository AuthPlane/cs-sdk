using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Locks the atomic contract on <see cref="InMemoryDPoPReplayStore.CheckAndStore"/>
/// — under N concurrent calls with the same jti, exactly one caller must observe
/// first-seen (false) and N-1 must observe replay (true). A two-call
/// <c>Seen + Remember</c> sequence can't guarantee this; the single-lock impl in
/// commit 81c2fc0 can.
/// </summary>
public sealed class DPoPReplayStoreConcurrencyTests
{
    [Fact]
    public void CheckAndStore_ParallelSameJti_ExactlyOneFirstSeen()
    {
        var store = new InMemoryDPoPReplayStore();
        var jti = Guid.NewGuid().ToString("n");
        var expiresAtSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300;

        const int callers = 64;
        var firstSeenCount = 0;
        var replayCount = 0;

        Parallel.For(0, callers, _ =>
        {
            var isReplay = store.CheckAndStore(jti, expiresAtSeconds);
            if (isReplay)
            {
                Interlocked.Increment(ref replayCount);
            }
            else
            {
                Interlocked.Increment(ref firstSeenCount);
            }
        });

        Assert.Equal(1, firstSeenCount);
        Assert.Equal(callers - 1, replayCount);
    }

    [Fact]
    public void CheckAndStore_DistinctJtisInParallel_AllFirstSeen()
    {
        // Sanity: distinct jtis must not collide on lock-internal state.
        var store = new InMemoryDPoPReplayStore();
        var expiresAtSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300;

        const int callers = 64;
        var firstSeenCount = 0;

        Parallel.For(0, callers, i =>
        {
            var jti = $"jti-{i}";
            var isReplay = store.CheckAndStore(jti, expiresAtSeconds);
            if (!isReplay)
            {
                Interlocked.Increment(ref firstSeenCount);
            }
        });

        Assert.Equal(callers, firstSeenCount);
    }
}
