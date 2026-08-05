using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers <see cref="TokenCache"/> directly: deterministic key shape, sort order,
/// collision protection (the H1 bug), TTL accounting, remaining-lifetime semantics
/// on hits, invalidate, clear.
/// </summary>
public sealed class TokenCacheTests
{
    // -------------------- BuildKey --------------------

    [Fact]
    public void BuildKey_DistinctScopesAndResources_DoNotCollide()
    {
        // H1: pre-fix, ("a b","c") and ("a bc","") collided because there
        // was no delimiter between scope and resource.
        Assert.NotEqual(TokenCache.BuildKey("a b", "c"), TokenCache.BuildKey("a bc", ""));
    }

    [Fact]
    public void BuildKey_ScopeTokenOrder_IsCanonical()
    {
        // Sort: "a b" and "b a" describe the same OAuth scope set.
        Assert.Equal(TokenCache.BuildKey("a b", "r"), TokenCache.BuildKey("b a", "r"));
    }

    [Fact]
    public void BuildKey_EmptyInputs_FallBackToSentinel()
    {
        Assert.Equal("_default", TokenCache.BuildKey(null, null));
        Assert.Equal("_default", TokenCache.BuildKey("", "  "));
    }

    [Fact]
    public void BuildKey_OnlyResource_PrefixesWithPipe()
    {
        Assert.Equal("|https://api.example.com", TokenCache.BuildKey(null, "https://api.example.com"));
    }

    [Fact]
    public void BuildKey_ScopeAndResource_JoinedWithPipe()
    {
        Assert.Equal("a b|https://api.example.com",
            TokenCache.BuildKey("a b", "https://api.example.com"));
    }

    [Fact]
    public void BuildKey_EmptyClientId_PreservesLegacyKey()
    {
        // Null / empty principal is back-compat: callers with a per-client
        // cache (the common case today) get the same key bytes as before
        // the principal was added.
        Assert.Equal(TokenCache.BuildKey("a b", "r"),
            TokenCache.BuildKey("a b", "r", clientId: null));
        Assert.Equal(TokenCache.BuildKey("a b", "r"),
            TokenCache.BuildKey("a b", "r", clientId: ""));
    }

    [Fact]
    public void BuildKey_ClientId_PrefixesWithBangSeparator()
    {
        // The principal sits before the legacy key, separated by `!` so it
        // can't be confused with the `|` that splits scope from resource.
        Assert.Equal("alice!a b|r",
            TokenCache.BuildKey("a b", "r", clientId: "alice"));
        Assert.Equal("alice!_default",
            TokenCache.BuildKey(null, null, clientId: "alice"));
    }

    [Fact]
    public void BuildKey_DistinctPrincipals_DoNotCollide()
    {
        // Two distinct confidential clients sharing one TokenCache must
        // never hit the same key, even for identical (scope, resource)
        // tuples.
        Assert.NotEqual(
            TokenCache.BuildKey("read", "https://api.example.com", clientId: "alice"),
            TokenCache.BuildKey("read", "https://api.example.com", clientId: "bob"));
    }

    // -------------------- GetOrFetchAsync --------------------

    [Fact]
    public async Task GetOrFetchAsync_NewKey_CallsFactoryOnceAndCaches()
    {
        var cache = new TokenCache();
        var calls = 0;

        async Task<TokenResponse> Factory(CancellationToken _)
        {
            calls++;
            await Task.Yield();
            return new TokenResponse("tok", "Bearer", expiresIn: 3600, scope: "tools/add");
        }

        var r1 = await cache.GetOrFetchAsync("tools/add", "res", Factory);
        var r2 = await cache.GetOrFetchAsync("tools/add", "res", Factory);

        Assert.Equal(1, calls);
        Assert.Equal("tok", r1.AccessToken);
        Assert.Equal("tok", r2.AccessToken);
    }

    [Fact]
    public async Task GetOrFetchAsync_HitReportsRemainingLifetime()
    {
        var cache = new TokenCache(ttlBuffer: TimeSpan.FromSeconds(1));
        var fresh = new TokenResponse("tok", "Bearer", expiresIn: 3600, scope: null);

        // First call seeds the cache.
        await cache.GetOrFetchAsync("s", "r", _ => Task.FromResult(fresh));

        // Wait briefly so the remaining lifetime is materially less than the
        // original 3600.
        await Task.Delay(TimeSpan.FromMilliseconds(50));

        var hit = await cache.GetOrFetchAsync("s", "r",
            _ => throw new InvalidOperationException("factory must not be called on hit"));

        Assert.NotNull(hit.ExpiresIn);
        Assert.True(hit.ExpiresIn < 3600,
            $"cache hit's ExpiresIn ({hit.ExpiresIn}) must be the remaining lifetime, not the original AS-issued value");
    }

    [Fact]
    public async Task GetOrFetchAsync_ResponseWithoutExpiresIn_FallsBackToDefaultTtl()
    {
        // L-12: when the AS omits expires_in (some implementations do for
        // never-expiring tokens) we used to cache nothing and pay a round-trip
        // per call. Now: fall back to the configured defaultTtl.
        var cache = new TokenCache(defaultTtl: TimeSpan.FromMinutes(5));
        var calls = 0;

        Task<TokenResponse> Factory(CancellationToken _)
        {
            calls++;
            return Task.FromResult(new TokenResponse("tok", "Bearer", expiresIn: null, scope: null));
        }

        await cache.GetOrFetchAsync("s", "r", Factory);
        await cache.GetOrFetchAsync("s", "r", Factory);

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task GetOrFetchAsync_ExpiredEntry_IsEvictedOnMiss()
    {
        // L-12: workloads that cycle through many distinct (scope, resource)
        // tuples used to grow the cache without bound — entries expired but
        // were never removed. Now: a miss against an expired entry evicts it.
        var cache = new TokenCache(
            ttlBuffer: TimeSpan.FromSeconds(0),
            defaultTtl: TimeSpan.FromMilliseconds(50));

        var calls = 0;
        Task<TokenResponse> Factory(CancellationToken _)
        {
            calls++;
            return Task.FromResult(new TokenResponse("tok-" + calls, "Bearer", expiresIn: null, scope: null));
        }

        await cache.GetOrFetchAsync("s", "r", Factory);
        await Task.Delay(TimeSpan.FromMilliseconds(150));
        var r2 = await cache.GetOrFetchAsync("s", "r", Factory);

        Assert.Equal(2, calls);
        Assert.Equal("tok-2", r2.AccessToken);
    }

    [Fact]
    public async Task Invalidate_DropsEntry()
    {
        var cache = new TokenCache();
        var calls = 0;
        Task<TokenResponse> Factory(CancellationToken _)
        {
            calls++;
            return Task.FromResult(new TokenResponse("tok", "Bearer", expiresIn: 3600, scope: null));
        }

        await cache.GetOrFetchAsync("s", "r", Factory);
        cache.Invalidate("s", "r");
        await cache.GetOrFetchAsync("s", "r", Factory);

        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetOrFetchAsync_DistinctPrincipals_DoNotShareEntries()
    {
        // End-to-end peer of BuildKey_DistinctPrincipals_DoNotCollide:
        // pins that clientId actually threads through GetOrFetchAsync's
        // read+write path, not just BuildKey's pure projection. Two
        // principals sharing one cache with the same (scope, resource)
        // must each pay one fetch — a bug that drops clientId on either
        // side would silently collapse them onto one entry.
        var cache = new TokenCache();
        var calls = 0;

        Task<TokenResponse> Factory(CancellationToken _)
        {
            calls++;
            return Task.FromResult(new TokenResponse("tok-" + calls, "Bearer", expiresIn: 3600, scope: null));
        }

        var alice1 = await cache.GetOrFetchAsync("read", "https://api.example.com", Factory, clientId: "alice");
        var bob1 = await cache.GetOrFetchAsync("read", "https://api.example.com", Factory, clientId: "bob");

        Assert.Equal(2, calls);
        Assert.NotEqual(alice1.AccessToken, bob1.AccessToken);

        // Second pair of reads must both hit the cache — neither principal
        // re-invokes the factory.
        var alice2 = await cache.GetOrFetchAsync("read", "https://api.example.com", Factory, clientId: "alice");
        var bob2 = await cache.GetOrFetchAsync("read", "https://api.example.com", Factory, clientId: "bob");

        Assert.Equal(2, calls);
        Assert.Equal(alice1.AccessToken, alice2.AccessToken);
        Assert.Equal(bob1.AccessToken, bob2.AccessToken);
    }

    [Fact]
    public async Task Invalidate_OnlyDropsMatchingPrincipal()
    {
        // Invalidate(scope, resource, clientId: alice) must not affect bob's
        // entry — drop on either side of the principal key would let one
        // principal's logout/rotation flush another's cached token.
        var cache = new TokenCache();
        var calls = 0;

        Task<TokenResponse> Factory(CancellationToken _)
        {
            calls++;
            return Task.FromResult(new TokenResponse("tok-" + calls, "Bearer", expiresIn: 3600, scope: null));
        }

        await cache.GetOrFetchAsync("s", "r", Factory, clientId: "alice");
        await cache.GetOrFetchAsync("s", "r", Factory, clientId: "bob");
        Assert.Equal(2, calls);

        cache.Invalidate("s", "r", clientId: "alice");

        // Alice misses (factory invoked again).
        await cache.GetOrFetchAsync("s", "r", Factory, clientId: "alice");
        Assert.Equal(3, calls);

        // Bob still hits (factory not invoked).
        await cache.GetOrFetchAsync("s", "r", Factory, clientId: "bob");
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task Clear_DropsEveryEntry()
    {
        var cache = new TokenCache();
        await cache.GetOrFetchAsync("a", "r1",
            _ => Task.FromResult(new TokenResponse("t1", "Bearer", 3600, null)));
        await cache.GetOrFetchAsync("b", "r2",
            _ => Task.FromResult(new TokenResponse("t2", "Bearer", 3600, null)));

        cache.Clear();

        var calls = 0;
        Task<TokenResponse> Factory(CancellationToken _)
        {
            calls++;
            return Task.FromResult(new TokenResponse("t", "Bearer", 3600, null));
        }

        await cache.GetOrFetchAsync("a", "r1", Factory);
        await cache.GetOrFetchAsync("b", "r2", Factory);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetOrFetchAsync_NullFactory_Throws()
    {
        var cache = new TokenCache();
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => cache.GetOrFetchAsync("s", "r", factory: null!));
    }
}
