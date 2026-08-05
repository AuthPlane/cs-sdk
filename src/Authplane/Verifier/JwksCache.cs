using Microsoft.IdentityModel.Tokens;

namespace Authplane;

/// <summary>
/// JWKS cache with:
///   - lock-coordinated fetches (no stampede on cold cache)
///   - background refresh at 80% of effective TTL
///   - effective TTL = min(configured refreshInterval, server Cache-Control/Expires)
///   - stale-cache fallback when a refresh fetch fails (capped at maxStaleAge)
///   - force-refresh on a missing <c>kid</c>
///   - error callback for observability
/// </summary>
public sealed class JwksCache : IAsyncDisposable
{
    private readonly Func<CancellationToken, Task<JwksFetchResult>> _fetcher;
    private readonly TimeSpan _defaultRefreshInterval;
    private readonly TimeSpan _maxStaleAge;
    private readonly Action<Exception>? _onRefreshError;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private JsonWebKeySet? _cached;
    private DateTimeOffset _cachedAt;
    private TimeSpan _effectiveRefreshInterval;
    private Task? _backgroundRefresh;

    /// <summary>
    /// Overload accepting a simple fetcher (no server TTL). For backward compatibility.
    /// </summary>
    public JwksCache(
        Func<CancellationToken, Task<JsonWebKeySet>> fetcher,
        TimeSpan refreshInterval,
        TimeSpan? maxStaleAge = null,
        Action<Exception>? onRefreshError = null)
        : this(
            async ct => new JwksFetchResult(await fetcher(ct).ConfigureAwait(false)),
            refreshInterval, maxStaleAge, onRefreshError)
    {
    }

    public JwksCache(
        Func<CancellationToken, Task<JwksFetchResult>> fetcher,
        TimeSpan refreshInterval,
        TimeSpan? maxStaleAge = null,
        Action<Exception>? onRefreshError = null)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _defaultRefreshInterval = refreshInterval > TimeSpan.Zero
            ? refreshInterval
            : TimeSpan.FromMinutes(5);
        _effectiveRefreshInterval = _defaultRefreshInterval;
        _maxStaleAge = maxStaleAge ?? TimeSpan.FromHours(24);
        _onRefreshError = onRefreshError;
    }

    public async Task<JsonWebKeySet> GetAsync(CancellationToken cancellationToken = default)
    {
        if (_cached is null)
        {
            await EnsureFetchedAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var age = DateTimeOffset.UtcNow - _cachedAt;

            if (age > _maxStaleAge)
            {
                await EnsureFetchedAsync(cancellationToken).ConfigureAwait(false);
            }
            else if (age > _effectiveRefreshInterval * 0.8 && Volatile.Read(ref _backgroundRefresh) is null)
            {
                var sentinel = new TaskCompletionSource<bool>();
                if (Interlocked.CompareExchange(ref _backgroundRefresh, sentinel.Task, null) is null)
                {
#pragma warning disable CS4014
                    // Task.Run uses CancellationToken.None so a caller's
                    // cancelled token at schedule-time doesn't put the task in
                    // Canceled state — that would skip the finally{} and leave
                    // _backgroundRefresh pinned to sentinel.Task forever,
                    // disabling all future background refreshes for the
                    // lifetime of the cache. The body itself already uses
                    // CancellationToken.None for EnsureFetchedAsync.
                    Task.Run(async () =>
                    {
                        try { await EnsureFetchedAsync(CancellationToken.None).ConfigureAwait(false); }
                        catch (Exception ex)
                        {
                            try { _onRefreshError?.Invoke(ex); } catch { }
                        }
                        finally
                        {
                            Interlocked.Exchange(ref _backgroundRefresh, null);
                            sentinel.TrySetResult(true);
                        }
                    }, CancellationToken.None);
#pragma warning restore CS4014
                }
            }
        }

        return _cached!;
    }

    public Task ForceRefreshAsync(CancellationToken cancellationToken = default)
        => EnsureFetchedAsync(cancellationToken, forceFresh: true);

    private async Task EnsureFetchedAsync(CancellationToken cancellationToken, bool forceFresh = false)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Stampede coalescing — re-check inside the gate so concurrent
            // cold callers don't each fetch sequentially. Skip the short-circuit
            // for explicit ForceRefreshAsync calls (used on kid-miss).
            if (!forceFresh && _cached is not null &&
                (DateTimeOffset.UtcNow - _cachedAt) <= _effectiveRefreshInterval)
            {
                return;
            }

            try
            {
                var result = await _fetcher(cancellationToken).ConfigureAwait(false);
                _cached = result.KeySet;
                _cachedAt = DateTimeOffset.UtcNow;

                // Effective TTL = min(configured default, server hint).
                // Zero means RFC 7234 no-store / no-cache / already-past Expires:
                // force re-fetch on the next read so the cache becomes a pass-through.
                if (result.ServerTtl is { } serverTtl)
                {
                    if (serverTtl == TimeSpan.Zero)
                    {
                        _effectiveRefreshInterval = TimeSpan.Zero;
                        _cachedAt = DateTimeOffset.MinValue;
                    }
                    else
                    {
                        _effectiveRefreshInterval = serverTtl < _defaultRefreshInterval
                            ? serverTtl
                            : _defaultRefreshInterval;
                    }
                }
                else
                {
                    _effectiveRefreshInterval = _defaultRefreshInterval;
                }
            }
            catch (Exception ex)
            {
                if (_cached is null || (DateTimeOffset.UtcNow - _cachedAt) > _maxStaleAge)
                {
                    throw;
                }
                try { _onRefreshError?.Invoke(ex); } catch { }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Bound how long DisposeAsync waits for the in-flight refresh.
        // The background fetch uses CancellationToken.None internally (so its
        // HTTP request continues to completion), but we shouldn't block the
        // app shutdown indefinitely waiting for its HTTP timeout — 2s is
        // enough for an already-in-flight call to finish in the happy case
        // and short enough that an unresponsive AS doesn't pin shutdown.
        if (_backgroundRefresh is not null)
        {
            try
            {
                await _backgroundRefresh.WaitAsync(System.TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch { /* timeout or background failure — drop at shutdown */ }
        }
        _gate.Dispose();
    }

    public JsonWebKey? FindByKid(string kid)
    {
        if (_cached is null || string.IsNullOrEmpty(kid))
        {
            return null;
        }

        foreach (var k in _cached.Keys)
        {
            if (string.Equals(k.Kid, kid, StringComparison.Ordinal))
            {
                return k;
            }
        }
        return null;
    }
}
