namespace Authplane;

/// <summary>
/// AS-metadata cache with stale-fallback and conditional refresh. Mirrors the
/// shape of <see cref="JwksCache"/>: lock-coordinated fetches (no stampede on
/// cold cache), background refresh at 80% of effective TTL, effective TTL =
/// <c>min(configured refreshInterval, server Cache-Control/Expires)</c>,
/// stale-fallback when a refresh fetch fails (capped at <c>maxStaleAge</c>),
/// optional error callback for observability.
/// </summary>
internal sealed class MetadataCache : IAsyncDisposable
{
    private readonly Func<CancellationToken, Task<MetadataFetchResult>> _fetcher;
    private readonly TimeSpan _defaultRefreshInterval;
    private readonly TimeSpan _maxStaleAge;
    private readonly Action<Exception>? _onRefreshError;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private MetadataDocument? _cached;
    private DateTimeOffset _cachedAt;
    private TimeSpan _effectiveRefreshInterval;
    private Task? _backgroundRefresh;

    public MetadataCache(
        Func<CancellationToken, Task<MetadataFetchResult>> fetcher,
        TimeSpan refreshInterval,
        TimeSpan? maxStaleAge = null,
        Action<Exception>? onRefreshError = null)
    {
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _defaultRefreshInterval = refreshInterval > TimeSpan.Zero
            ? refreshInterval
            : TimeSpan.FromHours(1);
        _effectiveRefreshInterval = _defaultRefreshInterval;
        _maxStaleAge = maxStaleAge ?? TimeSpan.FromHours(24);
        _onRefreshError = onRefreshError;
    }

    public async Task<MetadataDocument> GetAsync(CancellationToken cancellationToken = default)
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
                            try { _onRefreshError?.Invoke(ex); } catch { /* observability only */ }
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
            // Stampede coalescing. N concurrent cold callers all acquire
            // the gate sequentially; without this re-check each one would
            // serialize through its own fetch. Re-check inside the lock so
            // only the first caller actually fetches and the rest see a
            // populated cache. Skip the
            // short-circuit for explicit ForceRefreshAsync calls.
            if (!forceFresh && _cached is not null &&
                (DateTimeOffset.UtcNow - _cachedAt) <= _effectiveRefreshInterval)
            {
                return;
            }

            try
            {
                var result = await _fetcher(cancellationToken).ConfigureAwait(false);
                _cached = result.Document;
                _cachedAt = DateTimeOffset.UtcNow;

                if (result.ServerTtl is { } serverTtl)
                {
                    if (serverTtl == TimeSpan.Zero)
                    {
                        // RFC 7234: no-store / no-cache / already-past Expires.
                        // Force the entry to be considered stale on the next read so
                        // the cache acts as a pass-through. The document is still
                        // returned to the caller that triggered this fetch — only
                        // subsequent reads pay the refetch.
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
                try { _onRefreshError?.Invoke(ex); } catch { /* observability only */ }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Bound the wait so an in-flight refresh against an unresponsive AS
        // doesn't pin app shutdown until the HTTP timeout. 2s is enough for
        // an already-in-flight metadata fetch in the happy case.
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
}
