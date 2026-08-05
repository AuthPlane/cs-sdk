using System.Collections.Concurrent;
using System.Diagnostics;

namespace Authplane;

/// <summary>
/// Per-<c>(scope, resource)</c> cache for <c>client_credentials</c> token responses:
/// the same token is reused across
/// concurrent callers within its TTL minus a configurable buffer, so a long-lived
/// application doesn't issue a fresh AS round-trip on every protected request.
///
/// Time is tracked off <see cref="Stopwatch.GetTimestamp"/> (monotonic), not the
/// wall clock — an NTP adjustment can't expire / un-expire entries unexpectedly.
/// </summary>
public sealed class TokenCache
{
    private readonly TimeSpan _ttlBuffer;
    private readonly TimeSpan _defaultTtl;
    private readonly ConcurrentDictionary<string, Entry> _entries = new();

    private sealed record Entry(TokenResponse Response, long ExpiresAtTicks);

    /// <param name="ttlBuffer">
    /// Safety margin subtracted from each token's lifetime before the entry is
    /// considered expired. Defaults to 30s.
    /// </param>
    /// <param name="defaultTtl">
    /// Fallback lifetime applied when the AS response omits <c>expires_in</c>.
    /// Defaults to 1h.
    /// </param>
    public TokenCache(TimeSpan? ttlBuffer = null, TimeSpan? defaultTtl = null)
    {
        _ttlBuffer = ttlBuffer ?? TimeSpan.FromSeconds(30);
        _defaultTtl = defaultTtl ?? TimeSpan.FromHours(1);
    }

    /// <summary>
    /// Return a cached token for <paramref name="scope"/> + <paramref name="resource"/>, or
    /// fetch a fresh one via <paramref name="factory"/> and cache it.
    /// </summary>
    /// <param name="scope">OAuth scope string; whitespace-tokenized and sort-canonicalized for keying.</param>
    /// <param name="resource">RFC 8707 resource indicator (or a joined surrogate for multi-resource calls).</param>
    /// <param name="factory">
    /// Async producer invoked on cache miss to mint a fresh <see cref="TokenResponse"/>.
    /// Receives the caller's <paramref name="cancellationToken"/>; the returned response is
    /// cached for its <c>expires_in</c> lifetime minus the configured TTL buffer.
    /// </param>
    /// <param name="clientId">
    /// Optional principal identifier. Folded into the cache key so a future caller
    /// sharing one <see cref="TokenCache"/> across multiple confidential clients
    /// (different <c>client_id</c>s) cannot serve a token issued to one client in
    /// response to a request from another. Null / empty preserves the original
    /// key shape — callers that own a per-client cache instance don't have to
    /// migrate.
    /// </param>
    /// <param name="cancellationToken">Cancellation forwarded to the factory.</param>
    public async Task<TokenResponse> GetOrFetchAsync(
        string? scope,
        string? resource,
        Func<CancellationToken, Task<TokenResponse>> factory,
        string? clientId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(factory);

        var key = BuildKey(scope, resource, clientId);
        var nowTicks = Stopwatch.GetTimestamp();

        if (_entries.TryGetValue(key, out var hit))
        {
            if (hit.ExpiresAtTicks > nowTicks)
            {
                // The entry is deliberately NOT returned as stored (which would
                // preserve the original `expires_in`). Here
                // we report remaining lifetime instead: a caller that schedules
                // its own refresh off the returned `TokenResponse.ExpiresIn` would
                // otherwise be misled into thinking it has a full freshly-minted
                // lifetime when most of it has already been consumed. This is
                // correct for callers that refresh on every read, and harmless
                // for callers that read `expires_in` only on the first fetch.
                var remaining = Stopwatch.GetElapsedTime(nowTicks, hit.ExpiresAtTicks);
                var remainingSeconds = (long)Math.Ceiling(remaining.TotalSeconds);
                return new TokenResponse(
                    accessToken: hit.Response.AccessToken,
                    tokenType: hit.Response.TokenType,
                    expiresIn: remainingSeconds,
                    scope: hit.Response.Scope,
                    issuedTokenType: hit.Response.IssuedTokenType,
                    cnfJkt: hit.Response.CnfJkt);
            }

            // Expired entry. Evict on miss so a workload cycling through many
            // distinct scope/resource tuples doesn't grow the cache unboundedly.
            _entries.TryRemove(key, out _);
        }

        var response = await factory(cancellationToken).ConfigureAwait(false);

        // Resolve the effective lifetime. The AS *should* set expires_in; when
        // it doesn't, fall back to defaultTtl so subsequent calls within that
        // window still hit the cache instead of paying a round-trip per call.
        TimeSpan lifetime;
        if (response.ExpiresIn is { } expiresIn && expiresIn > 0)
        {
            lifetime = TimeSpan.FromSeconds(expiresIn) - _ttlBuffer;
        }
        else
        {
            lifetime = _defaultTtl - _ttlBuffer;
        }

        if (lifetime > TimeSpan.Zero)
        {
            var expiresAt = Stopwatch.GetTimestamp() + (long)(lifetime.TotalSeconds * Stopwatch.Frequency);
            _entries[key] = new Entry(response, expiresAt);
        }

        return response;
    }

    /// <summary>Forget any cached token for <paramref name="scope"/> + <paramref name="resource"/>.</summary>
    public void Invalidate(string? scope, string? resource, string? clientId = null)
    {
        _entries.TryRemove(BuildKey(scope, resource, clientId), out _);
    }

    /// <summary>Drop the entire cache (e.g. on credential rotation).</summary>
    public void Clear() => _entries.Clear();

    /// <summary>
    /// Deterministic cache key for a <c>(scope, resource)</c> pair:
    /// scope tokens are split on whitespace and sorted so
    /// <c>"a b"</c> and <c>"b a"</c> share an entry; <c>scope</c> and <c>resource</c> are
    /// joined with a literal pipe so <c>("a b", "c")</c> and <c>("a bc", "")</c> map to
    /// different keys. Empty / null inputs yield <c>"_default"</c> rather than colliding
    /// on the empty string.
    /// <para>
    /// When <paramref name="clientId"/> is non-empty, the principal is prefixed
    /// to the resulting key (separated by <c>!</c>) so multi-tenant callers
    /// sharing one <see cref="TokenCache"/> can never serve a token issued to
    /// one <c>client_id</c> in response to a request from another. The <c>!</c>
    /// separator is intentionally distinct from <c>|</c> (used between scope
    /// and resource) so the principal cannot be confused with either part of
    /// the legacy key shape. An empty / null <paramref name="clientId"/>
    /// preserves the original key bytes — callers with a per-client cache
    /// instance don't have to migrate.
    /// </para>
    /// </summary>
    public static string BuildKey(string? scope, string? resource, string? clientId = null)
    {
        var scopePart = string.IsNullOrWhiteSpace(scope)
            ? string.Empty
            : string.Join(
                ' ',
                scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .OrderBy(s => s, StringComparer.Ordinal));

        var hasResource = !string.IsNullOrWhiteSpace(resource);
        string baseKey;
        if (hasResource)
        {
            baseKey = scopePart.Length == 0 ? $"|{resource}" : $"{scopePart}|{resource}";
        }
        else
        {
            baseKey = scopePart.Length == 0 ? "_default" : scopePart;
        }

        return string.IsNullOrEmpty(clientId) ? baseKey : $"{clientId}!{baseKey}";
    }
}
