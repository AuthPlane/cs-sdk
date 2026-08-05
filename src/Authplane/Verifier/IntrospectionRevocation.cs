using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Authplane;

/// <summary>
/// <see cref="IRevocationChecker"/> implementation backed by RFC 7662 introspection.
/// Reports a token as revoked when the AS responds with <c>active=false</c>.
/// Caches "active" results for a configurable TTL to avoid per-request AS round-trips.
/// </summary>
public sealed class IntrospectionRevocation : IRevocationChecker
{
    private readonly AuthplaneAuthClient _client;
    private readonly bool _failOpen;
    private readonly TimeSpan _cacheTtl;
    private readonly string _tokenTypeHint;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();

    private readonly record struct CacheEntry(bool IsRevoked, DateTimeOffset ExpiresAt);

    /// <summary>
    /// Creates a new introspection-based revocation checker.
    /// </summary>
    /// <param name="client">Auth client used to call the introspection endpoint.</param>
    /// <param name="failOpen">
    /// When <c>true</c>, transient errors (network failures, parsing errors) cause
    /// the checker to report the token as <b>not revoked</b> (fail-open / lenient).
    /// When <c>false</c> (default), errors propagate as exceptions, letting the caller
    /// decide how to handle them (fail-closed / strict).
    /// <para>
    /// <see cref="CircuitOpenException"/> always propagates, regardless of this flag —
    /// a tripped circuit means the authorization server is observably unhealthy, and
    /// silently accepting tokens during the outage would defeat revocation entirely.
    /// The resource-level <c>failClosed</c> on <see cref="AuthplaneResource"/> still
    /// decides whether the propagated exception becomes a hard reject or a fail-open
    /// accept. The two flags are intentionally independent: this one tunes
    /// "transient I/O hiccup" leniency; the resource's <c>failClosed</c> tunes
    /// "AS unreachable" leniency.
    /// </para>
    /// </param>
    /// <param name="cacheTtl">
    /// How long to cache "active" introspection results. Revoked results are never cached
    /// (always re-checked). Default: 60 seconds.
    /// </param>
    /// <param name="tokenTypeHint">
    /// RFC 7662 §2.1 <c>token_type_hint</c> sent with introspection requests. Defaults to
    /// <c>"access_token"</c>. Set to <c>"refresh_token"</c> when checking refresh tokens, or
    /// to <c>""</c> to omit the hint.
    /// </param>
    public IntrospectionRevocation(
        AuthplaneAuthClient client,
        bool failOpen = false,
        TimeSpan? cacheTtl = null,
        string tokenTypeHint = OAuthConstants.TokenTypeHintAccessToken)
    {
        _client = client;
        _failOpen = failOpen;
        _cacheTtl = cacheTtl ?? TimeSpan.FromSeconds(60);
        _tokenTypeHint = tokenTypeHint ?? string.Empty;
    }

    /// <summary>
    /// Whether this checker is configured for fail-open (lenient) behaviour.
    /// </summary>
    public bool FailOpen => _failOpen;

    public async Task<bool> IsRevokedAsync(string token, CancellationToken cancellationToken = default)
    {
        // SHA-256 fingerprint of the access token as the cache key.
        // The token itself is a JWT (frequently KBs); keying by the raw
        // string blew up the cache's working set on busy resource servers.
        // The hash is 32 bytes (43 base64url chars) regardless of token
        // size and is deterministic, so reads and writes still match.
        var key = CacheKey(token);

        // Only active (not-revoked) results are cached.
        if (_cache.TryGetValue(key, out var entry) && entry.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return entry.IsRevoked;
        }

        try
        {
            var introspection = await _client.IntrospectAsync(token, tokenTypeHint: _tokenTypeHint, cancellationToken: cancellationToken).ConfigureAwait(false);
            var isRevoked = !introspection.Active;

            // Cache active results to reduce AS load. Never cache revoked results
            // (they should always be rechecked in case of AS error).
            if (!isRevoked && _cacheTtl > TimeSpan.Zero)
            {
                _cache[key] = new CacheEntry(false, DateTimeOffset.UtcNow + _cacheTtl);
                EvictExpiredEntries();
            }

            return isRevoked;
        }
        catch (CircuitOpenException)
        {
            // A tripped circuit breaker means the AS is observably unhealthy.
            // Translating that to "not revoked" (silently allow the token)
            // lets a revoked token pass during an AS outage even when the
            // operator chose failOpen=true for transient I/O errors. Surface
            // the circuit-open as an explicit signal so the resource-level
            // fail-closed/open policy can choose how to handle "AS unavailable"
            // separately from "AS said no".
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch when (_failOpen)
        {
            // Fail-open: treat transient I/O / parse errors as "not revoked"
            // so the request proceeds.
            return false;
        }
    }

    private void EvictExpiredEntries()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _cache)
        {
            if (kvp.Value.ExpiresAt <= now)
            {
                _cache.TryRemove(kvp.Key, out _);
            }
        }
    }

    // Collision-resistant digest of the access token, used as a small,
    // fixed-size cache key. Collisions would require finding two access
    // tokens with the same SHA-256 — operationally impossible. Equality
    // of fingerprints therefore implies equality of tokens for cache-hit
    // purposes.
    private static string CacheKey(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        // Base64Url-encoded SHA-256 — a stable 43-char fingerprint that
        // never embeds `+`, `/`, or `=`, so the key is safe for any
        // downstream serialization without further escaping.
        return Base64Url.Encode(hash);
    }
}
