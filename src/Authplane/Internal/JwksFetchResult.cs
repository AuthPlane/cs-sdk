using Microsoft.IdentityModel.Tokens;

namespace Authplane;

/// <summary>
/// Result of a JWKS fetch, carrying the key set and an optional server-provided TTL
/// derived from RFC 7234 cache headers.
/// </summary>
public sealed class JwksFetchResult
{
    public JsonWebKeySet KeySet { get; }

    /// <summary>
    /// Effective TTL from server cache headers (Cache-Control, Expires).
    /// Null when no cache header was present — the cache falls back to its configured default.
    /// </summary>
    public TimeSpan? ServerTtl { get; }

    public JwksFetchResult(JsonWebKeySet keySet, TimeSpan? serverTtl = null)
    {
        KeySet = keySet;
        ServerTtl = serverTtl;
    }
}
