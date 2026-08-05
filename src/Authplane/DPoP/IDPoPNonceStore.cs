namespace Authplane;

/// <summary>
/// Pluggable storage for outbound DPoP nonces (RFC 9449 §8). The auth client persists
/// the most recent <c>DPoP-Nonce</c> the AS issued for a given origin and replays it on
/// the next request to that origin, retrying once on <c>error=use_dpop_nonce</c>.
/// </summary>
/// <remarks>
/// Origin keys follow the form <c>scheme://host:port</c> (always lowercased, default
/// port made explicit when the URI elided it). Use <see cref="DPoPNonceOrigin.From"/>
/// to derive a key — it is the single source of truth across the SDK so the same
/// nonce is found whether the caller passes <c>https://AS/</c>, <c>HTTPS://as:443/x</c>,
/// or any other casing.
/// </remarks>
public interface IDPoPNonceStore
{
    /// <summary>Get the last nonce stored for <paramref name="origin"/>, or <c>null</c>.</summary>
    Task<string?> GetAsync(string origin, CancellationToken cancellationToken = default);

    /// <summary>Persist <paramref name="nonce"/> for future requests to <paramref name="origin"/>.</summary>
    Task SetAsync(string origin, string nonce, CancellationToken cancellationToken = default);
}

/// <summary>
/// Single source of truth for the nonce-store origin key shape:
/// lowercase scheme + host, default port made explicit.
/// </summary>
internal static class DPoPNonceOrigin
{
    public static string From(string url)
    {
        var uri = new Uri(url, UriKind.Absolute);
        var scheme = uri.Scheme.ToLowerInvariant();
        var host = uri.Host.ToLowerInvariant();
        var port = uri.IsDefaultPort
            ? (scheme == "https" ? 443 : scheme == "http" ? 80 : uri.Port)
            : uri.Port;
        return $"{scheme}://{host}:{port}";
    }
}
