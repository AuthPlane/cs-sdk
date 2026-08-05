namespace Authplane;

/// <summary>
/// Parsed authorization-server metadata document (RFC 8414 / OIDC discovery).
/// Only fields the SDK actively consumes are surfaced here.
/// </summary>
/// <remarks>
/// `internal` — the cache is plumbed inside AuthplaneClient; callers don't
/// hold references to MetadataDocument directly.
/// </remarks>
internal sealed record MetadataDocument(string Issuer, string JwksUri);

/// <summary>
/// Result of a metadata fetch including any server-supplied TTL hint
/// (RFC 7234 <c>Cache-Control: max-age</c> / <c>Expires</c>).
/// </summary>
internal sealed record MetadataFetchResult(MetadataDocument Document, System.TimeSpan? ServerTtl = null);
