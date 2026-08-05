namespace Authplane;

/// <summary>
/// Single source of truth for the Authplane-served OAuth endpoint paths.
/// Six call sites used to build "{issuer}/oauth/token" /
/// "{issuer}/oauth/introspect" / "{issuer}/oauth/revoke" inline with their
/// own TrimEnd('/'), so a future rename (e.g. /oauth/v2/token) would have
/// required touching every site. RFC 8414 prescribes that callers should
/// in principle read the AS metadata document for these endpoints — that
/// stays an open item, but the path strings are at least centralised
/// here so the metadata-driven version can swap them out cleanly.
/// </summary>
internal static class OAuthEndpoints
{
    public const string TokenPath = "/oauth/token";
    public const string IntrospectionPath = "/oauth/introspect";
    public const string RevocationPath = "/oauth/revoke";

    public static string TokenUrl(string issuerUrl) => Join(issuerUrl, TokenPath);
    public static string IntrospectionUrl(string issuerUrl) => Join(issuerUrl, IntrospectionPath);
    public static string RevocationUrl(string issuerUrl) => Join(issuerUrl, RevocationPath);

    private static string Join(string issuerUrl, string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUrl);

        return $"{issuerUrl.TrimEnd('/')}{path}";
    }
}
