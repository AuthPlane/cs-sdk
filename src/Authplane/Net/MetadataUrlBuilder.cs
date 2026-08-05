namespace Authplane;

/// <summary>
/// Builds authorization server metadata discovery URLs (RFC 8414 and OpenID Connect discovery).
/// </summary>
public static class MetadataUrlBuilder
{
    private const string WellKnownOAuth = "/.well-known/oauth-authorization-server";

    /// <summary>
    /// RFC 8414 §3 — inserts <c>/.well-known/oauth-authorization-server</c> after the authority.
    /// </summary>
    public static string BuildOAuthAuthorizationServerMetadataUrl(string issuer)
    {
        var normalized = issuer.EndsWith('/')
            ? issuer[..^1]
            : issuer;

        var uri = new Uri(normalized, UriKind.Absolute);

        // RFC 8414 §2: issuer MUST NOT contain query or fragment.
        if (!string.IsNullOrEmpty(uri.Query))
        {
            throw new AuthplaneException($"Issuer URL must not contain a query string: '{issuer}'.");
        }
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            throw new AuthplaneException($"Issuer URL must not contain a fragment: '{issuer}'.");
        }

        var path = uri.AbsolutePath.TrimEnd('/');
        var authority = uri.GetLeftPart(UriPartial.Authority);

        if (string.IsNullOrEmpty(path) || path == "/")
        {
            return $"{authority}{WellKnownOAuth}";
        }

        var pathNoLeading = path.StartsWith('/') ? path[1..] : path;
        return $"{authority}{WellKnownOAuth}/{pathNoLeading}";
    }

    /// <summary>
    /// OpenID Provider metadata (append <c>/.well-known/openid-configuration</c> to issuer), MCP fallback.
    /// </summary>
    public static string BuildOpenIdConfigurationMetadataUrl(string issuer)
    {
        var normalized = issuer.EndsWith('/')
            ? issuer[..^1]
            : issuer;
        return $"{normalized}/.well-known/openid-configuration";
    }
}
