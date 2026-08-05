namespace Authplane;

/// <summary>
/// RFC 9728 helpers for OAuth Protected Resource Metadata (document URL and JSON shape).
/// </summary>
public static class OAuthProtectedResourceMetadata
{
    /// <summary>
    /// RFC 9728 §3.1 — absolute URL of the Protected Resource Metadata document for <paramref name="resourceUrl"/>.
    /// Path template: <c>/.well-known/oauth-protected-resource{resource-path}</c>.
    /// Trailing slashes on the resource path are dropped, so identifiers differing only by
    /// a trailing slash resolve to the same metadata document. Only the well-known path
    /// derivation normalizes — the resource identifier itself stays exact-string everywhere else.
    /// </summary>
    public static string GetDocumentUrl(string resourceUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceUrl);

        var uri = new Uri(resourceUrl, UriKind.Absolute);

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("Resource URL must not contain userinfo.", nameof(resourceUrl));
        }

        // Root "/" trims to empty, yielding the bare well-known URL.
        var resourcePath = uri.AbsolutePath.TrimEnd('/');

        return $"{uri.GetLeftPart(UriPartial.Authority)}/.well-known/oauth-protected-resource{resourcePath}";
    }
}
