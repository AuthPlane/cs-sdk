namespace Authplane;

/// <summary>
/// RFC 9449 §4.2 htu normalization: lowercase scheme+host, strip default ports,
/// strip query+fragment, default empty path to "/".
/// </summary>
internal static class DPoPHtu
{
    internal static string Normalize(string url)
    {
        // A relative or otherwise malformed htu used to surface as the
        // UriFormatException from `new Uri(...)`, get caught by the outer
        // generic `catch (Exception)` in VerifyAsync, and be re-wrapped as
        // InvalidSignatureException with the misleading message "Token
        // verification failed". Bind it to the DPoP-scheme InvalidDPoPProof
        // surface.
        Uri uri;
        try
        {
            uri = new Uri(url, UriKind.Absolute);
        }
        catch (UriFormatException ex)
        {
            throw new InvalidDPoPProofException(
                $"DPoP proof htu is not a valid absolute URI: '{url}'.", ex);
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        var host = uri.Host.ToLowerInvariant();
        var port = uri.Port;
        var path = uri.AbsolutePath;

        if (string.IsNullOrEmpty(path))
        {
            path = "/";
        }

        // Strip default ports (80 for http, 443 for https).
        var includePort = !((scheme == "https" && port == 443) || (scheme == "http" && port == 80));

        return includePort
            ? $"{scheme}://{host}:{port}{path}"
            : $"{scheme}://{host}{path}";
    }
}
