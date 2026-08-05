using System.Net;

namespace Authplane;

/// <summary>
/// SSRF-safe URL validation. Resolves a hostname to its IPs once, validates each against
/// the allow-list defined by <see cref="FetchSettings"/>, and returns the resolved IPs so
/// the actual TCP connection can be pinned to one of them — defeating the DNS-rebinding
/// TOCTOU window where a hostname resolves to a public IP for the validation check and
/// to a private IP for the actual connection.
/// </summary>
/// <remarks>
/// Not used internally — DNS-pinning is handled by <see cref="TransportSecurity"/>'s
/// <c>SocketsHttpHandler.ConnectCallback</c>. Retained as public API for callers
/// that need standalone URL validation with resolved IPs.
/// </remarks>
public sealed class ValidatedUrl
{
    public string OriginalUrl { get; }
    public string Hostname { get; }
    public int Port { get; }
    public IPAddress[] ResolvedIps { get; }

    public ValidatedUrl(string originalUrl, string hostname, int port, IPAddress[] resolvedIps)
    {
        OriginalUrl = originalUrl;
        Hostname = hostname;
        Port = port;
        ResolvedIps = resolvedIps;
    }
}

/// <summary>
/// Standalone SSRF URL validation. DNS-pinning is now handled internally by
/// <see cref="TransportSecurity.CreateHttpClient"/> via <c>ConnectCallback</c>.
/// This class is retained for callers needing explicit URL+IP validation.
/// </summary>
public static class Ssrf
{
    /// <summary>
    /// Resolve <paramref name="url"/>, reject any IP not allowed by <paramref name="settings"/>,
    /// and return a <see cref="ValidatedUrl"/> with the resolved IPs the caller can pin to.
    /// </summary>
    /// <exception cref="UriFormatException">Thrown for malformed URLs.</exception>
    /// <exception cref="System.Security.SecurityException">
    /// Thrown when the resolved IPs are blocked by <paramref name="settings"/>.
    /// </exception>
    public static async Task<ValidatedUrl> ValidateUrlAsync(string url, FetchSettings settings)
    {
        var uri = new Uri(url);
        if (!uri.IsAbsoluteUri)
        {
            throw new UriFormatException($"URL must be absolute: {url}");
        }

        var scheme = uri.Scheme.ToLowerInvariant();
        if (scheme != "https" && !(scheme == "http" && settings.AllowHttp))
        {
            throw new System.Security.SecurityException(
                $"authplane: URL '{url}' uses scheme '{scheme}' which is not permitted by FetchSettings.");
        }

        // IP literal: skip DNS, validate directly.
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            if (!IpValidation.IsAllowed(literal, settings) && settings.SsrfProtection)
            {
                throw new System.Security.SecurityException(
                    $"authplane: URL '{url}' resolves to a blocked IP address: {literal}");
            }

            return new ValidatedUrl(url, uri.Host, uri.Port, new[] { literal });
        }

        // DNS resolve and validate every result.
        var entry = await Dns.GetHostAddressesAsync(uri.Host).ConfigureAwait(false);
        if (entry.Length == 0)
        {
            throw new System.Security.SecurityException($"authplane: hostname '{uri.Host}' resolved to zero IPs.");
        }

        if (settings.SsrfProtection)
        {
            var blocked = entry.Where(ip => !IpValidation.IsAllowed(ip, settings)).ToArray();
            if (blocked.Length > 0)
            {
                throw new System.Security.SecurityException(
                    $"authplane: hostname '{uri.Host}' resolved to blocked IP(s): {string.Join(", ", blocked.Select(ip => ip.ToString()))}");
            }
        }

        return new ValidatedUrl(url, uri.Host, uri.Port, entry);
    }
}
