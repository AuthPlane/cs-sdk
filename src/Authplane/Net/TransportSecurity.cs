using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Authplane;

internal static class TransportSecurity
{
    internal static HttpClient CreateHttpClient(FetchSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var socketsHandler = new SocketsHttpHandler
        {
            // Always disable auto-redirect so we can re-validate Location headers.
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            },
        };

        if (settings.SsrfProtection)
        {
            // DNS-pinning ConnectCallback: resolve once, validate IPs, then connect
            // to a validated IP directly — closes the TOCTOU / DNS-rebind window.
            socketsHandler.ConnectCallback = async (context, cancellationToken) =>
            {
                var host = context.DnsEndPoint.Host;
                var port = context.DnsEndPoint.Port;

                IPAddress[] addresses;
                if (IPAddress.TryParse(host, out var literal))
                {
                    addresses = new[] { literal };
                }
                else
                {
                    addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
                }

                if (addresses.Length == 0)
                {
                    throw new AuthplaneException($"DNS resolution returned no addresses for '{host}'.");
                }

                // Validate every resolved IP against SSRF policy.
                foreach (var ip in addresses)
                {
                    if (!IpValidation.IsAllowed(ip, settings))
                    {
                        throw new AuthplaneException(
                            $"Host '{host}' resolved to blocked IP '{ip}' — blocked by network policy.");
                    }
                }

                // Try each validated IP in order, iterating on connect failure.
                Exception? lastException = null;
                foreach (var addr in addresses)
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        socket.NoDelay = true;
                        await socket.ConnectAsync(addr, port, cancellationToken).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception ex)
                    {
                        socket.Dispose();
                        lastException = ex;
                    }
                }
                throw lastException ?? new AuthplaneException($"Failed to connect to '{host}'.");
            };
        }

        return new HttpClient(socketsHandler)
        {
            Timeout = TimeSpan.FromSeconds(settings.TimeoutSeconds),
            // 64 KB max response size — prevents unbounded memory allocation
            // from malicious metadata/JWKS endpoints.
            MaxResponseContentBufferSize = 65_536,
        };
    }

    internal static void ValidateFetchUrl(string value, FetchSettings settings, string context)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new AuthplaneException($"{context} must be an absolute URL.");
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw new AuthplaneException($"{context} must be an absolute URL: {value}");
        }

        ValidateParsedFetchUrl(uri, settings, context);
    }

    private static void ValidateParsedFetchUrl(Uri uri, FetchSettings settings, string context)
    {
        // Positive scheme allowlist: only http(s), block gopher://, file://, etc.
        var scheme = uri.Scheme.ToLowerInvariant();
        if (scheme != "https" && scheme != "http")
        {
            throw new AuthplaneException($"{context} must use http or https scheme, got '{uri.Scheme}'.");
        }

        if (!settings.AllowHttp && scheme != "https")
        {
            throw new AuthplaneException($"{context} must use HTTPS, got scheme '{uri.Scheme}'.");
        }

        // Reject userinfo in URLs: https://attacker@internal/admin leaks credentials
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new AuthplaneException($"{context} must not contain userinfo (user:pass@) in the URL.");
        }

        if (!settings.SsrfProtection)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new AuthplaneException($"{context} is missing host.");
        }

        var host = uri.Host;
        if (IsLocalhostName(host) && !settings.AllowLocalhost)
        {
            throw new AuthplaneException($"{context} host '{host}' is blocked by localhost policy.");
        }

        if (IPAddress.TryParse(host, out var ip))
        {
            if (!IpValidation.IsAllowed(ip, settings))
            {
                throw new AuthplaneException($"{context} host '{host}' is blocked by network policy.");
            }
        }
    }

    private static bool IsLocalhostName(string host)
    {
        var normalized = host.TrimEnd('.').ToLowerInvariant();
        return normalized == "localhost" || normalized.EndsWith(".localhost", StringComparison.Ordinal);
    }
}

