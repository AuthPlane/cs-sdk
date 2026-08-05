using System.Net;

namespace Authplane;

/// <summary>
/// IP-address classification helpers for SSRF policy.
/// </summary>
public static class IpValidation
{
    private static readonly IPAddress[] CloudMetadataAddresses =
    {
        IPAddress.Parse("169.254.169.254"),         // AWS / Azure / GCP IMDSv1/v2
        IPAddress.Parse("fd00:ec2::254"),           // AWS IMDSv2 IPv6
    };

    /// <summary>True when <paramref name="ip"/> is loopback (<c>127.0.0.0/8</c>, <c>::1</c>).</summary>
    public static bool IsLoopback(IPAddress ip) => IPAddress.IsLoopback(ip);

    /// <summary>True when <paramref name="ip"/> is link-local (<c>169.254/16</c>, <c>fe80::/10</c>).</summary>
    public static bool IsLinkLocal(IPAddress ip)
    {
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 169 && bytes[1] == 254;
        }
        return ip.IsIPv6LinkLocal;
    }

    /// <summary>True when <paramref name="ip"/> is in an RFC 1918 private range, CGNAT, or IPv6 ULA.</summary>
    public static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (b[0] == 10)
            {
                return true;
            }
            // 172.16.0.0/12
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            {
                return true;
            }
            // 192.168.0.0/16
            if (b[0] == 192 && b[1] == 168)
            {
                return true;
            }
            // 100.64.0.0/10 — RFC 6598 Carrier-Grade NAT
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            {
                return true;
            }

            return false;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            // fc00::/7 — unique local addresses
            return (b[0] & 0xFE) == 0xFC;
        }

        return false;
    }

    /// <summary>True when <paramref name="ip"/> is a cloud-metadata service address.</summary>
    public static bool IsCloudMetadata(IPAddress ip)
    {
        foreach (var meta in CloudMetadataAddresses)
        {
            if (ip.Equals(meta))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>True when <paramref name="ip"/> is multicast (<c>224.0.0.0/4</c>, IPv6 <c>ff00::/8</c>).</summary>
    public static bool IsMulticast(IPAddress ip)
    {
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return ip.GetAddressBytes()[0] >= 224 && ip.GetAddressBytes()[0] <= 239;
        }
        return ip.IsIPv6Multicast;
    }

    /// <summary>True when <paramref name="ip"/> is unspecified (<c>0.0.0.0</c>, <c>::</c>).</summary>
    public static bool IsUnspecified(IPAddress ip) =>
        ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6None);

    /// <summary>True when <paramref name="ip"/> is broadcast (<c>255.255.255.255</c>).</summary>
    public static bool IsBroadcast(IPAddress ip) => ip.Equals(IPAddress.Broadcast);

    /// <summary>
    /// True when <paramref name="ip"/> is in an IANA documentation/example range:
    /// <c>192.0.2.0/24</c> (TEST-NET-1), <c>198.51.100.0/24</c> (TEST-NET-2),
    /// <c>203.0.113.0/24</c> (TEST-NET-3), <c>2001:db8::/32</c>.
    /// </summary>
    public static bool IsDocumentation(IPAddress ip)
    {
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return (b[0] == 192 && b[1] == 0 && b[2] == 2)     // 192.0.2.0/24
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)   // 198.51.100.0/24
                || (b[0] == 203 && b[1] == 0 && b[2] == 113);   // 203.0.113.0/24
        }
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8; // 2001:db8::/32
        }
        return false;
    }

    /// <summary>True when <paramref name="ip"/> is in the benchmarking range <c>198.18.0.0/15</c>.</summary>
    public static bool IsBenchmarking(IPAddress ip)
    {
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 198 && (b[1] == 18 || b[1] == 19); // 198.18.0.0/15
        }
        return false;
    }

    /// <summary>
    /// Default SSRF policy: reject loopback, link-local, private, cloud-metadata,
    /// unspecified, broadcast, multicast, documentation, and benchmarking IPs
    /// unless the corresponding <see cref="FetchSettings"/> opt-in is set.
    /// Also unwraps IPv6 transition addresses (IPv4-mapped, 6to4, Teredo) and checks
    /// the embedded IPv4 portions.
    /// </summary>
    public static bool IsAllowed(IPAddress ip, FetchSettings settings)
    {
        // ALWAYS block cloud metadata — most dangerous SSRF vector
        if (IsCloudMetadata(ip))
        {
            return false;
        }

        // ALWAYS block link-local (includes cloud metadata 169.254.x.x, fe80::/10)
        if (IsLinkLocal(ip))
        {
            return false;
        }

        // IPv6 transition address unwrapping — must happen before other checks
        // because e.g. ::ffff:127.0.0.1 is not detected as loopback by .NET
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6)
            {
                return IsAllowed(ip.MapToIPv4(), settings);
            }

            var bytes = ip.GetAddressBytes();
            var seg0 = (ushort)((bytes[0] << 8) | bytes[1]);
            var seg1 = (ushort)((bytes[2] << 8) | bytes[3]);

            // 6to4 (2002::/16) — embedded IPv4 is bytes[2..5]
            if (seg0 == 0x2002)
            {
                var embedded = new IPAddress(new[] { bytes[2], bytes[3], bytes[4], bytes[5] });
                return IsAllowed(embedded, settings);
            }

            // Teredo (2001:0000::/32) — check BOTH server and client portions
            if (seg0 == 0x2001 && seg1 == 0x0000)
            {
                var server = new IPAddress(new[] { bytes[4], bytes[5], bytes[6], bytes[7] });
                if (!IsAllowed(server, settings))
                {
                    return false;
                }
                var client = new IPAddress(new[] {
                    (byte)~bytes[12], (byte)~bytes[13],
                    (byte)~bytes[14], (byte)~bytes[15]
                });
                return IsAllowed(client, settings);
            }
        }

        if (IsLoopback(ip))
        {
            return settings.AllowLocalhost;
        }

        if (IsPrivate(ip))
        {
            return settings.AllowPrivateNetworks;
        }

        // ALWAYS block these regardless of settings
        if (IsUnspecified(ip) || IsBroadcast(ip) || IsMulticast(ip)
            || IsDocumentation(ip) || IsBenchmarking(ip))
        {
            return false;
        }

        return true;
    }
}
