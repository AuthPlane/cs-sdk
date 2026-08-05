using System.Net;
using System.Security;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers <see cref="IpValidation"/> classifiers and the public
/// <see cref="Ssrf.ValidateUrlAsync"/> entry point. The classifiers have
/// 100+ complexity but most arms are unexercised; the policy entry point
/// is retained as public API but unused internally.
/// </summary>
public sealed class IpValidationAndSsrfTests
{
    private static readonly FetchSettings ProdStrict = new(
        ssrfProtection: true,
        allowHttp: false,
        allowLocalhost: false,
        allowPrivateNetworks: false,
        timeoutSeconds: 10);

    private static readonly FetchSettings DevPermissive = FetchSettings.FromDevMode(devMode: true);

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.5.5.5", true)]
    [InlineData("::1", true)]
    [InlineData("8.8.8.8", false)]
    public void IsLoopback(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsLoopback(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("169.254.1.2", true)]
    [InlineData("169.255.0.0", false)]
    [InlineData("fe80::1", true)]
    [InlineData("8.8.8.8", false)]
    public void IsLinkLocal(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsLinkLocal(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.1", true)]
    [InlineData("100.64.0.1", true)]   // CGNAT
    [InlineData("100.127.255.255", true)]
    [InlineData("100.128.0.1", false)] // outside CGNAT
    [InlineData("fc00::1", true)]      // ULA
    [InlineData("fd00::1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("2001:db8::1", false)] // documentation, not private
    public void IsPrivate(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsPrivate(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("169.254.169.254", true)]  // AWS / GCP / Azure IMDS
    [InlineData("fd00:ec2::254", true)]    // AWS IMDSv2 IPv6
    [InlineData("8.8.8.8", false)]
    public void IsCloudMetadata(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsCloudMetadata(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("224.0.0.1", true)]
    [InlineData("239.255.255.255", true)]
    [InlineData("ff02::1", true)]
    [InlineData("8.8.8.8", false)]
    public void IsMulticast(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsMulticast(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("0.0.0.0", true)]
    [InlineData("::", true)]
    [InlineData("8.8.8.8", false)]
    public void IsUnspecified(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsUnspecified(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("255.255.255.255", true)]
    [InlineData("8.8.8.8", false)]
    public void IsBroadcast(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsBroadcast(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("192.0.2.1", true)]
    [InlineData("198.51.100.1", true)]
    [InlineData("203.0.113.1", true)]
    [InlineData("2001:db8::1", true)]
    [InlineData("8.8.8.8", false)]
    public void IsDocumentation(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsDocumentation(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("198.18.0.1", true)]
    [InlineData("198.19.255.255", true)]
    [InlineData("198.20.0.1", false)]
    [InlineData("8.8.8.8", false)]
    public void IsBenchmarking(string ip, bool expected)
    {
        Assert.Equal(expected, IpValidation.IsBenchmarking(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("169.254.169.254")]        // cloud metadata
    [InlineData("169.254.1.1")]             // link-local
    [InlineData("0.0.0.0")]                 // unspecified
    [InlineData("255.255.255.255")]         // broadcast
    [InlineData("224.0.0.1")]               // multicast
    [InlineData("192.0.2.1")]               // documentation
    [InlineData("198.18.5.5")]              // benchmarking
    [InlineData("::ffff:169.254.169.254")]  // IPv4-mapped cloud metadata
    public void IsAllowed_AlwaysBlocked_RegardlessOfPolicy(string ip)
    {
        Assert.False(IpValidation.IsAllowed(IPAddress.Parse(ip), DevPermissive));
    }

    [Fact]
    public void IsAllowed_6to4_UnwrapsAndAppliesPolicyToEmbeddedIPv4()
    {
        // 2002:ac10:0101::1 wraps 172.16.1.1 (RFC 1918 private). Blocked in prod,
        // permitted in dev mode that allows private networks.
        var addr = IPAddress.Parse("2002:ac10:0101::1");
        Assert.False(IpValidation.IsAllowed(addr, ProdStrict));
        Assert.True(IpValidation.IsAllowed(addr, DevPermissive));
    }

    [Fact]
    public void IsAllowed_Teredo_UnwrapsAndChecksBothServerAndClient()
    {
        // Teredo prefix 2001:0000::/32, server 0.0.0.0 (unspecified) — always blocked.
        // Server = bytes[4..7]. Build "2001:0000:0000:0000::1" then patch.
        // Easier: explicit construction.
        var bytes = new byte[16];
        bytes[0] = 0x20; bytes[1] = 0x01; // 2001
        // bytes[2..3] = 0x00 (Teredo prefix continues)
        // bytes[4..7] = server = 0.0.0.0 (unspecified — blocked)
        // bytes[8..11] = flags+UDP port (irrelevant)
        // bytes[12..15] = inverted client (all 0xff inverted = 0.0.0.0)
        for (int i = 12; i < 16; i++)
        {
            bytes[i] = 0xff;
        }

        var teredo = new IPAddress(bytes);
        Assert.False(IpValidation.IsAllowed(teredo, DevPermissive));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    public void IsAllowed_LoopbackAndPrivate_BlockedInProd(string ip)
    {
        Assert.False(IpValidation.IsAllowed(IPAddress.Parse(ip), ProdStrict));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("::1")]
    public void IsAllowed_LoopbackAndPrivate_PermittedInDev(string ip)
    {
        Assert.True(IpValidation.IsAllowed(IPAddress.Parse(ip), DevPermissive));
    }

    [Fact]
    public void IsAllowed_PublicIp_PermittedEverywhere()
    {
        Assert.True(IpValidation.IsAllowed(IPAddress.Parse("8.8.8.8"), ProdStrict));
        Assert.True(IpValidation.IsAllowed(IPAddress.Parse("8.8.8.8"), DevPermissive));
    }

    // -----------------------------------------------------------------------
    // Ssrf.ValidateUrlAsync + ValidatedUrl
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ValidateUrlAsync_HttpsLiteralPublicIp_Allowed()
    {
        var result = await Ssrf.ValidateUrlAsync("https://8.8.8.8:443/path", ProdStrict);
        Assert.Equal("8.8.8.8", result.Hostname);
        Assert.Equal(443, result.Port);
        Assert.Single(result.ResolvedIps);
        Assert.Equal(IPAddress.Parse("8.8.8.8"), result.ResolvedIps[0]);
        Assert.Equal("https://8.8.8.8:443/path", result.OriginalUrl);
    }

    [Fact]
    public async Task ValidateUrlAsync_HttpScheme_RejectedWhenAllowHttpFalse()
    {
        await Assert.ThrowsAsync<SecurityException>(
            () => Ssrf.ValidateUrlAsync("http://8.8.8.8/", ProdStrict));
    }

    [Fact]
    public async Task ValidateUrlAsync_BlockedIpLiteral_Rejected()
    {
        await Assert.ThrowsAsync<SecurityException>(
            () => Ssrf.ValidateUrlAsync("https://169.254.169.254/", ProdStrict));
    }

    [Fact]
    public async Task ValidateUrlAsync_BlockedIpLiteral_PermittedWhenSsrfOff()
    {
        var settings = new FetchSettings(
            ssrfProtection: false, allowHttp: false,
            allowLocalhost: false, allowPrivateNetworks: false, timeoutSeconds: 10);
        var result = await Ssrf.ValidateUrlAsync("https://169.254.169.254/", settings);
        Assert.NotNull(result);
    }

    [Fact]
    public void ValidatedUrl_Ctor_AssignsAllFields()
    {
        var ips = new[] { IPAddress.Parse("1.2.3.4") };
        var v = new ValidatedUrl("https://example/", "example", 443, ips);
        Assert.Equal("https://example/", v.OriginalUrl);
        Assert.Equal("example", v.Hostname);
        Assert.Equal(443, v.Port);
        Assert.Same(ips, v.ResolvedIps);
    }
}
