using Xunit;

namespace Authplane.Mcp.Tests;

/// <summary>
/// The adapter's options are the single operator-facing entry for the resource
/// identifier, so they carry their own copy of the identifier gate set: the user
/// guide's lazy DI wiring defers the AuthplaneResource constructor to the first
/// request, and without this copy a misconfigured identifier boots clean and then
/// takes an unhandled exception out of the middleware — including out of the
/// public PRM GET.
///
/// The RFC 3986 §3.2.2 host production has to be in that copy for the same reason
/// as every other axis in it.
/// </summary>
public sealed class AuthplaneMcpAuthHostProductionTests
{
    [Theory]
    [InlineData("https://café.example.com/mcp")]
    [InlineData("https://例え.example.com/mcp")]
    [InlineData("https://api​.example.com/mcp")]
    public void Options_NonAsciiHost_IsRejectedAtConstruction(string resource)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("host", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("§3.2.2", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://api.example.com/mcp")]
    [InlineData("https://xn--caf-dma.example.com/mcp")]
    [InlineData("https://[fe80::1%25eth0]/mcp")]
    [InlineData("http://localhost:8080/mcp")]
    public void Options_HostInsideTheProduction_StaysAccepted(string resource)
    {
        var ex = Record.Exception(() =>
            new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Null(ex);
    }
}
