using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Authplane.Mcp.Tests;

public sealed class AuthplaneMcpAuthExtensionsGuardTests
{
    [Fact]
    public void UseAuthplaneMcpAuth_NullApp_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AuthplaneMcpAuthExtensions.UseAuthplaneMcpAuth(
                app: null!,
                options: new AuthplaneMcpAuth.Options(
                    issuer: "https://auth.example.com",
                    resource: "https://mcp.example.com",
                    scopes: new[] { "tools/add" })));
    }

    [Fact]
    public void UseAuthplaneMcpAuth_NullOptions_Throws()
    {
        var services = new ServiceCollection();
        var app = new ApplicationBuilder(services.BuildServiceProvider());

        Assert.Throws<ArgumentNullException>(() =>
            app.UseAuthplaneMcpAuth(options: null!));
    }
}
