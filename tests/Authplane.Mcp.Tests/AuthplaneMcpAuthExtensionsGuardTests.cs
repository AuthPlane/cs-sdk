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

    /// <summary>
    /// The <see cref="AuthplaneMcpAuth.Options"/> constructor is the single
    /// operator-facing entry for the adapter, so the full identifier gate set
    /// runs there: <c>CreateResourceAsync</c>, <c>SetupAsync</c>, and
    /// <c>UseAuthplaneMcpAuth</c> (which derives the DPoP <c>htu</c> origin
    /// from the identifier) all inherit it, and a misconfigured identifier
    /// fails where the operator writes it — at startup.
    /// </summary>
    [Theory]
    [InlineData("https://mcp.example.com/mcp#frag", "fragment")]
    [InlineData("/mcp", "absolute URL")]
    [InlineData("//api.example.com/mcp", "absolute URL")]
    [InlineData("https://svc:s3cr3t@api.example.com/mcp", "userinfo")]
    [InlineData("https://mcp.example.com/mcp ", "whitespace")]
    [InlineData("https://mcp.example.com/my mcp", "whitespace")]
    [InlineData("https://mcp.example.com/m\\cp", "backslash")]
    [InlineData("https://mcp.example.com/mcp?a=\"b\"", "query")]
    [InlineData("https://mcp.example.com/mcp?a=%zz", "query")]
    [InlineData("https://mcp.example.com:80O/mcp", "port")]
    public void Options_InvalidResource_ThrowsAtConstruction(string resource, string expectedInMessage)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: resource,
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains(expectedInMessage, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The quickstart wires the verifier as a lazy DI factory, so
    /// <c>CreateResourceAsync</c> — and the <see cref="AuthplaneResource"/>
    /// constructor gates — would only run on first resolution inside the
    /// middleware. The Options gate fails earlier: the wiring cannot even be
    /// declared with <c>resource: "/mcp"</c>, so the server never boots into a
    /// state where the first request (including the public PRM GET) takes an
    /// unhandled exception out of the middleware. Without the Options gate,
    /// <c>UseAuthplaneMcpAuth</c> would also have anchored the DPoP
    /// <c>htu</c> origin on the runtime's implicit <c>file</c> scheme.
    /// </summary>
    [Fact]
    public void Options_RelativeResource_FailsBeforeLazyDiWiringCanBeDeclared()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(() =>
        {
            // Mirrors the user guide's Program.cs shape: Options first, then
            // the lazy singleton and the middleware. The first line throws.
            var options = new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: "/mcp",
                scopes: new[] { "tools/add" });

            services.AddSingleton<AuthplaneResource>(_ =>
                AuthplaneMcpAuth.CreateResourceAsync(options).GetAwaiter().GetResult());
            var app = new ApplicationBuilder(services.BuildServiceProvider());
            app.UseAuthplaneMcpAuth(options);
        });

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The deeper gates stay in place as defence in depth: the
    /// <see cref="AuthplaneResource"/> construction path re-runs the same
    /// checks ahead of the issuer metadata fetch, so even a hypothetical
    /// caller that bypassed Options would fail before any network round trip.
    /// </summary>
    [Fact]
    public async Task CreateResourceAsync_GateAlsoRunsInCoreFactory()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "https://auth.example.com",
                resource: "/mcp",
                scopes: new[] { "tools/add" }));

        Assert.Equal("resource", ex.ParamName);
        Assert.Contains("absolute URL", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
