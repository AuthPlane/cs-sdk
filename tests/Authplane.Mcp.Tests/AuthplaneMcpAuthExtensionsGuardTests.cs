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
    [InlineData("https://mcp.example.com/café", "path")]
    [InlineData("https://mcp.example.com/m%zzcp", "path")]
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
    /// <c>resourceMetadataUrl</c> is advertised to clients and never fetched by
    /// us, so nothing on the server side would ever notice a value that cannot
    /// be dereferenced: the failure surfaces at the client, on the first
    /// unauthenticated request, as a challenge pointing at nothing. It is held
    /// to the rules the issuer is held to, at construction, for the same reason
    /// the resource identifier is.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/oauth-protected-resource/mcp", "absolute URL")]
    [InlineData("//auth.example.com/.well-known/oauth-protected-resource/mcp", "absolute URL")]
    [InlineData("mailto:ops@auth.example.com", "absolute URL")]
    [InlineData("ftp://auth.example.com/prm", "must be https or http")]
    [InlineData("https://svc:s3cr3t@auth.example.com/prm", "userinfo")]
    // The identifier's whole gate set, not a subset: each of these parses into
    // a Uri with a scheme and a host, so an absoluteness check alone lets it
    // ride into the challenge and out to unauthenticated clients.
    [InlineData("https://café.example.com/prm", "host")]
    [InlineData("https://auth.example.com/pr%zzm", "path")]
    [InlineData("https://auth.example.com/prm?x=café", "query")]
    [InlineData("https://auth.example.com:80O/prm", "port")]
    [InlineData("https://auth.example.com/prm#frag", "fragment")]
    // Uri.TryCreate trims surrounding whitespace before parsing, so without a
    // raw-string gate these clear every parsed-URL check and are advertised
    // verbatim: the client fetches `.../prm%20` and gets a 404, with nothing
    // on the server side to say why.
    [InlineData("https://auth.example.com/prm ", "whitespace")]
    [InlineData(" https://auth.example.com/prm", "whitespace")]
    [InlineData("https://auth.example.com/prm\tx", "whitespace")]
    [InlineData("https://auth.example.com\\prm", "backslash")]
    public void Options_InvalidResourceMetadataUrl_ThrowsAtConstruction(
        string resourceMetadataUrl, string expectedInMessage)
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: "https://mcp.example.com/mcp",
                scopes: new[] { "tools/add" },
                resourceMetadataUrl: resourceMetadataUrl));

        Assert.Equal("resourceMetadataUrl", ex.ParamName);
        Assert.Contains(expectedInMessage, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Shape only, with no host policy and no <c>devMode</c> dependency: the
    /// value is advertised and never fetched, so it carries no SSRF surface of
    /// its own, and a loopback-only carve-out would refuse the in-cluster and
    /// docker-compose topologies dev mode exists to serve, so a single
    /// deployment configuration is accepted wherever this option is set.
    /// </summary>
    [Theory]
    [InlineData("http://localhost:9000/.well-known/oauth-protected-resource/mcp")]
    [InlineData("http://authserver:8080/.well-known/oauth-protected-resource/mcp")]
    [InlineData("https://10.1.2.3/.well-known/oauth-protected-resource/mcp")]
    public void Options_HttpAndPrivateResourceMetadataUrl_AcceptedWithoutDevMode(string url)
    {
        var options = new AuthplaneMcpAuth.Options(
            issuer: "https://auth.example.com",
            resource: "https://mcp.example.com/mcp",
            scopes: new[] { "tools/add" },
            devMode: false,
            resourceMetadataUrl: url);

        Assert.Equal(url, options.ResourceMetadataUrl);
    }

    /// <summary>
    /// The message has to name the setting the operator typed. These gates are
    /// shared with the resource identifier, so a hard-coded subject would send
    /// someone who mistyped <c>resourceMetadataUrl</c> off to look at
    /// <c>resource</c>.
    /// </summary>
    [Fact]
    public void Options_InvalidResourceMetadataUrl_MessageNamesTheSetting()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new AuthplaneMcpAuth.Options(
                issuer: "https://auth.example.com",
                resource: "https://mcp.example.com/mcp",
                scopes: new[] { "tools/add" },
                resourceMetadataUrl: "https://auth.example.com/prm "));

        Assert.StartsWith("resourceMetadataUrl", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("Resource identifier", ex.Message, StringComparison.Ordinal);
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
