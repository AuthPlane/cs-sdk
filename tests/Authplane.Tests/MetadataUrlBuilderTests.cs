using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

public sealed class MetadataUrlBuilderTests
{
    [Fact]
    public void BuildOAuthAuthorizationServerMetadataUrl_RootIssuer()
    {
        Assert.Equal(
            "https://auth.example.com/.well-known/oauth-authorization-server",
            MetadataUrlBuilder.BuildOAuthAuthorizationServerMetadataUrl("https://auth.example.com"));
    }

    [Fact]
    [Conformance("rfc8414-discovery-url-must-insert-well-known-before-issuer-path")]
    public void BuildOAuthAuthorizationServerMetadataUrl_PathIssuer()
    {
        Assert.Equal(
            "https://auth.example.com/.well-known/oauth-authorization-server/t1",
            MetadataUrlBuilder.BuildOAuthAuthorizationServerMetadataUrl("https://auth.example.com/t1"));
    }

    [Fact]
    public void BuildOpenIdConfigurationMetadataUrl_AppendsSegment()
    {
        Assert.Equal(
            "https://auth.example.com/.well-known/openid-configuration",
            MetadataUrlBuilder.BuildOpenIdConfigurationMetadataUrl("https://auth.example.com"));
    }
}
