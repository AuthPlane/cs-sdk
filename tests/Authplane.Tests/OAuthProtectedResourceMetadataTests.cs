using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

public sealed class OAuthProtectedResourceMetadataTests
{
    [Fact]
    [Conformance("rfc9728-well-known-path-must-derive-from-resource-uri")]
    public void GetDocumentUrl_Rfc9728Examples()
    {
        Assert.Equal(
            "https://rs.example.com/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://rs.example.com/mcp"));

        Assert.Equal(
            "https://rs.example.com/.well-known/oauth-protected-resource",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://rs.example.com/"));
    }

    [Fact]
    [Conformance("rfc9728-well-known-path-must-derive-from-resource-uri")]
    public void GetDocumentUrl_DropsTrailingSlashOnResourcePath()
    {
        // Identifiers differing only by a trailing slash resolve to the same document.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp/"));

        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/v2/mcp",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/v2/mcp"));

        // Root with trailing slash still yields the bare well-known URL.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/"));

        // Bare host (no path at all) also yields the bare well-known URL.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com"));

        // RFC 3986 §3.3: a percent-encoded %2F is data inside the final
        // segment, not the "/" delimiter, so it must survive the trim.
        // Pins that Uri.AbsolutePath hands back the escaped form rather
        // than decoding it into a trimmable slash.
        Assert.Equal(
            "https://api.example.com/.well-known/oauth-protected-resource/mcp%2F",
            OAuthProtectedResourceMetadata.GetDocumentUrl("https://api.example.com/mcp%2F"));
    }
}
