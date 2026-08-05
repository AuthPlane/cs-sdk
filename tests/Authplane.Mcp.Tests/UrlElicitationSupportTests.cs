using ModelContextProtocol;
using Xunit;

namespace Authplane.Mcp.Tests;

public sealed class UrlElicitationSupportTests
{
    [Fact]
    public void ToUrlElicitationRequiredError_MapsConsentRequiredException()
    {
        var source = new ConsentRequiredException(
            message: "user must grant access",
            oauthError: "consent_required",
            httpStatus: 400,
            serviceId: "calendar",
            causeDetail: "missing_user_consent",
            consentUrl: "https://as.example.com/consent?service=calendar");

        var mapped = UrlElicitationSupport.ToUrlElicitationRequiredError(source);

        var protocol = Assert.IsType<McpProtocolException>(mapped);
        Assert.Equal(McpErrorCode.UrlElicitationRequired, protocol.ErrorCode);
        Assert.Equal("user must grant access", protocol.Message);
        Assert.True(protocol.Data.Contains("elicitations"));
    }

    [Fact]
    public void ToUrlElicitationRequiredError_NonConsent_ReturnsOriginalError()
    {
        var source = new AuthplaneTokenRequestException("invalid request", "invalid_request", 400);
        var mapped = UrlElicitationSupport.ToUrlElicitationRequiredError(source);
        Assert.Same(source, mapped);
    }

    [Fact]
    public async Task WrapToolWithUrlElicitation_PassesThroughResult()
    {
        var result = await UrlElicitationSupport.WrapToolWithUrlElicitation(() => Task.FromResult(42));
        Assert.Equal(42, result);
    }

    [Fact]
    public async Task WrapToolWithUrlElicitation_ThrowsMcpProtocolException()
    {
        await Assert.ThrowsAsync<McpProtocolException>(() =>
            UrlElicitationSupport.WrapToolWithUrlElicitation<int>(() =>
                Task.FromException<int>(new ConsentRequiredException(
                    message: "interaction required",
                    oauthError: "interaction_required",
                    httpStatus: 400,
                    serviceId: "profile",
                    causeDetail: "interaction_required",
                    consentUrl: "https://as.example.com/consent?service=profile"))));
    }
}
