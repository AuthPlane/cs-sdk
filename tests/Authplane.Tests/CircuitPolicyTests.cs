using Xunit;

namespace Authplane.Tests;

public class CircuitPolicyTests
{
    [Fact]
    public void CircuitOpenException_DoesNotRecord()
    {
        Assert.False(CircuitPolicy.ShouldRecordFailure(new CircuitOpenException()));
    }

    [Fact]
    public void ServerError_AlwaysRecords()
    {
        Assert.True(CircuitPolicy.ShouldRecordFailure(new ServerError("network")));
    }

    [Fact]
    public void TokenRequest_InvalidGrant_DoesNotRecord()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 400, error=invalid_grant",
            oauthError: "invalid_grant",
            httpStatus: 400);
        Assert.False(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_InvalidScope_DoesNotRecord()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 400",
            oauthError: "invalid_scope",
            httpStatus: 400);
        Assert.False(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_ConsentRequired_DoesNotRecord()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 400",
            oauthError: "consent_required",
            httpStatus: 400);
        Assert.False(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_InvalidClient_Records()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 401",
            oauthError: "invalid_client",
            httpStatus: 401);
        Assert.True(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_UnauthorizedClient_Records()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 400",
            oauthError: "unauthorized_client",
            httpStatus: 400);
        Assert.True(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_ServerErrorOAuthCode_Records_On400()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 400",
            oauthError: "server_error",
            httpStatus: 400);
        Assert.True(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_Http503_Records()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 503",
            oauthError: null,
            httpStatus: 503);
        Assert.True(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_401_NoOAuthBody_Records()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 401",
            oauthError: null,
            httpStatus: 401);
        Assert.True(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void TokenRequest_UnknownOAuthCodeOn400_DoesNotRecord()
    {
        var ex = new AuthplaneTokenRequestException(
            "HTTP 400",
            oauthError: "slow_down",
            httpStatus: 400);
        Assert.False(CircuitPolicy.ShouldRecordFailure(ex));
    }

    [Fact]
    public void GenericException_Records()
    {
        Assert.True(CircuitPolicy.ShouldRecordFailure(new InvalidOperationException("x")));
    }
}
