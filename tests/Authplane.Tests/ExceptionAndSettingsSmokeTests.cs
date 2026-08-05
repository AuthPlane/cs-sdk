using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Coverage smoke tests for exception ctors and DTO settings classes that
/// otherwise sit at 0% line-rate because no test in the existing suite
/// throws / constructs them.
/// </summary>
public sealed class ExceptionAndSettingsSmokeTests
{
    [Fact]
    public void AllExceptionTypes_ConstructAndCarryMessage()
    {
        // Instantiate every public exception type so ctor lines are covered.
        // (The verifier and OAuth paths only exercise a subset of these in
        //  the existing suite, leaving several ctors at 0%.)
        var inner = new InvalidOperationException("inner");

        var exceptions = new AuthplaneException[]
        {
            new TokenMissingException("a"),
            new TokenExpiredException("a"),
            new InvalidSignatureException("a"),
            new InvalidSignatureException("a", inner),
            new InvalidClaimsException("a"),
            new InvalidClaimsException("a", inner),
            new InsufficientScopeException("a"),
            new JwksFetchException("a"),
            new JwksFetchException("a", inner),
            new MetadataFetchException("a"),
            new MetadataFetchException("a", inner),
            new MissingMetadataEndpointException("a"),
            new MissingMetadataEndpointException("a", inner),
            new TokenRevokedException("a", inner),
            new VerifierRuntimeException("a"),
            new VerifierRuntimeException("a", inner),
            new ProtocolException("a"),
            new ProtocolException("a", inner),
            new DPoPException("a"),
            new DPoPException("a", inner),
            new InvalidDPoPProofException("a"),
            new InvalidDPoPProofException("a", inner),
            new DPoPProofMissingException("a"),
            new DPoPBindingMismatchException("a"),
            new DPoPReplayDetectedException("a"),
            new DPoPNotSupportedException("a"),
            new TokenRevokedException("a"),
            new CircuitOpenException(),
            new AuthplaneAuthClientException("a"),
            new AuthplaneAuthClientException("a", inner),
            new AuthplaneTokenResponseParsingException("a"),
            new AuthplaneTokenResponseParsingException("a", inner),
            new AuthplaneIntrospectionResponseParsingException("a"),
            new AuthplaneIntrospectionResponseParsingException("a", inner),
            new ServerError("a"),
        };

        foreach (var ex in exceptions)
        {
            Assert.False(string.IsNullOrEmpty(ex.Message));
        }
    }

    [Fact]
    public void MissingMetadataEndpointException_PreservesTransportCause()
    {
        // The (string, Exception) ctor exists so AuthplaneClient.FetchMetadata
        // can surface the last transport failure when every discovery URL
        // fails. The whole point of the change is that the operator gets the
        // root cause attached instead of a bare "neither endpoint reachable"
        // string.
        var transport = new System.Net.Http.HttpRequestException("connection refused");
        var ex = new MissingMetadataEndpointException(
            "Failed to discover JWKS URI: ... Last transport error: connection refused.",
            transport);

        Assert.Same(transport, ex.InnerException);
        Assert.Contains("Last transport error", ex.Message, StringComparison.Ordinal);
        // Still a MetadataFetchException so existing catch(MetadataFetchException) sites match.
        Assert.IsAssignableFrom<MetadataFetchException>(ex);
    }

    [Fact]
    public void AuthplaneTokenRequestException_CarriesOAuthMetadata()
    {
        var ex = new AuthplaneTokenRequestException("msg", "invalid_grant", 400, "describe", "https://x/y");
        Assert.Equal("invalid_grant", ex.OAuthError);
        Assert.Equal(400, ex.HttpStatus);
        Assert.Equal("describe", ex.ErrorDescription);
        Assert.Equal("https://x/y", ex.ErrorUri);

        // 1-arg ctor — defaults oauthError/httpStatus to null.
        var bare = new AuthplaneTokenRequestException("msg");
        Assert.Null(bare.OAuthError);
        Assert.Null(bare.HttpStatus);
    }

    [Fact]
    public void TokenRequestException_TypedSubclasses_CarryTheirCode()
    {
        Assert.Equal("invalid_client", new InvalidClientException("m", 400).OAuthError);
        Assert.Equal("unauthorized_client", new UnauthorizedClientException("m", 401).OAuthError);
        Assert.Equal("invalid_grant", new InvalidGrantException("m", 400).OAuthError);
        Assert.Equal("invalid_scope", new InvalidScopeException("m", 400).OAuthError);
        Assert.Equal("invalid_request", new InvalidRequestException("m", 400).OAuthError);
        Assert.Equal("unsupported_grant_type", new UnsupportedGrantTypeException("m", 400).OAuthError);
    }

    [Fact]
    public void ConsentRequiredException_NormalisesBlankServiceIdAndCause()
    {
        var ex = new ConsentRequiredException(
            message: "msg",
            oauthError: "consent_required",
            httpStatus: 403,
            serviceId: "   ",
            causeDetail: "   ",
            consentUrl: "  ");
        Assert.Equal("unknown_service", ex.ServiceId);
        Assert.Equal("msg", ex.CauseDetail); // falls back to message
        Assert.Null(ex.ConsentUrl);
    }

    [Fact]
    public void JwksFetchSettings_ProdAndDevDefaults()
    {
        var prod = JwksFetchSettings.CreateForDevMode(devMode: false);
        Assert.True(prod.SsrfProtection);
        Assert.False(prod.AllowHttp);
        Assert.False(prod.AllowLocalhost);
        Assert.False(prod.AllowPrivateNetworks);

        var dev = JwksFetchSettings.CreateForDevMode(devMode: true);
        Assert.False(dev.SsrfProtection);
        Assert.True(dev.AllowHttp);
        Assert.True(dev.AllowLocalhost);
        Assert.True(dev.AllowPrivateNetworks);
    }

    [Fact]
    public void MetadataFetchSettings_ProdAndDevDefaults()
    {
        var prod = MetadataFetchSettings.CreateForDevMode(devMode: false);
        Assert.True(prod.SsrfProtection);
        Assert.False(prod.AllowHttp);

        var dev = MetadataFetchSettings.CreateForDevMode(devMode: true);
        Assert.False(dev.SsrfProtection);
        Assert.True(dev.AllowHttp);
    }
}
