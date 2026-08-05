using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers <see cref="AuthplaneErrors"/> — WWW-Authenticate building,
/// HttpStatus mapping, and the RFC 6749 §5.2 MapOAuthError dispatcher.
/// All pure functions; no fixtures needed.
/// </summary>
public sealed class AuthplaneErrorsTests
{
    // -----------------------------------------------------------------------
    // WwwAuthenticate
    // -----------------------------------------------------------------------

    [Fact]
    public void WwwAuthenticate_BearerScheme_ForNonDPoPException()
    {
        var header = AuthplaneErrors.WwwAuthenticate(new TokenExpiredException("expired"));
        Assert.StartsWith("Bearer ", header, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_token\"", header, StringComparison.Ordinal);
        Assert.Contains("error_description=\"expired\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public void WwwAuthenticate_DPoPScheme_ForDPoPException()
    {
        var header = AuthplaneErrors.WwwAuthenticate(new DPoPProofMissingException("missing proof"));
        Assert.StartsWith("DPoP ", header, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_token\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public void WwwAuthenticate_InsufficientScopeErrorCode()
    {
        var header = AuthplaneErrors.WwwAuthenticate(new InsufficientScopeException("need tools/add"));
        Assert.Contains("error=\"insufficient_scope\"", header, StringComparison.Ordinal);
    }

    [Fact]
    [Conformance("rfc6750-error-response-must-map-error-codes",
        Note = "Covers the dpop_not_supported scheme row of the www_authenticate(error) scenario table")]
    public void WwwAuthenticate_BearerScheme_ForDPoPNotSupported()
    {
        // A resource that has not opted into DPoP must not answer a DPoP
        // signal with a DPoP-scheme challenge — that would send the client
        // into a negotiate-DPoP-then-reject loop. Bearer breaks it.
        var header = AuthplaneErrors.WwwAuthenticate(new DPoPNotSupportedException("dpop not supported"));
        Assert.StartsWith("Bearer ", header, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_token\"", header, StringComparison.Ordinal);
    }

    [Fact]
    [Conformance("rfc6750-error-response-must-map-error-codes",
        Note = "Covers the multiple-proofs invalid_dpop_proof row of the www_authenticate(error) scenario table")]
    public void WwwAuthenticate_InvalidDPoPProofErrorCode_ForMultipleProofs()
    {
        // RFC 9449 §7.1 prescribes `invalid_dpop_proof` for the §4.3
        // cardinality rejection; the other DPoP failures stay on
        // `invalid_token` (asserted above for DPoPProofMissingException).
        var header = AuthplaneErrors.WwwAuthenticate(new DPoPMultipleProofsException("multiple proofs"));
        Assert.StartsWith("DPoP ", header, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_dpop_proof\"", header, StringComparison.Ordinal);
    }

    [Fact]
    [Conformance("rfc6750-error-response-realm-should-be-included",
        Note = "Realm emission lives in AuthplaneErrors.WwwAuthenticate; the Authplane.Mcp middleware exposes it via Options.Realm (asserted in AuthplaneMcpAuthMiddlewareTests)")]
    public void WwwAuthenticate_IncludesRealm_WhenProvided()
    {
        var header = AuthplaneErrors.WwwAuthenticate(
            new TokenExpiredException("expired"), realm: "api.example.com");
        Assert.Contains("realm=\"api.example.com\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public void WwwAuthenticate_OmitsRealm_WhenEmpty()
    {
        var header = AuthplaneErrors.WwwAuthenticate(new TokenExpiredException("expired"));
        Assert.DoesNotContain("realm=", header, StringComparison.Ordinal);
    }

    [Fact]
    public void WwwAuthenticate_EscapesQuotesAndBackslashesInErrorDescription()
    {
        // RFC 7235 quoted-string: " and \ must be backslash-escaped. A naked
        // " inside error_description would terminate the header value early
        // and break the auth-param parser. Same pattern applies to realm.
        var header = AuthplaneErrors.WwwAuthenticate(
            new TokenExpiredException("bad \"token\" with \\ slash"),
            realm: "api \"prod\" \\");

        Assert.Contains(
            "error_description=\"bad \\\"token\\\" with \\\\ slash\"",
            header,
            StringComparison.Ordinal);
        Assert.Contains(
            "realm=\"api \\\"prod\\\" \\\\\"",
            header,
            StringComparison.Ordinal);
    }

    [Fact]
    public void WwwAuthenticate_StripsCRLFAndControlChars_FromErrorDescriptionAndRealm()
    {
        // H11 / RFC 7230/9110: CTLs (0x00-0x1F and 0x7F) are forbidden in
        // header field values. An attacker-controlled fragment of error.Message
        // (or a maliciously-configured realm) containing \r\n could inject
        // continuation lines and forge subsequent response headers. CR/LF are
        // the canonical injection vector; tabs/NUL/etc. are defence in depth.
        var header = AuthplaneErrors.WwwAuthenticate(
            new TokenExpiredException("expired\r\nX-Injected: 1\ttab\x7f"),
            realm: "api\r\nX-Realm-Injection: yes");

        // The header must contain no CR, LF, tab or other CTL — those are the
        // bytes that would actually let an attacker inject a new header line.
        // Printable text around the stripped CTLs remains inside the
        // quoted-string and is harmless.
        Assert.DoesNotContain("\r", header, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", header, StringComparison.Ordinal);
        Assert.DoesNotContain("\t", header, StringComparison.Ordinal);
        Assert.DoesNotContain("\x7f", header, StringComparison.Ordinal);

        Assert.Contains("error_description=\"expiredX-Injected: 1tab\"", header, StringComparison.Ordinal);
        Assert.Contains("realm=\"apiX-Realm-Injection: yes\"", header, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // HttpStatus
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData(typeof(InsufficientScopeException), 403)]
    [InlineData(typeof(JwksFetchException), 503)]
    [InlineData(typeof(MetadataFetchException), 503)]
    [InlineData(typeof(MissingMetadataEndpointException), 503)] // subclass of MetadataFetchException
    [InlineData(typeof(TokenMissingException), 401)]
    [InlineData(typeof(TokenExpiredException), 401)]
    [InlineData(typeof(InvalidSignatureException), 401)]
    [InlineData(typeof(InvalidClaimsException), 401)]
    [InlineData(typeof(TokenRevokedException), 401)]
    [InlineData(typeof(DPoPProofMissingException), 401)] // subclass of DPoPException
    [InlineData(typeof(DPoPMultipleProofsException), 401)]
    [InlineData(typeof(DPoPBindingMismatchException), 401)]
    [InlineData(typeof(ProtocolException), 500)]
    [InlineData(typeof(VerifierRuntimeException), 500)]
    public void HttpStatus_MapsKnownExceptionTypes(Type exceptionType, int expectedStatus)
    {
        var exception = (AuthplaneException)Activator.CreateInstance(exceptionType, "test")!;
        Assert.Equal(expectedStatus, AuthplaneErrors.HttpStatus(exception));
    }

    [Fact]
    public void HttpStatus_DefaultsTo500_ForUnknownException()
    {
        // CircuitOpenException is intentionally not in the switch — exercises the default arm.
        Assert.Equal(500, AuthplaneErrors.HttpStatus(new CircuitOpenException()));
    }

    // -----------------------------------------------------------------------
    // MapOAuthError
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("invalid_client", typeof(InvalidClientException))]
    [InlineData("unauthorized_client", typeof(UnauthorizedClientException))]
    [InlineData("invalid_grant", typeof(InvalidGrantException))]
    [InlineData("invalid_scope", typeof(InvalidScopeException))]
    [InlineData("invalid_request", typeof(InvalidRequestException))]
    [InlineData("unsupported_grant_type", typeof(UnsupportedGrantTypeException))]
    public void MapOAuthError_DispatchesTypedSubclass(string oauthError, Type expectedType)
    {
        var ex = (AuthplaneTokenRequestException)AuthplaneErrors.MapOAuthError(
            oauthError: oauthError,
            httpStatus: 400,
            errorDescription: "describe",
            errorUri: "https://errors.example.com/x");

        Assert.IsType(expectedType, ex);
        Assert.Equal(oauthError, ex.OAuthError);
        Assert.Equal(400, ex.HttpStatus);
        Assert.Equal("describe", ex.ErrorDescription);
        Assert.Equal("https://errors.example.com/x", ex.ErrorUri);
    }

    [Fact]
    public void MapOAuthError_UnknownCode_ReturnsBaseTokenRequestException()
    {
        var ex = Assert.IsType<AuthplaneTokenRequestException>(
            AuthplaneErrors.MapOAuthError(oauthError: "weird_error", httpStatus: 400));
        Assert.Equal("weird_error", ex.OAuthError);
        Assert.Equal(400, ex.HttpStatus);
    }

    [Fact]
    public void MapOAuthError_5xx_ReturnsServerError()
    {
        // RFC 6749 doesn't define a token-endpoint behaviour for 5xx;
        // MapOAuthError surfaces it as ServerError regardless of the (often missing)
        // `error` body.
        var ex = AuthplaneErrors.MapOAuthError(oauthError: null, httpStatus: 503);
        Assert.IsType<ServerError>(ex);
    }

    [Fact]
    public void MapOAuthError_Bare401_ReturnsInvalidClient()
    {
        // A bodyless 401 is the AS rejecting client authentication — InvalidClientError
        // is the typed handle. Without this fallback, callers got the generic
        // AuthplaneTokenRequestException with no useful discriminator.
        var ex = AuthplaneErrors.MapOAuthError(oauthError: null, httpStatus: 401);
        Assert.IsType<InvalidClientException>(ex);
    }

    [Fact]
    public void MapOAuthError_NullOAuthError_OmitsErrorSuffix()
    {
        // 400 with no body — not 5xx (would map to ServerError) and not 401 (would
        // map to InvalidClient). Falls through to the generic base.
        var ex = (AuthplaneTokenRequestException)AuthplaneErrors.MapOAuthError(
            oauthError: null, httpStatus: 400);
        Assert.Null(ex.OAuthError);
        Assert.DoesNotContain(", error=", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MapOAuthError_CustomMessage_OverridesDefault()
    {
        var ex = AuthplaneErrors.MapOAuthError(
            oauthError: "invalid_grant",
            httpStatus: 400,
            message: "custom override");
        Assert.Equal("custom override", ex.Message);
    }

    [Fact]
    public void MapOAuthError_ConsentRequired_ReturnsConsentRequiredException()
    {
        var ex = AuthplaneErrors.MapOAuthError(
            oauthError: "consent_required",
            httpStatus: 403,
            errorDescription: "user must consent",
            serviceId: "svc_calendar",
            cause: "calendar scope missing",
            consentUrl: "https://consent.example.com/calendar");

        var consent = Assert.IsType<ConsentRequiredException>(ex);
        Assert.Equal("svc_calendar", consent.ServiceId);
        Assert.Equal("calendar scope missing", consent.CauseDetail);
        Assert.Equal("https://consent.example.com/calendar", consent.ConsentUrl);
    }

    [Fact]
    public void MapOAuthError_InteractionRequired_AlsoMapsToConsentRequired()
    {
        var ex = AuthplaneErrors.MapOAuthError(
            oauthError: "interaction_required",
            httpStatus: 403,
            errorDescription: "interaction needed");
        var consent = Assert.IsType<ConsentRequiredException>(ex);
        Assert.Equal("unknown_service", consent.ServiceId);
        Assert.Equal("interaction needed", consent.CauseDetail);
        Assert.Null(consent.ConsentUrl);
    }

    [Fact]
    public void MapOAuthError_ConsentRequired_FallsBackToErrorDescription_ForCause()
    {
        var ex = AuthplaneErrors.MapOAuthError(
            oauthError: "consent_required",
            httpStatus: 403,
            errorDescription: "fallback cause text");
        var consent = Assert.IsType<ConsentRequiredException>(ex);
        Assert.Equal("fallback cause text", consent.CauseDetail);
    }

    [Fact]
    public void MapOAuthError_ConsentRequired_BlankConsentUrl_BecomesNull()
    {
        var ex = AuthplaneErrors.MapOAuthError(
            oauthError: "consent_required",
            httpStatus: 403,
            consentUrl: "   ");
        var consent = Assert.IsType<ConsentRequiredException>(ex);
        Assert.Null(consent.ConsentUrl);
    }
}
