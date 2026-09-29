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
        // The message ("expired") no longer reaches the wire: the description is
        // the fixed sentence the error code selects.
        Assert.Contains(
            "error_description=\"The access token is missing or not valid for this resource\"",
            header,
            StringComparison.Ordinal);
        Assert.DoesNotContain("expired", header, StringComparison.Ordinal);
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

        // The fixed description carries no quote or backslash to escape, so the
        // message path is exercised through the verbose overload instead — the
        // one way an operator can still put a caller-influenced string here.
        var verbose = AuthplaneErrors.WwwAuthenticate(
            new TokenExpiredException("bad \"token\" with \\ slash"),
            realm: "",
            verboseDescription: true);
        Assert.Contains(
            "error_description=\"bad \\\"token\\\" with \\\\ slash\"",
            verbose,
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

        // As above: the fixed description has no CTL to strip, so the stripping
        // is pinned on the message through the verbose overload.
        var verbose = AuthplaneErrors.WwwAuthenticate(
            new TokenExpiredException("expired\r\nX-Injected: 1\ttab\x7f"),
            realm: "",
            verboseDescription: true);
        Assert.DoesNotContain("\r", verbose, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", verbose, StringComparison.Ordinal);
        Assert.DoesNotContain("\t", verbose, StringComparison.Ordinal);
        Assert.DoesNotContain("\x7f", verbose, StringComparison.Ordinal);
        Assert.Contains("error_description=\"expiredX-Injected: 1tab\"", verbose, StringComparison.Ordinal);
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

    [Fact]
    public void ServerErrorCodeFor_Separates503FromEveryOther5xx()
    {
        // server_error reads as a fault in this resource server. A 503 here is
        // the authorization server being unreachable — transient, and worth a
        // retry — which is what RFC 6749 §5.2's temporarily_unavailable says.
        Assert.Equal("temporarily_unavailable", AuthplaneErrors.ServerErrorCodeFor(503));
        Assert.Equal("server_error", AuthplaneErrors.ServerErrorCodeFor(500));

        // Keyed off the status, so the two exceptions that produce a 503 reach
        // the transient code and CircuitOpenException — 500 by the default arm
        // above — does not.
        Assert.Equal(
            "temporarily_unavailable",
            AuthplaneErrors.ServerErrorCodeFor(AuthplaneErrors.HttpStatus(new JwksFetchException("unreachable"))));
        Assert.Equal(
            "temporarily_unavailable",
            AuthplaneErrors.ServerErrorCodeFor(AuthplaneErrors.HttpStatus(new MetadataFetchException("unreachable"))));
        Assert.Equal(
            "server_error",
            AuthplaneErrors.ServerErrorCodeFor(AuthplaneErrors.HttpStatus(new CircuitOpenException())));
    }

    [Fact]
    public void TemporarilyUnavailable_CarriesASafeDescription()
    {
        var description = AuthplaneErrors.ErrorDescriptionFor(AuthplaneErrors.TemporarilyUnavailableCode);

        Assert.NotEqual(AuthplaneErrors.FallbackErrorDescription, description);
        // The same rule the rest of the table follows: no comma, because a
        // comma separates challenge parameters in a WWW-Authenticate value.
        Assert.DoesNotContain(",", description, StringComparison.Ordinal);
    }

    [Fact]
    public void ErrorResponseBody_For503_NamesTheTransientCode()
    {
        var body = AuthplaneErrors.ErrorResponseBody(AuthplaneErrors.ServerErrorCodeFor(503));

        using var doc = System.Text.Json.JsonDocument.Parse(body);
        Assert.Equal("temporarily_unavailable", doc.RootElement.GetProperty("error").GetString());
        Assert.Equal(
            AuthplaneErrors.ErrorDescriptionFor(AuthplaneErrors.TemporarilyUnavailableCode),
            doc.RootElement.GetProperty("error_description").GetString());
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
    [InlineData("invalid_target", typeof(InvalidTargetException))]
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
    public void MapOAuthError_AccessDenied403_ReturnsAccessDeniedException()
    {
        // authserver 0.2.0 answers a cross-client exchange the Resource has not
        // allow-listed with access_denied + 403. Must not collapse into the
        // bare-401/403 InvalidClient handling or the generic base type.
        var ex = Assert.IsType<AccessDeniedException>(AuthplaneErrors.MapOAuthError(
            oauthError: "access_denied",
            httpStatus: 403,
            errorDescription: "client not allowed to exchange for this resource"));
        Assert.Equal("access_denied", ex.OAuthError);
        Assert.Equal(403, ex.HttpStatus);
        Assert.Equal("client not allowed to exchange for this resource", ex.ErrorDescription);
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

    // -----------------------------------------------------------------------
    // ErrorResponseBody
    // -----------------------------------------------------------------------

    [Fact]
    public void ErrorResponseBody_NeverCarriesTheExceptionMessage()
    {
        // The body reaches a caller who has not authenticated, and the SDK's
        // messages name the failing detail — here the exact audience the
        // resource expects, which is the value a caller needs in order to go
        // request a token for it.
        var json = AuthplaneErrors.ErrorResponseBody(
            AuthplaneErrors.ErrorCodeFor(
                new InvalidClaimsException("aud mismatch: expected https://api.example.com/mcp")));

        Assert.Contains(
            "\"error_description\":\"The access token is missing or not valid for this resource\"",
            json,
            StringComparison.Ordinal);
        Assert.DoesNotContain("api.example.com", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ErrorResponseBody_OmitsTheErrorCodeWhenNoCredentialsWerePresented()
    {
        // The three pre-token 401 paths build a challenge with no `error`
        // parameter, as RFC 6750 §3 requires for a request that carried no
        // authentication information. The body has to make the same omission:
        // §3.1 ties `invalid_request` to a malformed request answered with
        // 400, so naming it here would both misreport the failure and put the
        // body at odds with the header it travels with.
        var json = AuthplaneErrors.ErrorResponseBody();

        Assert.DoesNotContain("\"error\":", json, StringComparison.Ordinal);
        Assert.Equal(
            "{\"error_description\":\"The request did not carry a usable access token\"}",
            json);
    }

    [Fact]
    public void ErrorDescriptionFor_AcceptsNullTheWayErrorResponseBodyDoes()
    {
        // The XML doc invites an adapter to compose a challenge "from a code it
        // already knows", and ErrorResponseBody documents null as the
        // no-credentials case. An adapter holding one nullable code feeds both,
        // so the pair has to answer, not throw: Dictionary.TryGetValue raises
        // ArgumentNullException on a null key.
        Assert.Equal(
            "The request did not carry a usable access token",
            AuthplaneErrors.ErrorDescriptionFor(null));
        Assert.Equal(
            "The request did not carry a usable access token",
            AuthplaneErrors.ErrorDescriptionFor(string.Empty));

        // and the two halves agree on it
        Assert.Contains(
            "\"error_description\":\"" + AuthplaneErrors.ErrorDescriptionFor(null) + "\"",
            AuthplaneErrors.ErrorResponseBody(),
            StringComparison.Ordinal);
    }

    [Fact]
    public void ErrorResponseBody_FallsBackForACodeWithNoRow()
    {
        // use_dpop_nonce is the live case: no sibling SDK carries a row for it,
        // so it takes the contentless fallback rather than a sentence this SDK
        // invented on its own.
        var json = AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.UseDpopNonce);

        Assert.Contains("\"error\":\"use_dpop_nonce\"", json, StringComparison.Ordinal);
        Assert.Contains(
            $"\"error_description\":\"{AuthplaneErrors.FallbackErrorDescription}\"",
            json,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ErrorResponseBody_AgreesWithTheChallengeItTravelsWith()
    {
        // One table, two surfaces: a client reads whichever half it finds, so
        // they must not drift.
        var error = new InsufficientScopeException("missing tools/delete");
        var header = AuthplaneErrors.WwwAuthenticate(error);
        var json = AuthplaneErrors.ErrorResponseBody(AuthplaneErrors.ErrorCodeFor(error));

        Assert.Contains(
            $"error_description=\"{AuthplaneErrors.ErrorDescriptionFor(AuthplaneErrors.ErrorCodeFor(error))}\"",
            header,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"error_description\":\"The access token does not carry the scope this operation requires\"",
            json,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ErrorResponseBody_RestoresTheMessageUnderVerboseDescription()
    {
        // The development escape hatch, and the reason the body is serialized
        // rather than interpolated: JSON escaping has to hold for a message
        // carrying quotes and CRLF.
        var json = AuthplaneErrors.ErrorResponseBody(
            OAuthConstants.ErrorCodes.InvalidToken,
            new TokenExpiredException("bad \"token\"\r\nX-Injected: 1"),
            verboseDescription: true);

        using var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.Equal(
            "bad \"token\"\r\nX-Injected: 1",
            doc.RootElement.GetProperty("error_description").GetString());
    }
}
