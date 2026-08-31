namespace Authplane;

public class AuthplaneException : Exception
{
    public AuthplaneException(string message) : base(message) { }
    public AuthplaneException(string message, Exception inner) : base(message, inner) { }
}

public sealed class TokenMissingException : AuthplaneException
{
    public TokenMissingException(string message) : base(message) { }
}

public sealed class TokenExpiredException : AuthplaneException
{
    public TokenExpiredException(string message) : base(message) { }
}

public sealed class InvalidSignatureException : AuthplaneException
{
    public InvalidSignatureException(string message) : base(message) { }
    public InvalidSignatureException(string message, Exception inner) : base(message, inner) { }
}

public sealed class InvalidClaimsException : AuthplaneException
{
    public InvalidClaimsException(string message) : base(message) { }
    public InvalidClaimsException(string message, Exception inner) : base(message, inner) { }
}

public sealed class InsufficientScopeException : AuthplaneException
{
    public InsufficientScopeException(string message) : base(message) { }
}

public sealed class JwksFetchException : AuthplaneException
{
    public JwksFetchException(string message) : base(message) { }
    public JwksFetchException(string message, Exception inner) : base(message, inner) { }
}

public class MetadataFetchException : AuthplaneException
{
    public MetadataFetchException(string message) : base(message) { }
    public MetadataFetchException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Raised when a required field is missing from AS metadata (e.g. jwks_uri, token_endpoint).</summary>
public sealed class MissingMetadataEndpointException : MetadataFetchException
{
    public MissingMetadataEndpointException(string message) : base(message) { }
    public MissingMetadataEndpointException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>Raised when verification fails for a non-cryptographic runtime reason.</summary>
public class VerifierRuntimeException : AuthplaneException
{
    public VerifierRuntimeException(string message) : base(message) { }
    public VerifierRuntimeException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Raised when an OAuth/OIDC/DPoP protocol message is malformed.</summary>
public class ProtocolException : AuthplaneException
{
    public ProtocolException(string message) : base(message) { }
    public ProtocolException(string message, Exception inner) : base(message, inner) { }
}

// ---------------------------------------------------------------------------
// DPoP errors — all share a DPoPException base so callers can catch all
// DPoP failures as a group.
// ---------------------------------------------------------------------------

public class DPoPException : AuthplaneException
{
    public DPoPException(string message) : base(message) { }
    public DPoPException(string message, Exception inner) : base(message, inner) { }
}

public sealed class DPoPProofMissingException : DPoPException
{
    public DPoPProofMissingException(string message) : base(message) { }
}

public sealed class InvalidDPoPProofException : DPoPException
{
    public InvalidDPoPProofException(string message) : base(message) { }
    public InvalidDPoPProofException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Raised when an inbound request carries more than one <c>DPoP</c> header,
/// so there is no way to know which proof binds the request. RFC 9449
/// §4.3 #1 is a MUST-level receiving-server check; the spec-correct
/// response per §7.1 is HTTP 401 with a <c>DPoP</c>-scheme challenge
/// carrying <c>error="invalid_dpop_proof"</c>. Only this §4.3 rejection
/// follows the §7.1 prescription — the other DPoP failures keep the
/// <c>invalid_token</c> code.
/// </summary>
public sealed class DPoPMultipleProofsException : DPoPException
{
    public DPoPMultipleProofsException(string message) : base(message) { }
}

public sealed class DPoPBindingMismatchException : DPoPException
{
    public DPoPBindingMismatchException(string message) : base(message) { }
}

public sealed class DPoPReplayDetectedException : DPoPException
{
    public DPoPReplayDetectedException(string message) : base(message) { }
}

/// <summary>
/// Raised when the resource server's inbound nonce policy rejects a DPoP
/// proof: the <c>nonce</c> claim is missing, was not issued by this server,
/// or has aged out of the acceptance window. RFC 9449 §9 prescribes the
/// response — HTTP 401 with a <c>DPoP</c>-scheme challenge carrying
/// <c>error="use_dpop_nonce"</c> and a fresh nonce in the <c>DPoP-Nonce</c>
/// response header; the client re-signs its proof with that nonce and
/// retries. The nonce to advertise is carried in <see cref="NewNonce"/>.
/// Deliberately not a subclass of <see cref="InvalidDPoPProofException"/>:
/// §7.1's <c>invalid_dpop_proof</c> tells the client its proof is broken,
/// while <c>use_dpop_nonce</c> says the proof is fine and only the nonce
/// needs refreshing — conflating the two breaks the retry choreography.
/// </summary>
public sealed class DPoPNonceRequiredException : DPoPException
{
    /// <summary>
    /// Fresh nonce the adapter must emit in the <c>DPoP-Nonce</c> response
    /// header alongside the 401 challenge (RFC 9449 §9).
    /// <see cref="AuthplaneErrors.ResponseHeaders"/> surfaces it under the
    /// right header name so adapters need not special-case this type.
    /// </summary>
    public string NewNonce { get; }

    public DPoPNonceRequiredException(string message, string newNonce) : base(message)
    {
        ArgumentNullException.ThrowIfNull(newNonce);
        // Enforced here — once, for every adapter — rather than at each
        // header-write site: the value is emitted verbatim as the DPoP-Nonce
        // header, and a custom IDPoPNonceIssuer is third-party code. Same
        // defence-in-depth stance as EscapeQuotedString below, except issuer
        // output is a contract violation to reject, not input to sanitise.
        if (!DPoPNonceSyntax.IsValid(newNonce))
        {
            throw new ArgumentException(
                "newNonce must satisfy RFC 9449 §8.1 NQCHAR syntax (non-empty; no control characters, whitespace, '\"' or '\\'): it is emitted verbatim as the DPoP-Nonce response header value.",
                nameof(newNonce));
        }

        NewNonce = newNonce;
    }
}

/// <summary>
/// Raised when a resource has not opted into inbound DPoP but the request
/// carries a DPoP signal — either a DPoP-bound access token (<c>cnf.jkt</c>)
/// or a <c>DPoP</c> proof header. RFC 9449 §7 forbids silently downgrading
/// to bearer, and ad-hoc default DPoP policies would be invisible in PRM,
/// so we reject these requests up-front.
/// </summary>
public sealed class DPoPNotSupportedException : DPoPException
{
    public DPoPNotSupportedException(string message) : base(message) { }
}

public sealed class TokenRevokedException : AuthplaneException
{
    public TokenRevokedException(string message) : base(message) { }
    public TokenRevokedException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when the AS circuit breaker is open and outbound token/introspection calls are shed.
/// Inherits from <see cref="AuthplaneAuthClientException"/> so a single
/// <c>catch (AuthplaneAuthClientException)</c> handles every "talking to the AS failed"
/// path (transport, circuit, malformed wire, typed RFC 6749 errors).
/// </summary>
public sealed class CircuitOpenException : AuthplaneAuthClientException
{
    public CircuitOpenException()
        : base("authplane: circuit breaker is open — AS calls temporarily suspended")
    {
    }
}

// ---------------------------------------------------------------------------
// OAuth client / token operation errors
// ---------------------------------------------------------------------------

/// <summary>
/// Umbrella base for failures that originate from interacting with the
/// authorization server — wire-protocol errors, malformed responses, and
/// transport-level rejections. Callers can
/// <c>catch (AuthplaneAuthClientException)</c> to handle "anything went wrong
/// talking to the AS" without enumerating every typed subclass.
/// </summary>
public class AuthplaneAuthClientException : AuthplaneException
{
    public AuthplaneAuthClientException(string message) : base(message) { }
    public AuthplaneAuthClientException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Base exception for failures of OAuth client operations (token requests, introspection,
/// token exchange, revocation). Carries the wire-level OAuth <c>error</c> value and the HTTP
/// status code when available.
/// </summary>
public class AuthplaneTokenRequestException : AuthplaneAuthClientException
{
    public string? OAuthError { get; }

    /// <summary>RFC 6749 §5.2 <c>error_description</c> — human-readable detail from the AS.</summary>
    public string? ErrorDescription { get; }

    /// <summary>RFC 6749 §5.2 <c>error_uri</c> — URI identifying a page with error info.</summary>
    public string? ErrorUri { get; }

    public int? HttpStatus { get; }

    public AuthplaneTokenRequestException(string message)
        : this(message, oauthError: null, httpStatus: null)
    {
    }

    public AuthplaneTokenRequestException(string message, string? oauthError, int? httpStatus,
        string? errorDescription = null, string? errorUri = null)
        : base(message)
    {
        OAuthError = oauthError;
        HttpStatus = httpStatus;
        ErrorDescription = errorDescription;
        ErrorUri = errorUri;
    }
}

// Typed subclasses for each RFC 6749 §5.2 error code.
// Callers can catch specific codes instead of switching on OAuthError string.

public sealed class InvalidClientException : AuthplaneTokenRequestException
{
    public InvalidClientException(string message, int? httpStatus,
        string? errorDescription = null, string? errorUri = null)
        : base(message, OAuthConstants.ErrorCodes.InvalidClient, httpStatus, errorDescription, errorUri) { }
}

public sealed class UnauthorizedClientException : AuthplaneTokenRequestException
{
    public UnauthorizedClientException(string message, int? httpStatus,
        string? errorDescription = null, string? errorUri = null)
        : base(message, "unauthorized_client", httpStatus, errorDescription, errorUri) { }
}

public sealed class InvalidGrantException : AuthplaneTokenRequestException
{
    public InvalidGrantException(string message, int? httpStatus,
        string? errorDescription = null, string? errorUri = null)
        : base(message, OAuthConstants.ErrorCodes.InvalidGrant, httpStatus, errorDescription, errorUri) { }
}

public sealed class InvalidScopeException : AuthplaneTokenRequestException
{
    public InvalidScopeException(string message, int? httpStatus,
        string? errorDescription = null, string? errorUri = null)
        : base(message, "invalid_scope", httpStatus, errorDescription, errorUri) { }
}

public sealed class InvalidRequestException : AuthplaneTokenRequestException
{
    public InvalidRequestException(string message, int? httpStatus,
        string? errorDescription = null, string? errorUri = null)
        : base(message, "invalid_request", httpStatus, errorDescription, errorUri) { }
}

public sealed class UnsupportedGrantTypeException : AuthplaneTokenRequestException
{
    public UnsupportedGrantTypeException(string message, int? httpStatus,
        string? errorDescription = null, string? errorUri = null)
        : base(message, "unsupported_grant_type", httpStatus, errorDescription, errorUri) { }
}

/// <summary>
/// Thrown when the AS surfaces a consent-required signal (typically as part of an MCP
/// URL-elicitation flow). Adapters translate this into a framework-specific error response.
/// </summary>
public sealed class ConsentRequiredException : AuthplaneTokenRequestException
{
    public string ServiceId { get; }

    public string CauseDetail { get; }

    public string? ConsentUrl { get; }

    public ConsentRequiredException(
        string message,
        string oauthError,
        int? httpStatus,
        string serviceId,
        string causeDetail,
        string? consentUrl)
        : base(message, oauthError, httpStatus)
    {
        ServiceId = string.IsNullOrWhiteSpace(serviceId) ? "unknown_service" : serviceId;
        CauseDetail = string.IsNullOrWhiteSpace(causeDetail) ? message : causeDetail;
        ConsentUrl = string.IsNullOrWhiteSpace(consentUrl) ? null : consentUrl;
    }
}

/// <summary>
/// Wraps a malformed or unexpected token endpoint response body.
/// Inherits from <see cref="AuthplaneAuthClientException"/> so callers can
/// catch all AS-interaction failures as a single group.
/// </summary>
public sealed class AuthplaneTokenResponseParsingException : AuthplaneAuthClientException
{
    public AuthplaneTokenResponseParsingException(string message) : base(message) { }
    public AuthplaneTokenResponseParsingException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Wraps a malformed or unexpected introspection endpoint response body.
/// Inherits from <see cref="AuthplaneAuthClientException"/> so callers can
/// catch all AS-interaction failures as a single group.
/// </summary>
public sealed class AuthplaneIntrospectionResponseParsingException : AuthplaneAuthClientException
{
    public AuthplaneIntrospectionResponseParsingException(string message) : base(message) { }
    public AuthplaneIntrospectionResponseParsingException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// 5xx-class failure from the authorization server.
/// Inherits from <see cref="AuthplaneAuthClientException"/> so a single
/// <c>catch (AuthplaneAuthClientException)</c> handles every "talking to the AS failed"
/// path (transport, circuit, malformed wire, typed RFC 6749 errors).
/// </summary>
public sealed class ServerError : AuthplaneAuthClientException
{
    public ServerError(string message) : base(message) { }
}

// ---------------------------------------------------------------------------
// Error mapping helpers — WwwAuthenticate / HttpStatus
// ---------------------------------------------------------------------------

public static class AuthplaneErrors
{
    /// <summary>
    /// Build an RFC 6750 §3 <c>WWW-Authenticate</c> header value.
    /// DPoP errors use the <c>DPoP</c> scheme — except
    /// <see cref="DPoPNotSupportedException"/>, which uses <c>Bearer</c>;
    /// all others use <c>Bearer</c>.
    /// A framework-agnostic adapter builds a complete error response from
    /// three calls: <see cref="HttpStatus"/> for the status code, this
    /// helper for the challenge, and <see cref="ResponseHeaders"/> for the
    /// extra headers some errors require — a
    /// <see cref="DPoPNonceRequiredException"/> challenge without its
    /// <c>DPoP-Nonce</c> header is unsatisfiable (RFC 9449 §9).
    /// </summary>
    public static string WwwAuthenticate(AuthplaneException error, string realm = "")
    {
        var errorCode = error switch
        {
            InsufficientScopeException => OAuthConstants.ErrorCodes.InsufficientScope,
            // RFC 9449 §7.1 prescribes `invalid_dpop_proof` for §4.3
            // cardinality rejections, and §9 prescribes `use_dpop_nonce`
            // for nonce-policy rejections. This helper only builds the
            // challenge value — the DPoP-Nonce response header the §9
            // choreography also requires comes from ResponseHeaders, which
            // the adapter (having the response in hand) must apply. The
            // other DPoP failures keep `invalid_token`.
            DPoPMultipleProofsException => OAuthConstants.ErrorCodes.InvalidDPoPProof,
            DPoPNonceRequiredException => OAuthConstants.ErrorCodes.UseDpopNonce,
            _ => OAuthConstants.ErrorCodes.InvalidToken,
        };
        // DPoPNotSupportedException is thrown by a resource that does NOT
        // accept DPoP — answering it with a `DPoP …` challenge would tell
        // the client to negotiate DPoP and have the next request rejected
        // the same way. Bearer breaks that loop; it's the same routing the
        // MCP middleware applies through its default challenge scheme.
        var scheme = error is DPoPException and not DPoPNotSupportedException
            ? OAuthConstants.AuthSchemes.DPoP
            : OAuthConstants.AuthSchemes.Bearer;

        var parts = new System.Collections.Generic.List<string>();
        if (!string.IsNullOrEmpty(realm))
        {
            parts.Add($"realm=\"{EscapeQuotedString(realm)}\"");
        }
        parts.Add($"error=\"{errorCode}\"");
        parts.Add($"error_description=\"{EscapeQuotedString(error.Message)}\"");
        return $"{scheme} " + string.Join(", ", parts);
    }

    /// <summary>
    /// RFC 7235 §2.2.1 quoted-string escape: backslash-prefix any embedded
    /// <c>"</c> or <c>\</c>. SDK-generated messages don't contain these today,
    /// but caller-supplied realms or error.Message values might — without
    /// escaping a stray <c>"</c> would terminate the quoted-string and corrupt
    /// the auth-param list.
    ///
    /// RFC 7230/9110 also forbids all CTLs (0x00-0x1F and 0x7F) in header
    /// field values. Strip them before escaping so attacker-controlled
    /// fragments of <c>error.Message</c> or <c>realm</c> cannot inject
    /// continuation lines, tabs, or other control characters into the
    /// WWW-Authenticate header. CR/LF are the canonical injection vector; the
    /// rest are defence in depth against proxies/CDNs with looser parsers.
    /// This mirrors the same CTL-stripping invariant enforced by the MCP
    /// middleware's EscapeChallengeString so both builders for this header agree.
    /// </summary>
    private static string EscapeQuotedString(string value)
    {
        var sb = new System.Text.StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (c <= 0x1F || c == 0x7F)
            {
                continue;
            }

            if (c == '\\')
            {
                sb.Append("\\\\");
            }
            else if (c == '"')
            {
                sb.Append("\\\"");
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Map an <see cref="AuthplaneException"/> to an HTTP status code.
    /// Pair with <see cref="WwwAuthenticate"/> and
    /// <see cref="ResponseHeaders"/> when building an error response.
    /// </summary>
    public static int HttpStatus(AuthplaneException error) => error switch
    {
        InsufficientScopeException => 403,
        JwksFetchException => 503,
        MetadataFetchException => 503,
        TokenMissingException => 401,
        TokenExpiredException => 401,
        InvalidSignatureException => 401,
        InvalidClaimsException => 401,
        TokenRevokedException => 401,
        DPoPException => 401,
        ProtocolException => 500,
        VerifierRuntimeException => 500,
        _ => 500,
    };

    private static readonly IReadOnlyDictionary<string, string> NoResponseHeaders =
        System.Collections.ObjectModel.ReadOnlyDictionary<string, string>.Empty;

    /// <summary>
    /// Extra response headers a correct error response must carry alongside
    /// the <see cref="HttpStatus"/> code and <see cref="WwwAuthenticate"/>
    /// challenge. Today the only entry is <c>DPoP-Nonce</c> for
    /// <see cref="DPoPNonceRequiredException"/>: RFC 9449 §9 requires the
    /// fresh nonce on the <c>use_dpop_nonce</c> 401, and without it a
    /// conformant client has nothing to re-sign with and burns its single
    /// §8 retry. Every other error maps to an empty dictionary. Adapters
    /// should copy every entry onto the response rather than special-casing
    /// exception types — the set grows if a future error requires a header.
    /// The built-in MCP middleware consumes this same mapping.
    /// </summary>
    public static IReadOnlyDictionary<string, string> ResponseHeaders(AuthplaneException error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return error switch
        {
            DPoPNonceRequiredException nonceRequired => new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [OAuthConstants.Headers.DPoPNonce] = nonceRequired.NewNonce,
            },
            _ => NoResponseHeaders,
        };
    }

    /// <summary>
    /// Map an RFC 6749 §5.2 OAuth error response onto a typed
    /// <see cref="AuthplaneTokenRequestException"/> subclass.
    /// Public so callers parsing
    /// OAuth error responses outside the built-in client (their own resource-server
    /// logic, custom middleware, etc.) can reuse the same mapping. The built-in
    /// <c>OAuthHttpClient.BuildTokenRequestException</c> delegates here.
    /// </summary>
    /// <param name="oauthError">RFC 6749 §5.2 <c>error</c> code, or <c>null</c> if the body did not carry one.</param>
    /// <param name="httpStatus">HTTP status returned by the AS.</param>
    /// <param name="errorDescription">RFC 6749 §5.2 <c>error_description</c>.</param>
    /// <param name="errorUri">RFC 6749 §5.2 <c>error_uri</c>.</param>
    /// <param name="serviceId">Authplane-specific <c>service_id</c> for consent-required.</param>
    /// <param name="cause">Authplane-specific <c>cause</c> detail for consent-required.</param>
    /// <param name="consentUrl">Authplane-specific <c>consent_url</c> for consent-required.</param>
    /// <param name="message">Overrides the default message text.</param>
    public static AuthplaneAuthClientException MapOAuthError(
        string? oauthError,
        int httpStatus,
        string? errorDescription = null,
        string? errorUri = null,
        string? serviceId = null,
        string? cause = null,
        string? consentUrl = null,
        string? message = null)
    {
        var suffix = string.IsNullOrWhiteSpace(oauthError) ? string.Empty : $", error={oauthError}";
        var defaultMessage = message ?? $"authplane: token endpoint returned HTTP {httpStatus}{suffix}.";

        // Status >= 500 is checked BEFORE the error-code
        // switch (including consent_required / interaction_required): a 5xx is
        // server-side regardless of whatever (often misleading) error code came
        // back from a misbehaving AS, so it surfaces as ServerError.
        if (httpStatus >= 500)
        {
            return new ServerError(defaultMessage);
        }

        if (string.Equals(oauthError, OAuthConstants.ErrorCodes.ConsentRequired, StringComparison.Ordinal) ||
            string.Equals(oauthError, OAuthConstants.ErrorCodes.InteractionRequired, StringComparison.Ordinal))
        {
            var resolvedServiceId = string.IsNullOrWhiteSpace(serviceId) ? "unknown_service" : serviceId!;
            var causeDetail = string.IsNullOrWhiteSpace(cause)
                ? (errorDescription ?? oauthError!)
                : cause!;
            var msg = message
                ?? errorDescription
                ?? $"authplane: token endpoint returned HTTP {httpStatus}, error={oauthError}.";
            return new ConsentRequiredException(
                message: msg,
                oauthError: oauthError!,
                httpStatus: httpStatus,
                serviceId: resolvedServiceId,
                causeDetail: causeDetail,
                consentUrl: consentUrl);
        }

        // A bare 401 with no `error` body is an authentication
        // failure on the client credentials — InvalidClientException. Plain
        // AuthplaneTokenRequestException would mask the typed handle callers
        // catch.
        if (httpStatus == 401 && string.IsNullOrWhiteSpace(oauthError))
        {
            return new InvalidClientException(defaultMessage, httpStatus, errorDescription, errorUri);
        }

        return oauthError switch
        {
            OAuthConstants.ErrorCodes.InvalidClient => new InvalidClientException(defaultMessage, httpStatus, errorDescription, errorUri),
            OAuthConstants.ErrorCodes.UnauthorizedClient => new UnauthorizedClientException(defaultMessage, httpStatus, errorDescription, errorUri),
            OAuthConstants.ErrorCodes.InvalidGrant => new InvalidGrantException(defaultMessage, httpStatus, errorDescription, errorUri),
            OAuthConstants.ErrorCodes.InvalidScope => new InvalidScopeException(defaultMessage, httpStatus, errorDescription, errorUri),
            OAuthConstants.ErrorCodes.InvalidRequest => new InvalidRequestException(defaultMessage, httpStatus, errorDescription, errorUri),
            OAuthConstants.ErrorCodes.UnsupportedGrantType => new UnsupportedGrantTypeException(defaultMessage, httpStatus, errorDescription, errorUri),
            _ => new AuthplaneTokenRequestException(defaultMessage, oauthError, httpStatus, errorDescription, errorUri),
        };
    }
}

