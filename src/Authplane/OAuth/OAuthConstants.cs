namespace Authplane;

/// <summary>
/// Well-known OAuth 2.x / RFC 9449 / RFC 9728 string constants.
/// Holds parameter names, error codes,
/// header names, MIME types, JWT / DPoP / JWK claim names, well-known
/// document paths, and JOSE algorithm identifiers. New entries land here
/// the first time the same literal is needed in a second site.
/// </summary>
public static class OAuthConstants
{
    // Grant types (RFC 6749 / RFC 8693)
    public const string GrantTypeClientCredentials = "client_credentials";
    public const string GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";

    // Token types (RFC 8693)
    public const string TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";
    public const string TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";
    public const string TokenTypeIdToken = "urn:ietf:params:oauth:token-type:id_token";

    // Token type hints (RFC 7009, RFC 7662)
    public const string TokenTypeHintAccessToken = "access_token";
    public const string TokenTypeHintRefreshToken = "refresh_token";

    /// <summary>
    /// OAuth 2.0 / RFC 8693 form-body parameter names. Previously inlined
    /// as string literals across OAuthOperations and OAuthHttpClient.
    /// </summary>
    public static class Params
    {
        public const string GrantType = "grant_type";
        public const string SubjectToken = "subject_token";
        public const string SubjectTokenType = "subject_token_type";
        public const string ActorToken = "actor_token";
        public const string ActorTokenType = "actor_token_type";
        public const string RequestedTokenType = "requested_token_type";
        public const string Token = "token";
        public const string TokenTypeHint = "token_type_hint";
        public const string Scope = "scope";
        public const string Resource = "resource";
        public const string Audience = "audience";
    }

    /// <summary>
    /// OAuth 2.0 / RFC 6750 / RFC 9449 / RFC 7009 error codes. Previously
    /// duplicated between Errors.MapOAuthError, CircuitPolicy.OAuthErrorsNoCircuit,
    /// OAuthHttpClient's use_dpop_nonce detection, and AuthplaneMcpAuthExtensions.
    /// </summary>
    public static class ErrorCodes
    {
        public const string InvalidToken = "invalid_token";
        public const string InsufficientScope = "insufficient_scope";
        public const string InvalidDPoPProof = "invalid_dpop_proof";
        public const string UseDpopNonce = "use_dpop_nonce";
        public const string ConsentRequired = "consent_required";
        public const string InteractionRequired = "interaction_required";
        public const string InvalidGrant = "invalid_grant";
        public const string InvalidScope = "invalid_scope";
        public const string InvalidRequest = "invalid_request";
        public const string InvalidClient = "invalid_client";
        public const string UnauthorizedClient = "unauthorized_client";
        public const string ServerError = "server_error";
        public const string UnsupportedGrantType = "unsupported_grant_type";
        public const string UnsupportedTokenType = "unsupported_token_type";
        public const string DPoPReplayDetected = "dpop_replay_detected";
        public const string DPoPBindingMismatch = "dpop_binding_mismatch";
        public const string DPoPProofMissing = "dpop_proof_missing";
    }

    /// <summary>HTTP header names this SDK reads or writes.</summary>
    public static class Headers
    {
        public const string Authorization = "Authorization";
        public const string DPoP = "DPoP";
        public const string DPoPNonce = "DPoP-Nonce";
        public const string WwwAuthenticate = "WWW-Authenticate";
        public const string Accept = "Accept";
        public const string ContentType = "Content-Type";
        public const string CacheControl = "Cache-Control";
    }

    /// <summary>HTTP scheme prefixes and media types.</summary>
    public static class MediaTypes
    {
        public const string Json = "application/json";
        public const string FormUrlEncoded = "application/x-www-form-urlencoded";
    }

    /// <summary>Authorization scheme names.</summary>
    public static class AuthSchemes
    {
        public const string Bearer = "Bearer";
        public const string DPoP = "DPoP";
        public const string Basic = "Basic";
    }

    /// <summary>RFC 8414 / RFC 9728 / OIDC well-known document paths.</summary>
    public static class WellKnownPaths
    {
        public const string OAuthAuthorizationServer = "/.well-known/oauth-authorization-server";
        public const string OpenIdConfiguration = "/.well-known/openid-configuration";
        public const string OAuthProtectedResource = "/.well-known/oauth-protected-resource";
    }

    /// <summary>JOSE algorithm identifiers (RFC 7518).</summary>
    public static class JoseAlgorithms
    {
        public const string ES256 = "ES256";
        public const string RS256 = "RS256";
    }

    /// <summary>Standard JWT claim names (RFC 7519, RFC 9068).</summary>
    internal static class JwtClaims
    {
        public const string Iss = "iss";
        public const string Sub = "sub";
        public const string Aud = "aud";
        public const string Exp = "exp";
        public const string Iat = "iat";
        public const string Nbf = "nbf";
        public const string Jti = "jti";
        public const string Cnf = "cnf";
        public const string Jkt = "jkt";
        public const string ClientId = "client_id";
        public const string Scope = "scope";
        public const string Alg = "alg";
        public const string Kid = "kid";
        public const string Typ = "typ";
        public const string Jwk = "jwk";
    }

    /// <summary>RFC 9449 DPoP-proof claim names.</summary>
    internal static class DPoPClaims
    {
        public const string Htm = "htm";
        public const string Htu = "htu";
        public const string Ath = "ath";
        public const string Nonce = "nonce";
        public const string TypDPoPJwt = "dpop+jwt";
    }

    /// <summary>RFC 7517 JWK parameter names + RFC 7518 algorithm values.</summary>
    internal static class JwkParams
    {
        public const string Kty = "kty";
        public const string Crv = "crv";
        public const string X = "x";
        public const string Y = "y";
        public const string E = "e";
        public const string N = "n";
        public const string KtyEc = "EC";
        public const string KtyRsa = "RSA";
        public const string CrvP256 = "P-256";
    }
}
