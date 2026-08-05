using System.Text.Json;

namespace Authplane;

/// <summary>
/// JSON parsers for token and introspection endpoint responses. Throws the typed
/// <c>Authplane*ResponseParsingException</c> on malformed payloads.
/// </summary>
internal static class OAuthResponseParser
{
    public static TokenResponse ParseTokenResponse(
        string json,
        bool expectDPoP = false,
        bool requireIssuedTokenType = false)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new AuthplaneTokenResponseParsingException("token response must be a JSON object.");
            }

            var root = doc.RootElement;

            if (!root.TryGetProperty("access_token", out var accessTokenProp) ||
                accessTokenProp.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(accessTokenProp.GetString()))
            {
                throw new AuthplaneTokenResponseParsingException("token response missing required field access_token.");
            }

            if (!root.TryGetProperty("token_type", out var tokenTypeProp) ||
                tokenTypeProp.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(tokenTypeProp.GetString()))
            {
                throw new AuthplaneTokenResponseParsingException("token response missing required field token_type.");
            }

            var accessToken = accessTokenProp.GetString()!;
            var tokenType = tokenTypeProp.GetString()!;
            if (!string.Equals(tokenType, "Bearer", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(tokenType, "DPoP", StringComparison.OrdinalIgnoreCase))
            {
                throw new AuthplaneTokenResponseParsingException("authplane: token response unsupported token_type.");
            }

            // RFC 9449 §5 confused-deputy check: if we sent a DPoP proof, the AS MUST
            // respond with token_type=DPoP. A Bearer response means the AS ignored the
            // proof and the token is NOT sender-constrained.
            if (expectDPoP && string.Equals(tokenType, "Bearer", StringComparison.OrdinalIgnoreCase))
            {
                throw new AuthplaneTokenResponseParsingException(
                    "authplane: sent DPoP proof but AS responded with token_type=Bearer " +
                    "(RFC 9449 §5 confused-deputy — AS may have ignored the DPoP proof).");
            }

            long? expiresIn = null;
            if (root.TryGetProperty("expires_in", out var expiresInProp))
            {
                if (expiresInProp.ValueKind != JsonValueKind.Number)
                {
                    throw new AuthplaneTokenResponseParsingException("authplane: token response expires_in must be a non-negative integer when present.");
                }

                if (!expiresInProp.TryGetInt64(out var expiresInVal) || expiresInVal < 0)
                {
                    throw new AuthplaneTokenResponseParsingException("authplane: token response expires_in must be a non-negative integer when present.");
                }

                expiresIn = expiresInVal;
            }

            var scope = root.GetStringOrNull(OAuthConstants.Params.Scope);
            var issuedTokenType = root.GetStringOrNull("issued_token_type");

            // RFC 8693 §2.2.1: issued_token_type is REQUIRED in token-exchange responses.
            if (requireIssuedTokenType && string.IsNullOrWhiteSpace(issuedTokenType))
            {
                throw new AuthplaneTokenResponseParsingException(
                    "authplane: token-exchange response missing required field issued_token_type (RFC 8693 §2.2.1).");
            }

            // Extract cnf.jkt if present (DPoP-bound token). The "cnf" object
            // is itself a JsonElement we can recurse into with the helper.
            string? cnfJkt = null;
            if (root.TryGetProperty(OAuthConstants.JwtClaims.Cnf, out var cnfProp))
            {
                cnfJkt = cnfProp.GetStringOrNull(OAuthConstants.JwtClaims.Jkt);
            }

            return new TokenResponse(accessToken, tokenType, expiresIn, scope, issuedTokenType, cnfJkt);
        }
        catch (AuthplaneTokenResponseParsingException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AuthplaneTokenResponseParsingException("authplane: failed to parse token response.", ex);
        }
    }

    public static IntrospectionResponse ParseIntrospectionResponse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new AuthplaneIntrospectionResponseParsingException("introspection response must be a JSON object.");
            }

            var root = doc.RootElement;

            // RFC 7662 §2.2 — missing "active" defaults to false (inactive).
            var active = root.GetBoolOrNull("active") ?? false;

            // aud is the only polymorphic field: per RFC 7519 §4.1.3 it may be
            // either a single string or an array of strings. Try the string
            // shape first, fall back to the array helper.
            IReadOnlyList<string>? aud = null;
            var audSingle = root.GetStringOrNull(OAuthConstants.JwtClaims.Aud);
            if (!string.IsNullOrWhiteSpace(audSingle))
            {
                aud = new[] { audSingle };
            }
            else
            {
                var audArray = root.GetStringArrayOrEmpty(OAuthConstants.JwtClaims.Aud);
                if (audArray.Count > 0)
                {
                    aud = audArray;
                }
            }

            var agentChain = root.GetStringArrayOrEmpty("agent_chain");

            // RFC 9449 §6.2 / RFC 7662 confirmation claim. Preserve the raw
            // `cnf` object so callers can read extension members
            // (`x5t#S256`, future RFC 9449 additions) verbatim, and derive
            // the convenience `cnf_jkt` accessor from `cnf.jkt`. Non-object
            // `cnf` values are dropped to keep the typed shape honest,
            // mirroring the `TokenResponse` cnf extraction above.
            // `JsonElement.Clone()` detaches from the using-scoped
            // `JsonDocument` so the value survives this method.
            JsonElement? cnf = null;
            string? cnfJkt = null;
            if (root.TryGetProperty(OAuthConstants.JwtClaims.Cnf, out var cnfProp)
                && cnfProp.ValueKind == JsonValueKind.Object)
            {
                cnf = cnfProp.Clone();
                cnfJkt = cnfProp.GetStringOrNull(OAuthConstants.JwtClaims.Jkt);
            }

            return new IntrospectionResponse(
                active: active,
                scope: root.GetStringOrNull(OAuthConstants.Params.Scope),
                clientId: root.GetStringOrNull(OAuthConstants.JwtClaims.ClientId),
                sub: root.GetStringOrNull(OAuthConstants.JwtClaims.Sub),
                tokenType: root.GetStringOrNull("token_type"),
                iss: root.GetStringOrNull(OAuthConstants.JwtClaims.Iss),
                aud: aud,
                exp: root.GetInt64OrNull(OAuthConstants.JwtClaims.Exp),
                iat: root.GetInt64OrNull(OAuthConstants.JwtClaims.Iat),
                jti: root.GetStringOrNull(OAuthConstants.JwtClaims.Jti),
                agentId: root.GetStringOrNull("agent_id"),
                agentChain: agentChain.Count > 0 ? agentChain : null,
                cnf: cnf,
                cnfJkt: cnfJkt);
        }
        catch (AuthplaneIntrospectionResponseParsingException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new AuthplaneIntrospectionResponseParsingException(
                "authplane: failed to parse introspection response.",
                ex);
        }
    }
}
