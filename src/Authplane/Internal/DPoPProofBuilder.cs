using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Authplane;

/// <summary>
/// Single source of truth for RFC 9449 proof JWT construction. Used to be
/// duplicated between <see cref="DPoPProvider"/> (configurable TTL,
/// EC-or-RSA) and the ES256 inline signer (hard-coded 300s TTL, ES256-only);
/// both copies built the same header (<c>typ=dpop+jwt</c>, <c>alg</c>,
/// <c>jwk</c>) and the same payload (<c>htm</c>, <c>htu</c>, <c>iat</c>,
/// <c>exp</c>, <c>jti</c>, optional <c>nonce</c>/<c>ath</c>). The two had
/// already diverged on the TTL — a caller who raised the provider's TTL
/// would still have a fallback ES256 signer emitting 300s proofs.
/// </summary>
internal static class DPoPProofBuilder
{
    /// <summary>
    /// Build and sign a DPoP proof JWT. Caller supplies the
    /// <see cref="SigningCredentials"/> (ES256 / RS256) and the public JWK
    /// to embed in the header; this method enforces <c>htm</c>
    /// normalisation, <c>htu</c> canonicalisation, <c>iat</c>/<c>exp</c>
    /// computation, fresh <c>jti</c>, and optional <c>nonce</c>/<c>ath</c>.
    /// </summary>
    public static string Build(
        SigningCredentials creds,
        IReadOnlyDictionary<string, object> publicJwk,
        string method,
        string url,
        long proofTtlSeconds,
        DPoPProofOptions? options)
    {
        ArgumentNullException.ThrowIfNull(creds);
        ArgumentNullException.ThrowIfNull(publicJwk);
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        if (proofTtlSeconds <= 0)
        {
            throw new ArgumentException("proofTtlSeconds must be positive.", nameof(proofTtlSeconds));
        }

        var nowSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString("n");
        var htu = DPoPHtu.Normalize(url);

        var header = new JwtHeader(creds);
        header["typ"] = "dpop+jwt";
        header["jwk"] = publicJwk;

        // RFC 9449 §4.2: htm MUST be the HTTP method in uppercase form. An
        // ES256 inline signer used to forward the caller's case verbatim,
        // producing proofs a strict verifier rejected.
        var payload = new JwtPayload
        {
            { "htm", method.ToUpperInvariant() },
            { "htu", htu },
            { "iat", nowSeconds },
            { "exp", nowSeconds + proofTtlSeconds },
            { "jti", jti }
        };

        if (!string.IsNullOrWhiteSpace(options?.Nonce))
        {
            payload.Add("nonce", options!.Nonce);
        }

        if (!string.IsNullOrWhiteSpace(options?.AccessToken))
        {
            payload.Add("ath", DPoPHashes.Ath(options!.AccessToken!));
        }

        var token = new JwtSecurityToken(header, payload);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
