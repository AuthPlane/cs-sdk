using System.Security.Cryptography;
using System.Text;

namespace Authplane;

/// <summary>
/// Single source of truth for the SHA-256 + base64url digest used by DPoP
/// outbound proofs (the <c>ath</c> claim, RFC 9449 §4.2) and shared with the
/// inbound verifier when checking the binding. Three near-identical copies
/// existed (DPoPProvider, ES256DpoPSigner, AuthplaneResource); a divergence
/// between any two would have produced an <c>ath</c> mismatch that the
/// verifier silently rejected as a binding failure with no exception path to
/// help debugging.
/// </summary>
internal static class DPoPHashes
{
    /// <summary>
    /// RFC 9449 §4.2 <c>ath</c>: base64url(sha256(access_token_utf8)). The
    /// signer adds this claim to the proof so the resource can verify the
    /// proof is bound to the token presented in the same request.
    /// </summary>
    public static string Ath(string accessToken)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(accessToken));
        return Base64Url.Encode(digest);
    }

    /// <summary>
    /// Hash an arbitrary UTF-8 string with SHA-256 and return the base64url
    /// of the digest. Same primitive as <see cref="Ath"/> but available for
    /// other JOSE-shaped digests (e.g. <c>x5t#S256</c> in the future).
    /// </summary>
    public static string Sha256Base64Url(string value)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Base64Url.Encode(digest);
    }
}
