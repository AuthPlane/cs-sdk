namespace Authplane;

/// <summary>
/// Single source of truth for the unpadded base64url encoding used throughout
/// the SDK (RFC 7515 / RFC 7638 / RFC 9449). Previously inlined as
/// <c>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')</c>
/// in four different files; if one copy was tweaked (e.g. to drop the
/// padding-strip step or to forget a substitution) DPoP <c>cnf.jkt</c> binding
/// and the <c>ath</c> claim would silently diverge between the signer and the
/// verifier sides, breaking the proof check without raising any exception.
/// </summary>
internal static class Base64Url
{
    /// <summary>
    /// Encode <paramref name="bytes"/> as RFC 4648 §5 base64url (URL-safe
    /// alphabet, no padding). Used for JWS payload encoding, JWK thumbprints,
    /// DPoP <c>ath</c>, and any other JOSE-shaped output.
    /// </summary>
    public static string Encode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
