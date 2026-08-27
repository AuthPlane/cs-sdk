namespace Authplane;

/// <summary>
/// RFC 9449 §8.1 nonce syntax: one or more <c>NQCHAR</c>s (RFC 6749
/// Appendix A — <c>%x21 / %x23-5B / %x5D-7E</c>, i.e. printable ASCII
/// excluding space, <c>"</c> and <c>\</c>). The single check shared by
/// <see cref="DPoPNonceRequiredException"/> (the 401 path) and
/// <see cref="VerifiedClaims.NextDPoPNonce"/> (the success/rotation path),
/// so a misbehaving <see cref="IDPoPNonceIssuer"/> is rejected as a contract
/// violation before its output can reach a response header.
/// </summary>
internal static class DPoPNonceSyntax
{
    public static bool IsValid(string value)
    {
        if (value.Length == 0)
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c is < '\x21' or > '\x7E' or '"' or '\\')
            {
                return false;
            }
        }

        return true;
    }
}
