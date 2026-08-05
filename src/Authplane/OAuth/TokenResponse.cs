namespace Authplane;

/// <summary>
/// OAuth 2.1 Token Endpoint response (RFC 6749) as used by Authplane.
/// </summary>
public sealed class TokenResponse
{
    public string AccessToken { get; }
    public string TokenType { get; }
    public long? ExpiresIn { get; }
    public string? Scope { get; }
    public string? IssuedTokenType { get; }

    /// <summary>
    /// DPoP confirmation key thumbprint from <c>cnf.jkt</c>, if the AS bound
    /// the token to a DPoP key. Null when the token is a plain Bearer.
    /// </summary>
    public string? CnfJkt { get; }

    public TokenResponse(
        string accessToken,
        string tokenType,
        long? expiresIn,
        string? scope,
        string? issuedTokenType = null,
        string? cnfJkt = null)
    {
        AccessToken = accessToken;
        TokenType = tokenType;
        ExpiresIn = expiresIn;
        Scope = scope;
        IssuedTokenType = issuedTokenType;
        CnfJkt = cnfJkt;
    }
}

