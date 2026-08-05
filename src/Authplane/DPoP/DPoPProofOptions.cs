namespace Authplane;

public sealed class DPoPProofOptions
{
    public string? Nonce { get; }
    public string? AccessToken { get; }

    public DPoPProofOptions(string? nonce = null, string? accessToken = null)
    {
        Nonce = nonce;
        AccessToken = accessToken;
    }
}

