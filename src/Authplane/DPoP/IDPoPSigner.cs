namespace Authplane;

public interface IDPoPSigner
{
    /// <summary>
    /// Generate a DPoP proof JWT for an outbound request.
    /// </summary>
    Task<string> GenerateProofAsync(
        string method,
        string url,
        DPoPProofOptions? options,
        CancellationToken cancellationToken);

    /// <summary>
    /// JWK thumbprint (jkt) as per RFC 7638 (sha-256).
    /// </summary>
    string Thumbprint();
}

