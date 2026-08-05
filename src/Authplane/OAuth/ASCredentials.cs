namespace Authplane;

/// <summary>
/// Symmetrical client-credentials configuration object shared between introspection
/// (<see cref="AuthplaneAuthClient.IntrospectAsync"/>) and token-exchange operations.
/// Use this record
/// when the same <c>client_id</c> / <c>client_secret</c> pair is reused across
/// multiple AS-facing operations.
/// </summary>
/// <param name="ClientId">OAuth client identifier registered with the AS.</param>
/// <param name="ClientSecret">Confidential client secret. Must be non-empty for
/// confidential clients; public clients use a different path entirely.</param>
public sealed record ASCredentials(string ClientId, string ClientSecret)
{
    /// <summary>
    /// Convenience: materialise an <see cref="IAuthProvider"/> (HTTP Basic) backed
    /// by these credentials. Equivalent to passing
    /// <c>new ClientCredentialsProvider(ClientId, ClientSecret)</c>.
    /// </summary>
    public IAuthProvider ToAuthProvider() => new ClientCredentialsProvider(ClientId, ClientSecret);
}
