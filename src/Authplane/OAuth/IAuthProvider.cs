namespace Authplane;

/// <summary>
/// Pluggable authentication for OAuth endpoint requests.
/// Implementations return headers (e.g. <c>{"Authorization": "Basic ..."}</c>).
/// </summary>
public interface IAuthProvider
{
    /// <summary>
    /// Headers to attach to outbound AS requests for client authentication.
    /// Typically <c>{"Authorization": "Basic ..."}</c>; an alternate provider
    /// can supply any header-based scheme. Returning an empty dictionary
    /// means "no client auth headers" (e.g. mTLS where authentication is at
    /// the transport layer).
    /// </summary>
    IReadOnlyDictionary<string, string> AuthHeaders();
}

/// <summary>
/// HTTP Basic Auth from client_id + client_secret (RFC 6749 §2.3.1).
/// Credentials are form-URL-encoded before base64 per spec.
/// </summary>
public sealed class ClientCredentialsProvider : IAuthProvider
{
    private readonly IReadOnlyDictionary<string, string> _headers;

    /// <summary>
    /// Build an HTTP-Basic provider from a confidential client's credentials.
    /// Both <paramref name="clientId"/> and <paramref name="clientSecret"/> are
    /// form-URL-encoded before being joined with `:` and base64-encoded, per
    /// RFC 6749 §2.3.1 — reserved characters round-trip correctly.
    /// </summary>
    /// <exception cref="System.ArgumentException">Either argument is null, empty, or whitespace.</exception>
    public ClientCredentialsProvider(string clientId, string clientSecret)
    {
        System.ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        System.ArgumentException.ThrowIfNullOrWhiteSpace(clientSecret);

        var encodedId = System.Uri.EscapeDataString(clientId);
        var encodedSecret = System.Uri.EscapeDataString(clientSecret);
        var basic = System.Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"{encodedId}:{encodedSecret}"));
        _headers = new Dictionary<string, string>
        {
            ["Authorization"] = $"Basic {basic}"
        };
    }

    /// <inheritdoc/>
    public IReadOnlyDictionary<string, string> AuthHeaders() => _headers;
}
