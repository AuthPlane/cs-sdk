namespace Authplane;

/// <summary>
/// RFC 7009 token revocation helper. Lives in its own partial file so the revocation
/// feature can land as a focused commit.
/// </summary>
internal static partial class OAuthOperations
{
    /// <summary>
    /// POST <c>{issuer}/oauth/revoke</c> authenticating via the configured
    /// <see cref="IAuthProvider"/> (falling back to HTTP Basic from
    /// client_id/client_secret). Returns once the AS responds 200 OK;
    /// non-success bodies surface as <see cref="AuthplaneTokenRequestException"/>.
    /// </summary>
    public static async Task RevokeAsync(
        Context context,
        string token,
        string? tokenTypeHint,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var url = OAuthEndpoints.RevocationUrl(context.IssuerUrl);

        var parameters = OAuthRequestBodies.BuildTokenForm(token, tokenTypeHint);

        try
        {
            _ = await OAuthHttpClient.DoPostFormAsync(
                context, url, parameters, "revocation endpoint",
                cancellationToken).ConfigureAwait(false);
        }
        catch (AuthplaneTokenRequestException ex)
            when (!string.IsNullOrWhiteSpace(tokenTypeHint)
                  && string.Equals(ex.OAuthError, OAuthConstants.ErrorCodes.UnsupportedTokenType, StringComparison.Ordinal))
        {
            // RFC 7009 §2.2.1: retry without token_type_hint if AS doesn't support it.
            var retryParams = OAuthRequestBodies.BuildTokenForm(token, tokenTypeHint: null);
            _ = await OAuthHttpClient.DoPostFormAsync(
                context, url, retryParams, "revocation endpoint",
                cancellationToken).ConfigureAwait(false);
        }
    }
}
