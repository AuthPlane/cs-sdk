namespace Authplane;

/// <summary>
/// RFC 7009 token revocation surface for <see cref="AuthplaneAuthClient"/>.
/// Lives in its own partial file so the revocation feature can land as a single
/// focused commit.
/// </summary>
public sealed partial class AuthplaneAuthClient
{
    /// <summary>
    /// Revoke an access or refresh token (RFC 7009).
    /// </summary>
    /// <param name="token">The token to revoke. Required.</param>
    /// <param name="tokenTypeHint">
    /// Optional hint to the AS, typically <c>"access_token"</c> or <c>"refresh_token"</c>.
    /// Per RFC 7009 §2.1, the AS may ignore the hint when it knows otherwise.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="token"/> is empty.</exception>
    /// <exception cref="AuthplaneTokenRequestException">
    /// Thrown when the AS responds with a non-2xx status. The exception carries the
    /// OAuth <c>error</c> value and the HTTP status code when available.
    /// </exception>
    /// <exception cref="CircuitOpenException">Thrown when the auth circuit breaker is open.</exception>
    public async Task RevokeAsync(
        string token,
        string? tokenTypeHint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        // Lift the void-returning operation into the generic circuit pipeline
        // via a sentinel return. Avoids a parallel `ExecuteWithCircuitVoidAsync`
        // that drifted from its `<T>` sibling — both helpers previously
        // hand-rolled the same allow-check / record-success / record-failure
        // sequence and any breaker-policy fix had to be made twice.
        await ExecuteWithCircuitAsync<bool>(async () =>
        {
            await OAuthOperations.RevokeAsync(_oauthContext, token, tokenTypeHint, cancellationToken)
                .ConfigureAwait(false);
            return true;
        }).ConfigureAwait(false);
    }
}
