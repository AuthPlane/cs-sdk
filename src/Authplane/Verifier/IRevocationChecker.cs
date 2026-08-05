namespace Authplane;

/// <summary>
/// Pluggable check that consults the AS to decide whether a token has been revoked.
/// Combined with <see cref="AuthplaneResource"/>'s <c>failClosed</c> flag, the verifier
/// can either reject every token whose revocation status cannot be confirmed (strict),
/// or accept on transient AS failures (lenient).
/// </summary>
public interface IRevocationChecker
{
    /// <summary>
    /// Returns <c>true</c> when the token is known to be revoked, <c>false</c> when
    /// it is known to be active, or throws when the answer is unknown (callers decide
    /// via <c>failClosed</c> whether unknown == revoked).
    /// </summary>
    Task<bool> IsRevokedAsync(string token, CancellationToken cancellationToken = default);
}
