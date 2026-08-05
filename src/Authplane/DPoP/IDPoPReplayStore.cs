namespace Authplane;

public interface IDPoPReplayStore
{
    /// <summary>
    /// Returns true if the given DPoP proof JTI has been seen and is still valid.
    /// </summary>
    bool Seen(string jti);

    /// <summary>
    /// Remember the JTI until <paramref name="expiresAtSeconds"/> (unix seconds).
    /// </summary>
    void Remember(string jti, long expiresAtSeconds);

    /// <summary>
    /// Atomic anti-replay primitive (RFC 9449 §11.1). Returns <c>true</c> when
    /// <paramref name="jti"/> was already in the store with an unexpired
    /// expiry — i.e. the caller is observing a replay and MUST reject the
    /// proof. Returns <c>false</c> when <paramref name="jti"/> was new (or
    /// expired and replaced), in which case the entry is now stored with the
    /// supplied <paramref name="expiresAtSeconds"/>.
    ///
    /// The two-call <see cref="Seen"/> + <see cref="Remember"/> sequence has a
    /// race window: two concurrent verifies of the same JTI can both observe
    /// <c>Seen == false</c> before either calls <see cref="Remember"/>, so a
    /// replay slips through. Use this method instead.
    ///
    /// The default implementation falls back to <c>Seen</c> + <c>Remember</c>
    /// for backwards compatibility with custom store implementations that
    /// predate this method. Custom shared stores (Redis, Postgres) SHOULD
    /// override with a backend-atomic implementation (e.g. <c>SET … NX EX</c>).
    /// </summary>
    bool CheckAndStore(string jti, long expiresAtSeconds)
    {
        if (Seen(jti))
        {
            return true;
        }
        Remember(jti, expiresAtSeconds);
        return false;
    }
}
