namespace Authplane;

public sealed class InMemoryDPoPReplayStore : IDPoPReplayStore
{
    private readonly object _lock = new();
    private readonly Dictionary<string, long> _seen = new(StringComparer.Ordinal);

    public bool Seen(string jti)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        lock (_lock)
        {
            if (!_seen.TryGetValue(jti, out var expiresAtSeconds))
            {
                return false;
            }

            if (now >= expiresAtSeconds)
            {
                _seen.Remove(jti);
                return false;
            }

            return true;
        }
    }

    public void Remember(string jti, long expiresAtSeconds)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            return;
        }

        lock (_lock)
        {
            _seen[jti] = expiresAtSeconds;
        }
    }

    /// <summary>
    /// Atomic anti-replay primitive — see <see cref="IDPoPReplayStore.CheckAndStore"/>.
    /// This single-lock implementation closes the race window the two-call
    /// <see cref="Seen"/> + <see cref="Remember"/> sequence has under concurrent verifies.
    /// </summary>
    public bool CheckAndStore(string jti, long expiresAtSeconds)
    {
        if (string.IsNullOrWhiteSpace(jti))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        lock (_lock)
        {
            if (_seen.TryGetValue(jti, out var existing) && existing > now)
            {
                return true;
            }
            _seen[jti] = expiresAtSeconds;
            return false;
        }
    }
}
