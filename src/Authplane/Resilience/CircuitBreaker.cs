namespace Authplane;

/// <summary>
/// Protects against cascading failures when the authorization server is unavailable.
/// State machine: closed → open → half-open probe.
/// </summary>
public sealed class CircuitBreaker
{
    private readonly int _threshold;
    private readonly TimeSpan _cooldown;

    private readonly object _mutex = new();

    private BreakerState _state = BreakerState.Closed;
    private int _failures;
    private DateTimeOffset _openedAt;
    private bool _probeInFlight;

    private enum BreakerState
    {
        Closed,
        Open,
        HalfOpen,
    }

    /// <param name="failureThreshold">Consecutive failures before opening (minimum 1).</param>
    /// <param name="cooldown">How long the circuit stays open before a probe is allowed.</param>
    public CircuitBreaker(int failureThreshold, TimeSpan cooldown)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(failureThreshold, 1);
        _threshold = failureThreshold;
        _cooldown = cooldown <= TimeSpan.Zero ? TimeSpan.FromSeconds(30) : cooldown;
    }

    /// <summary>Returns the effective state for observability (matches Go <c>State()</c> strings).</summary>
    public CircuitBreakerState EffectiveState
    {
        get
        {
            lock (_mutex)
            {
                return MapEffective(EffectiveStateLocked());
            }
        }
    }

    /// <summary>Returns true if a request may proceed.</summary>
    public bool AllowRequest()
    {
        lock (_mutex)
        {
            var effective = EffectiveStateLocked();
            switch (effective)
            {
                case BreakerState.Closed:
                    return true;
                case BreakerState.Open:
                    return false;
                case BreakerState.HalfOpen:
                    if (_state != BreakerState.HalfOpen)
                    {
                        _state = BreakerState.HalfOpen;
                    }

                    if (_probeInFlight)
                    {
                        return false;
                    }

                    _probeInFlight = true;
                    return true;
                default:
                    return false;
            }
        }
    }

    /// <summary>Resets failure count and closes the circuit after a successful call.</summary>
    public void RecordSuccess()
    {
        lock (_mutex)
        {
            _failures = 0;
            _state = BreakerState.Closed;
            _probeInFlight = false;
        }
    }

    /// <summary>Records a failed call; may open the circuit when the threshold is reached.</summary>
    public void RecordFailure()
    {
        lock (_mutex)
        {
            var effective = EffectiveStateLocked();

            if (_probeInFlight &&
                (effective == BreakerState.HalfOpen || _state == BreakerState.HalfOpen))
            {
                _state = BreakerState.Open;
                _openedAt = DateTimeOffset.UtcNow;
                _probeInFlight = false;
                _failures = _threshold;
                return;
            }

            if (effective == BreakerState.HalfOpen && _state == BreakerState.Open)
            {
                return;
            }

            _failures++;
            if (_failures >= _threshold)
            {
                _state = BreakerState.Open;
                _openedAt = DateTimeOffset.UtcNow;
            }

            _probeInFlight = false;
        }
    }

    private BreakerState EffectiveStateLocked()
    {
        if (_state == BreakerState.Open && DateTimeOffset.UtcNow - _openedAt >= _cooldown)
        {
            return BreakerState.HalfOpen;
        }

        return _state;
    }

    private static CircuitBreakerState MapEffective(BreakerState s) =>
        s switch
        {
            BreakerState.Closed => CircuitBreakerState.Closed,
            BreakerState.Open => CircuitBreakerState.Open,
            BreakerState.HalfOpen => CircuitBreakerState.HalfOpen,
            _ => CircuitBreakerState.Closed,
        };
}

/// <summary>Logical circuit breaker state (for tests and metrics).</summary>
public enum CircuitBreakerState
{
    Closed,
    Open,
    HalfOpen,
}
