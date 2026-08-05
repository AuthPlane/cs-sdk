namespace Authplane;

/// <summary>
/// Optional resilience settings for <see cref="AuthplaneAuthClient"/> (circuit breaker around AS token
/// and introspection calls). Defaults match other Authplane SDKs (threshold 5, 30s cooldown).
/// </summary>
public sealed class AuthplaneAuthResilienceOptions
{
    /// <summary>Failures before the circuit opens. Minimum 1.</summary>
    public int CircuitBreakerThreshold { get; init; } = 5;

    /// <summary>Cooldown before a half-open probe is attempted.</summary>
    public int CircuitBreakerCooldownSeconds { get; init; } = 30;
}
