namespace Authplane;

/// <summary>
/// Per-resource inbound DPoP validation configuration (RFC 9449 §7.1 + RFC 9728 §2).
/// Passing any instance — even default-constructed — to <c>CreateResourceAsync</c>
/// (or <c>AuthplaneResource.CreateAsync</c>) is the on/off switch for PRM advertising
/// of <c>dpop_signing_alg_values_supported</c> and <c>dpop_bound_access_tokens_required</c>.
/// Passing <c>null</c> keeps DPoP fields out of PRM entirely AND causes the verifier to
/// reject any inbound DPoP signal with <see cref="DPoPNotSupportedException"/>.
/// </summary>
public sealed class InboundDPoPOptions
{
    private static readonly IReadOnlyList<string> DefaultAllowedProofAlgorithms =
        new System.Collections.ObjectModel.ReadOnlyCollection<string>(new[] { "ES256", "RS256" });

    private static readonly HashSet<string> SupportedDPoPAlgorithms =
        new(StringComparer.Ordinal) { "ES256", "RS256" };

    /// <summary>
    /// When true, the verifier rejects bearer-only tokens (those without
    /// <c>cnf.jkt</c>) with <see cref="DPoPBindingMismatchException"/> and PRM
    /// advertises <c>dpop_bound_access_tokens_required: true</c>.
    /// </summary>
    public bool Required { get; }

    /// <summary>
    /// JOSE <c>alg</c> values accepted on inbound DPoP proofs. Also published as
    /// <c>dpop_signing_alg_values_supported</c> in PRM. Defaults to <c>["ES256","RS256"]</c>.
    /// </summary>
    public IReadOnlyList<string> AllowedProofAlgorithms { get; }

    /// <summary>
    /// Maximum proof age (seconds) accepted from <c>iat</c>. Resolved value
    /// is <see cref="DefaultMaxProofAgeSeconds"/> (300) when the caller did
    /// not set one explicitly. <see cref="HasExplicitMaxProofAgeSeconds"/>
    /// is the flag the verifier checks to decide whether to fall back to
    /// the resource-level setting.
    /// </summary>
    public long MaxProofAgeSeconds { get; }

    /// <summary>True when the caller explicitly set <see cref="MaxProofAgeSeconds"/>.</summary>
    public bool HasExplicitMaxProofAgeSeconds { get; }

    /// <summary>
    /// Clock skew (seconds) tolerated on proof time claims. Resolved value
    /// is <see cref="DefaultClockSkewSeconds"/> (30) when the caller did
    /// not set one explicitly. <see cref="HasExplicitClockSkewSeconds"/>
    /// is the flag the verifier checks to decide whether to fall back to
    /// the resource-level setting.
    /// </summary>
    public long ClockSkewSeconds { get; }

    /// <summary>True when the caller explicitly set <see cref="ClockSkewSeconds"/>.</summary>
    public bool HasExplicitClockSkewSeconds { get; }

    public const long DefaultMaxProofAgeSeconds = DPoPDefaults.MaxProofAgeSeconds;
    public const long DefaultClockSkewSeconds = DPoPDefaults.ClockSkewSeconds;

    /// <summary>
    /// Replay detector for accepted proof <c>jti</c> values. When <c>null</c>, the
    /// resource allocates a per-resource <see cref="InMemoryDPoPReplayStore"/>.
    /// Use a shared store (Redis, DB) for multi-process deployments.
    /// </summary>
    public IDPoPReplayStore? ReplayStore { get; }

    /// <summary>
    /// Server-side nonce policy (RFC 9449 §9). <c>null</c> — the default —
    /// disables inbound nonce enforcement entirely: proofs verify exactly as
    /// before whether or not they carry a <c>nonce</c> claim. Non-null makes
    /// the nonce mandatory on every inbound proof; a missing, unknown, or
    /// expired nonce raises <see cref="DPoPNonceRequiredException"/> carrying
    /// a fresh <see cref="IDPoPNonceIssuer.Issue"/> value, which adapters
    /// surface as 401 <c>error="use_dpop_nonce"</c> plus a <c>DPoP-Nonce</c>
    /// response header. <see cref="HmacDPoPNonceIssuer"/> is the built-in
    /// stateless implementation; as with <see cref="ReplayStore"/>,
    /// multi-process deployments must share state — here, the HMAC key.
    /// The per-request <see cref="DPoPRequestContext.RequiredNonce"/>
    /// override takes precedence over this policy when both are set.
    /// </summary>
    public IDPoPNonceIssuer? NonceIssuer { get; }

    /// <param name="required">When <c>true</c>, bearer-only tokens are rejected
    /// and the PRM flag <c>dpop_bound_access_tokens_required</c> is emitted as
    /// <c>true</c>.</param>
    /// <param name="allowedProofAlgorithms">Restrict accepted proof <c>alg</c>
    /// values; default <c>["ES256","RS256"]</c>. Must be a subset of supported
    /// algorithms.</param>
    /// <param name="maxProofAgeSeconds">Maximum proof age from <c>iat</c>.
    /// <c>null</c> means "inherit the resource-level setting" — distinguishes
    /// "I didn't set this" from "I explicitly want 300".</param>
    /// <param name="clockSkewSeconds">Clock skew tolerated on proof time claims.
    /// <c>null</c> means "inherit the resource-level setting".</param>
    /// <param name="replayStore">Replay detector. <c>null</c> uses a per-resource
    /// in-memory store; multi-process deployments should pass a shared store.</param>
    /// <param name="nonceIssuer">Server-side nonce policy (RFC 9449 §9).
    /// <c>null</c> (default) leaves nonce enforcement off; non-null requires
    /// every inbound proof to carry a nonce this issuer recognises.</param>
    public InboundDPoPOptions(
        bool required = false,
        IEnumerable<string>? allowedProofAlgorithms = null,
        long? maxProofAgeSeconds = null,
        long? clockSkewSeconds = null,
        IDPoPReplayStore? replayStore = null,
        IDPoPNonceIssuer? nonceIssuer = null)
    {
        Required = required;

        if (allowedProofAlgorithms is null)
        {
            AllowedProofAlgorithms = DefaultAllowedProofAlgorithms;
        }
        else
        {
            var algs = allowedProofAlgorithms.ToArray();
            if (algs.Length == 0)
            {
                throw new ArgumentException(
                    $"allowedProofAlgorithms must be non-empty; pass null to accept the default {{{string.Join(", ", DefaultAllowedProofAlgorithms)}}}.",
                    nameof(allowedProofAlgorithms));
            }

            var invalid = algs.Where(a => !SupportedDPoPAlgorithms.Contains(a)).ToArray();
            if (invalid.Length > 0)
            {
                throw new ArgumentException(
                    $"Unsupported DPoP proof algorithms {{{string.Join(", ", invalid)}}}; only {{{string.Join(", ", SupportedDPoPAlgorithms)}}} are permitted.",
                    nameof(allowedProofAlgorithms));
            }

            // Wrap so the policy can't be mutated through a string[] cast.
            AllowedProofAlgorithms = new System.Collections.ObjectModel.ReadOnlyCollection<string>(algs);
        }

        if (maxProofAgeSeconds is { } maxAge && maxAge < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxProofAgeSeconds),
                "maxProofAgeSeconds must be non-negative.");
        }

        if (clockSkewSeconds is { } skew && skew < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkewSeconds),
                "clockSkewSeconds must be non-negative.");
        }

        HasExplicitMaxProofAgeSeconds = maxProofAgeSeconds.HasValue;
        HasExplicitClockSkewSeconds = clockSkewSeconds.HasValue;
        MaxProofAgeSeconds = maxProofAgeSeconds ?? DefaultMaxProofAgeSeconds;
        ClockSkewSeconds = clockSkewSeconds ?? DefaultClockSkewSeconds;
        ReplayStore = replayStore;
        NonceIssuer = nonceIssuer;
    }
}
