namespace Authplane;

/// <summary>
/// Single source of truth for the small set of numeric DPoP defaults that
/// must agree between the signer side and the verifier side. The proof TTL
/// used to live in four places — <c>DPoPProvider</c> (configurable, default
/// 300), an inline ES256 signer (hard-coded 300),
/// <c>AuthplaneResource.DpopMaxAgeSeconds</c>, and
/// <c>InboundDPoPOptions.DefaultMaxProofAgeSeconds</c> — and a caller who
/// raised the signer's TTL above the verifier's would have every proof
/// silently rejected. Constants now resolve to this class.
/// </summary>
internal static class DPoPDefaults
{
    /// <summary>
    /// Proof lifetime / max accepted proof age (seconds). RFC 9449 §11.1
    /// recommends short-lived proofs; 300s is what the verifier accepts
    /// when the caller has not overridden
    /// <see cref="InboundDPoPOptions.MaxProofAgeSeconds"/>.
    /// </summary>
    public const long MaxProofAgeSeconds = 300;

    /// <summary>
    /// Clock-skew tolerance (seconds) applied symmetrically around proof
    /// <c>iat</c>/<c>exp</c> claims on the verifier side. The signer side
    /// does not consume this directly but the resource-level skew default
    /// is shared with <see cref="InboundDPoPOptions.DefaultClockSkewSeconds"/>.
    /// </summary>
    public const long ClockSkewSeconds = 30;
}
