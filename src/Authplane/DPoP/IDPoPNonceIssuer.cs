namespace Authplane;

/// <summary>
/// Outcome of validating an inbound DPoP proof <c>nonce</c> claim against the
/// resource server's nonce policy (RFC 9449 §9).
/// </summary>
public enum DPoPNonceValidationResult
{
    /// <summary>
    /// The nonce was not issued by this server, failed integrity checks, or
    /// has aged out of the acceptance window. The verifier rejects the proof
    /// with <see cref="DPoPNonceRequiredException"/> carrying a fresh nonce,
    /// which adapters surface as HTTP 401 <c>error="use_dpop_nonce"</c> plus
    /// a <c>DPoP-Nonce</c> response header.
    /// </summary>
    Invalid,

    /// <summary>The nonce is valid and fresh. Nothing else to do.</summary>
    Valid,

    /// <summary>
    /// The nonce is still valid but close enough to expiry that the client
    /// should rotate. The proof is accepted, and the verifier surfaces a
    /// fresh nonce via <see cref="VerifiedClaims.NextDPoPNonce"/> so the
    /// adapter can advertise it in the <c>DPoP-Nonce</c> header of the
    /// success response (RFC 9449 §8.2) — the client picks it up without
    /// ever taking the 401 round trip.
    /// </summary>
    ValidRotationDue,
}

/// <summary>
/// Resource-server-side nonce policy for inbound DPoP proofs (RFC 9449 §9).
/// Wiring one into <see cref="InboundDPoPOptions"/> is the opt-in switch for
/// nonce enforcement: with an issuer configured, every inbound DPoP proof must
/// carry a <c>nonce</c> claim this issuer recognises; without one (the
/// default), proofs are accepted with or without a nonce claim exactly as
/// before.
/// </summary>
/// <remarks>
/// This is the inbound counterpart of the outbound <see cref="IDPoPNonceStore"/>:
/// the store remembers nonces *other* servers handed this process as a client,
/// while the issuer mints and recognises the nonces this process hands *its*
/// clients as a resource server. The counterpart deliberately has the other
/// shape: <see cref="IDPoPNonceStore"/> is async because it runs on the
/// outbound HTTP path, while these methods are synchronous because they run
/// inside proof verification, matching the <see cref="IDPoPReplayStore"/>
/// precedent — an implementation pulling its key from remote storage takes
/// the same sync-over-async trade the replay store already made.
/// </remarks>
public interface IDPoPNonceIssuer
{
    /// <summary>
    /// Mint a fresh nonce for the <c>DPoP-Nonce</c> response header.
    /// The value must satisfy the RFC 9449 §8.1 <c>NQCHAR</c> syntax —
    /// in particular no control characters, whitespace, <c>"</c> or
    /// <c>\</c> — since it is emitted verbatim as an HTTP header value.
    /// </summary>
    string Issue();

    /// <summary>
    /// Decide whether <paramref name="nonce"/> — the <c>nonce</c> claim of an
    /// otherwise-valid inbound proof — was issued by this server and is still
    /// inside the acceptance window. Implementations must treat any
    /// unparseable input as <see cref="DPoPNonceValidationResult.Invalid"/>
    /// rather than throwing: the value is attacker-controlled.
    /// </summary>
    DPoPNonceValidationResult Validate(string nonce);
}
