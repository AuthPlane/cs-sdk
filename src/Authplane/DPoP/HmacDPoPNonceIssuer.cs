using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Authplane;

/// <summary>
/// Stateless <see cref="IDPoPNonceIssuer"/>: each nonce is an HMAC-sealed
/// issue timestamp, so validation is a recompute-and-compare with no storage,
/// no eviction, and no cross-request coordination. Chosen over a lookup store
/// because RFC 9449 nonces bound proof *lifetime*, not proof *uniqueness* —
/// single-use is already enforced by the <c>jti</c> replay store, so
/// remembering issued nonces would duplicate state the design doesn't need.
/// A multi-process deployment shares nonces by sharing the key (any instance
/// validates any sibling's nonce), where a store-based design would need
/// shared infrastructure.
/// </summary>
/// <remarks>
/// Wire shape: <c>base64url( issuedAt:int64-BE || HMAC-SHA256(key, issuedAt)[0..16) )</c>
/// — 24 bytes, 32 <c>NQCHAR</c>-safe characters. The truncated 128-bit tag
/// follows standard HMAC truncation (RFC 2104 §5); forging a nonce still
/// requires a full second-preimage on HMAC-SHA256. The timestamp is *when the
/// nonce was issued*, so the acceptance window is measured from issuance:
/// a nonce older than <see cref="NonceLifetimeSeconds"/> is
/// <see cref="DPoPNonceValidationResult.Invalid"/>, and one past half that
/// lifetime is accepted as <see cref="DPoPNonceValidationResult.ValidRotationDue"/>
/// so a steadily-active client is handed its next nonce on a success response
/// (RFC 9449 §8.2) before the current one ever expires.
/// </remarks>
public sealed class HmacDPoPNonceIssuer : IDPoPNonceIssuer
{
    /// <summary>
    /// Default nonce lifetime (seconds). Matches the verifier's default max
    /// proof age (<see cref="InboundDPoPOptions.DefaultMaxProofAgeSeconds"/>):
    /// a shorter nonce would expire proofs the resource still accepts, and a
    /// longer one would extend exactly the pre-generation window §9 nonces
    /// exist to bound.
    /// </summary>
    public const long DefaultNonceLifetimeSeconds = DPoPDefaults.MaxProofAgeSeconds;

    private const int TimestampLengthBytes = 8;
    private const int TagLengthBytes = 16;
    private const int NonceLengthBytes = TimestampLengthBytes + TagLengthBytes;
    private const int MinKeyLengthBytes = 16;

    private readonly byte[] _key;
    private readonly long _nonceLifetimeSeconds;
    private readonly TimeProvider _timeProvider;

    /// <summary>Acceptance window, measured from nonce issuance.</summary>
    public long NonceLifetimeSeconds => _nonceLifetimeSeconds;

    /// <param name="key">HMAC key, at least 128 bits. Required — the key IS
    /// the deployment topology: every instance that must accept another's
    /// nonces (any multi-replica resource server) has to hold the same key,
    /// so it must come from configuration, not from this class. For a
    /// deliberately single-process setup use
    /// <see cref="CreateEphemeral"/>.</param>
    /// <param name="nonceLifetimeSeconds">Acceptance window from issuance;
    /// default <see cref="DefaultNonceLifetimeSeconds"/> (300).</param>
    /// <param name="timeProvider">Clock override for tests; default
    /// <see cref="TimeProvider.System"/>.</param>
    public HmacDPoPNonceIssuer(
        byte[] key,
        long nonceLifetimeSeconds = DefaultNonceLifetimeSeconds,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (nonceLifetimeSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonceLifetimeSeconds),
                "nonceLifetimeSeconds must be positive.");
        }

        if (key.Length < MinKeyLengthBytes)
        {
            throw new ArgumentException(
                $"key must be at least {MinKeyLengthBytes} bytes (128 bits); use CreateEphemeral() for a single-process random key.",
                nameof(key));
        }

        // Clone so a caller reusing (or later zeroing) its key buffer cannot
        // silently change what this issuer validates against.
        _key = (byte[])key.Clone();
        _nonceLifetimeSeconds = nonceLifetimeSeconds;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Issuer with a random 256-bit key private to this instance —
    /// single-process deployments ONLY. Per-process keys mean per-process
    /// nonces: behind a load balancer, a nonce issued by one replica is
    /// rejected by the next, and since RFC 9449 §8 prescribes a single
    /// retry, every request degenerates into a hard 401 loop that only
    /// shows up under multi-replica load. Anything running more than one
    /// replica must use the constructor with a shared key instead. This
    /// factory exists so "my nonces are per-process" is a line of code
    /// someone wrote, never a default they fell into.
    /// </summary>
    /// <param name="nonceLifetimeSeconds">Acceptance window from issuance;
    /// default <see cref="DefaultNonceLifetimeSeconds"/> (300).</param>
    /// <param name="timeProvider">Clock override for tests; default
    /// <see cref="TimeProvider.System"/>.</param>
    public static HmacDPoPNonceIssuer CreateEphemeral(
        long nonceLifetimeSeconds = DefaultNonceLifetimeSeconds,
        TimeProvider? timeProvider = null)
    {
        return new HmacDPoPNonceIssuer(
            RandomNumberGenerator.GetBytes(32), nonceLifetimeSeconds, timeProvider);
    }

    public string Issue()
    {
        var buffer = new byte[NonceLengthBytes];
        BinaryPrimitives.WriteInt64BigEndian(buffer, NowSeconds());
        var tag = HMACSHA256.HashData(_key, buffer.AsSpan(0, TimestampLengthBytes));
        tag.AsSpan(0, TagLengthBytes).CopyTo(buffer.AsSpan(TimestampLengthBytes));
        return Base64Url.Encode(buffer);
    }

    public DPoPNonceValidationResult Validate(string nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return DPoPNonceValidationResult.Invalid;
        }

        byte[] bytes;
        try
        {
            bytes = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(nonce);
        }
        catch
        {
            // Attacker-controlled input: malformed base64url is a rejection,
            // never an exception (see IDPoPNonceIssuer.Validate contract).
            return DPoPNonceValidationResult.Invalid;
        }

        if (bytes.Length != NonceLengthBytes)
        {
            return DPoPNonceValidationResult.Invalid;
        }

        var expectedTag = HMACSHA256.HashData(_key, bytes.AsSpan(0, TimestampLengthBytes));
        if (!CryptographicOperations.FixedTimeEquals(
                bytes.AsSpan(TimestampLengthBytes),
                expectedTag.AsSpan(0, TagLengthBytes)))
        {
            return DPoPNonceValidationResult.Invalid;
        }

        var issuedAt = BinaryPrimitives.ReadInt64BigEndian(bytes);
        var now = NowSeconds();

        // Defence in depth: unreachable without the key (the tag covers the
        // timestamp and FixedTimeEquals ran first), but a negative timestamp
        // near long.MinValue would wrap `now - issuedAt` negative and pass
        // both window checks below. Garbage stays a rejection, never a pass.
        if (issuedAt < 0)
        {
            return DPoPNonceValidationResult.Invalid;
        }

        // A future timestamp beyond the shared skew tolerance cannot have
        // come from a correctly-clocked sibling holding the same key; treat
        // it as forged/garbage rather than granting it an extended lifetime.
        if (issuedAt > now + DPoPDefaults.ClockSkewSeconds)
        {
            return DPoPNonceValidationResult.Invalid;
        }

        var age = now - issuedAt;
        if (age > _nonceLifetimeSeconds)
        {
            return DPoPNonceValidationResult.Invalid;
        }

        // Second half of the window: still valid, but tell the adapter to
        // hand out the next nonce on the success response (RFC 9449 §8.2) so
        // an active client rotates without ever hitting the 401 round trip.
        return age > _nonceLifetimeSeconds / 2
            ? DPoPNonceValidationResult.ValidRotationDue
            : DPoPNonceValidationResult.Valid;
    }

    private long NowSeconds() => _timeProvider.GetUtcNow().ToUnixTimeSeconds();
}
