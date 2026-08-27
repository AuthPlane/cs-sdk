namespace Authplane;

public sealed class DPoPRequestContext
{
    /// <summary>
    /// HTTP method of the inbound request being verified. MUST be the
    /// canonical-uppercase form per RFC 7230 §3.1.1 (e.g. <c>"GET"</c>,
    /// <c>"POST"</c>) — the verifier compares it byte-exact against the
    /// proof's <c>htm</c> claim per RFC 9449 §4.3 step 11, so a lowercased
    /// method here will cause every proof to be rejected with no other
    /// diagnostic. ASP.NET Core's <c>HttpRequest.Method</c> already meets
    /// this contract; integrations on custom HTTP stacks must uppercase
    /// before constructing the context.
    /// </summary>
    public string Method { get; }
    public string Url { get; }
    public string? Proof { get; }
    public IDPoPReplayStore? ReplayStore { get; }

    /// <summary>
    /// When set, the inbound DPoP verifier MUST check that the proof carries a <c>nonce</c>
    /// claim whose value matches this string. If the proof is missing the nonce or the
    /// value does not match, verification fails with <see cref="InvalidDPoPProofException"/>.
    /// Takes precedence over the resource-level
    /// <see cref="InboundDPoPOptions.NonceIssuer"/> policy when both are
    /// configured — the same per-request-override rule as <see cref="ReplayStore"/>.
    /// </summary>
    public string? RequiredNonce { get; }

    public DPoPRequestContext(
        string method,
        string url,
        string? proof = null,
        IDPoPReplayStore? replayStore = null,
        string? requiredNonce = null)
    {
        Method = !string.IsNullOrWhiteSpace(method)
            ? method
            : throw new ArgumentNullException(nameof(method));
        Url = !string.IsNullOrWhiteSpace(url)
            ? url
            : throw new ArgumentNullException(nameof(url));
        Proof = proof;
        ReplayStore = replayStore;
        RequiredNonce = requiredNonce;
    }

    /// <summary>
    /// Build a request context from the raw <c>DPoP</c> header values,
    /// enforcing RFC 9449 §4.3 #1: at most one <c>DPoP</c> proof per
    /// request. Two on-wire shapes are rejected: multiple header entries,
    /// and a single entry pre-joined with <c>,</c> by a header-folding
    /// intermediary (RFC 9110 §5.3 permits combining repeated field lines
    /// that way). Blank entries are dropped rather than counted, so zero
    /// values — or only whitespace-only values — is the bearer-only path
    /// and returns <c>null</c>; two or more non-blank proofs throw
    /// <see cref="DPoPMultipleProofsException"/>, surfaced as a
    /// <c>DPoP</c>-scheme challenge carrying
    /// <c>error="invalid_dpop_proof"</c> (RFC 9449 §7.1).
    /// Framework adapters reduce to header extraction plus this call;
    /// hand-rolled integrations get the same §4.3 enforcement by routing
    /// every inbound <c>DPoP</c> header value through
    /// <paramref name="proofs"/> instead of constructing the context
    /// directly.
    /// </summary>
    public static DPoPRequestContext? FromHeaderValues(
        string method,
        string url,
        IReadOnlyList<string?> proofs,
        IDPoPReplayStore? replayStore = null,
        string? requiredNonce = null)
    {
        ArgumentNullException.ThrowIfNull(proofs);

        // JWS compact serialization is base64url + '.' and never contains a
        // literal ',', so split-on-comma is unambiguous. The bounded split
        // caps the allocation on an attacker-controlled header: only
        // 0 / 1 / ≥2 non-blank pieces matter, and a third piece already
        // trips the cardinality guard below.
        var flattened = new List<string>(1);
        foreach (var value in proofs)
        {
            if (flattened.Count > 1)
            {
                // Already over the cardinality limit — stop flattening so N
                // field lines cannot allocate more than a handful of strings.
                break;
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            flattened.AddRange(value.Split(
                ',', 3, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));
        }

        if (flattened.Count > 1)
        {
            throw new DPoPMultipleProofsException(
                "multiple DPoP proofs received; exactly one required (RFC 9449 section 4.3)");
        }

        if (flattened.Count == 0)
        {
            return null;
        }

        return new DPoPRequestContext(method, url, flattened[0], replayStore, requiredNonce);
    }
}

