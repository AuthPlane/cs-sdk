using System.Text.Json;

namespace Authplane;

/// <summary>
/// Single source of truth for the RFC 7638 JWK thumbprint used as
/// <c>cnf.jkt</c> for DPoP binding. Three copies of the canonical-JSON
/// construction lived in DPoPKeyMaterial, ES256DpoPSigner, and
/// AuthplaneResource; they differed subtly in how they treated the
/// <c>kty</c> casing (one matched ordinal-ignore-case but emitted the
/// uppercase canonical form; another interpolated whatever casing the
/// caller passed). Centralising here normalises to the RFC 7518 §6.1
/// registered casing (<c>"EC"</c>, <c>"RSA"</c>) and emits the canonical
/// member order RFC 7638 §3.2 prescribes — so signer and verifier always
/// produce identical thumbprints for the same key.
/// </summary>
internal static class JwkThumbprint
{
    public static string ComputeEc(string crv, string x, string y)
    {
        if (string.IsNullOrWhiteSpace(crv) || string.IsNullOrWhiteSpace(x) || string.IsNullOrWhiteSpace(y))
        {
            throw new InvalidOperationException("EC JWK missing required parameters (crv, x, y).");
        }

        RequireJwkSafe(crv, "crv");
        RequireJwkSafe(x, "x");
        RequireJwkSafe(y, "y");

        var canonical = $"{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return DPoPHashes.Sha256Base64Url(canonical);
    }

    public static string ComputeRsa(string e, string n)
    {
        if (string.IsNullOrWhiteSpace(e) || string.IsNullOrWhiteSpace(n))
        {
            throw new InvalidOperationException("RSA JWK missing required parameters (e, n).");
        }

        RequireJwkSafe(e, "e");
        RequireJwkSafe(n, "n");

        var canonical = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";
        return DPoPHashes.Sha256Base64Url(canonical);
    }

    // RFC 7638 §3.2 wants the canonical-JSON form of the required members, with
    // JSON-mandated escaping only. The canonical form is built here by string
    // interpolation rather than JsonSerializer; that is safe iff every member
    // value is already in the base64url alphabet — which is what RFC 7515
    // Appendix C requires for `x`/`y`/`e`/`n`, and which the JWA `crv` registry
    // also satisfies (`P-256`, `P-384`, `P-521`, `Ed25519`, `secp256k1` …).
    // Reject anything outside that alphabet up front so a malformed JWK whose
    // sig-check happens to be bypassed (e.g. by a future reorder of the
    // verification steps) cannot inject `"` or `\` into the canonical bytes
    // and forge a thumbprint collision.
    private static void RequireJwkSafe(string value, string field)
    {
        foreach (var c in value)
        {
            var ok = (c >= 'A' && c <= 'Z')
                  || (c >= 'a' && c <= 'z')
                  || (c >= '0' && c <= '9')
                  || c == '-' || c == '_';
            if (!ok)
            {
                throw new InvalidOperationException(
                    $"JWK member '{field}' contains characters outside the base64url / JWA registry alphabet.");
            }
        }
    }

    /// <summary>
    /// Compute the thumbprint from a JWK already deserialised into a
    /// <see cref="JsonElement"/> (used by the inbound DPoP verifier, which
    /// parses the proof header JWK on the hot path).
    /// </summary>
    public static string Compute(JsonElement jwk)
    {
        if (!jwk.TryGetProperty("kty", out var ktyProp) || ktyProp.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException("JWK missing kty.");
        }

        var kty = ktyProp.GetString()!;
        if (string.Equals(kty, "EC", StringComparison.OrdinalIgnoreCase))
        {
            return ComputeEc(
                GetStringOrNull(jwk, "crv"),
                GetStringOrNull(jwk, "x"),
                GetStringOrNull(jwk, "y"));
        }

        if (string.Equals(kty, "RSA", StringComparison.OrdinalIgnoreCase))
        {
            return ComputeRsa(
                GetStringOrNull(jwk, "e"),
                GetStringOrNull(jwk, "n"));
        }

        throw new InvalidOperationException($"Unsupported JWK kty '{kty}'.");
    }

    /// <summary>
    /// Compute the thumbprint from a JWK held as a dictionary (used by the
    /// outbound signers, which build their public JWK as a dictionary before
    /// serialising it into the proof header).
    /// </summary>
    public static string Compute(IReadOnlyDictionary<string, object> jwk)
    {
        if (!jwk.TryGetValue("kty", out var ktyObj) || ktyObj is null)
        {
            throw new InvalidOperationException("JWK missing kty.");
        }

        var kty = ktyObj.ToString() ?? string.Empty;
        if (string.Equals(kty, "EC", StringComparison.OrdinalIgnoreCase))
        {
            return ComputeEc(
                GetStringOrNull(jwk, "crv"),
                GetStringOrNull(jwk, "x"),
                GetStringOrNull(jwk, "y"));
        }

        if (string.Equals(kty, "RSA", StringComparison.OrdinalIgnoreCase))
        {
            return ComputeRsa(
                GetStringOrNull(jwk, "e"),
                GetStringOrNull(jwk, "n"));
        }

        throw new InvalidOperationException($"Unsupported JWK kty '{kty}'.");
    }

    private static string GetStringOrNull(JsonElement jwk, string name)
    {
        return jwk.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString() ?? string.Empty
            : string.Empty;
    }

    private static string GetStringOrNull(IReadOnlyDictionary<string, object> jwk, string name)
    {
        return jwk.TryGetValue(name, out var value) && value is not null
            ? value.ToString() ?? string.Empty
            : string.Empty;
    }
}
