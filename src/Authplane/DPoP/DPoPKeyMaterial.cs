using System.Security.Cryptography;

namespace Authplane;

/// <summary>
/// Signing key material for DPoP proof generation.
/// </summary>
public sealed class DPoPKeyMaterial
{
    private static readonly HashSet<string> SupportedAlgorithms = new(StringComparer.Ordinal)
    {
        "ES256",
        "RS256",
    };

    public IReadOnlyDictionary<string, object> PublicJwk { get; }
    public string Algorithm { get; }

    internal ECDsa? EcKey { get; }
    internal RSA? RsaKey { get; }

    private DPoPKeyMaterial(
        IReadOnlyDictionary<string, object> publicJwk,
        string algorithm,
        ECDsa? ecKey,
        RSA? rsaKey)
    {
        PublicJwk = publicJwk;
        Algorithm = algorithm;
        EcKey = ecKey;
        RsaKey = rsaKey;
    }

    /// <summary>Create ES256 key material from a new ephemeral P-256 key.</summary>
    public static DPoPKeyMaterial CreateES256()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = ecdsa.ExportParameters(false);
        var x = Base64Url.Encode(pub.Q.X!);
        var y = Base64Url.Encode(pub.Q.Y!);

        var publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = x,
            ["y"] = y,
        };

        return new DPoPKeyMaterial(publicJwk, "ES256", ecKey: ecdsa, rsaKey: null);
    }

    /// <summary>Create RS256 key material from a new ephemeral 2048-bit RSA key.</summary>
    public static DPoPKeyMaterial CreateRS256(int keySizeBits = 2048)
    {
        var rsa = RSA.Create(keySizeBits);
        var pub = rsa.ExportParameters(false);
        var e = Base64Url.Encode(pub.Exponent!);
        var n = Base64Url.Encode(pub.Modulus!);

        var publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["e"] = e,
            ["n"] = n,
        };

        return new DPoPKeyMaterial(publicJwk, "RS256", ecKey: null, rsaKey: rsa);
    }

    /// <summary>
    /// Load DPoP key material from a PEM-encoded private key. Real deployments
    /// key off persisted material rather than the ephemeral
    /// <see cref="CreateES256"/> / <see cref="CreateRS256"/> factories. Accepts
    /// PKCS#8 (<c>BEGIN PRIVATE KEY</c>) and SEC 1 / PKCS#1 (<c>BEGIN EC PRIVATE KEY</c>
    /// / <c>BEGIN RSA PRIVATE KEY</c>) PEM bodies.
    /// </summary>
    /// <param name="pem">PEM text containing the private key.</param>
    /// <param name="algorithm">Either <c>"ES256"</c> or <c>"RS256"</c>; default <c>"ES256"</c>.</param>
    public static DPoPKeyMaterial FromPem(string pem, string algorithm = "ES256")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);

        if (!SupportedAlgorithms.Contains(algorithm))
        {
            throw new ArgumentException(
                $"Unsupported DPoP algorithm '{algorithm}'. Supported: ES256, RS256.",
                nameof(algorithm));
        }

        if (algorithm == "ES256")
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            try
            {
                ecdsa.ImportFromPem(pem.AsSpan());
            }
            catch (Exception ex)
            {
                ecdsa.Dispose();
                throw new ArgumentException(
                    "Failed to import ES256 key from PEM. Expected a P-256 ECDSA private key.",
                    nameof(pem),
                    ex);
            }

            // ImportFromPem replaces the curve we passed to Create() with whatever
            // the PEM actually carries — a P-384 / secp256k1 key imports cleanly
            // and then we'd publish a JWK labelled "P-256" with wrong-size x/y
            // bytes that no verifier could reconstruct. RFC 7518 §3.4 binds the
            // ES256 alg identifier to NIST P-256 specifically.
            var ecParams = ecdsa.ExportParameters(false);
            const string P256Oid = "1.2.840.10045.3.1.7";
            var importedOid = ecParams.Curve.Oid?.Value ?? ecParams.Curve.Oid?.FriendlyName;
            if (!string.Equals(importedOid, P256Oid, StringComparison.Ordinal) &&
                !string.Equals(importedOid, "nistP256", StringComparison.Ordinal) &&
                !string.Equals(importedOid, "ECDSA_P256", StringComparison.Ordinal))
            {
                ecdsa.Dispose();
                throw new ArgumentException(
                    $"ES256 requires a P-256 (secp256r1) key, but the PEM contained curve '{importedOid}'.",
                    nameof(pem));
            }

            if (ecParams.Q.X is null || ecParams.Q.Y is null)
            {
                ecdsa.Dispose();
                throw new ArgumentException(
                    "PEM-loaded ECDSA key does not expose its public point — required for the JWK.",
                    nameof(pem));
            }

            var publicJwk = new Dictionary<string, object>
            {
                ["kty"] = "EC",
                ["crv"] = "P-256",
                ["x"] = Base64Url.Encode(ecParams.Q.X!),
                ["y"] = Base64Url.Encode(ecParams.Q.Y!),
            };
            return new DPoPKeyMaterial(publicJwk, "ES256", ecKey: ecdsa, rsaKey: null);
        }

        // RS256
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem.AsSpan());
        }
        catch (Exception ex)
        {
            rsa.Dispose();
            throw new ArgumentException(
                "Failed to import RS256 key from PEM. Expected an RSA private key.",
                nameof(pem),
                ex);
        }

        var rsaParams = rsa.ExportParameters(false);
        if (rsaParams.Exponent is null || rsaParams.Modulus is null)
        {
            rsa.Dispose();
            throw new ArgumentException(
                "PEM-loaded RSA key does not expose its public components — required for the JWK.",
                nameof(pem));
        }

        var rsaJwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["e"] = Base64Url.Encode(rsaParams.Exponent!),
            ["n"] = Base64Url.Encode(rsaParams.Modulus!),
        };
        return new DPoPKeyMaterial(rsaJwk, "RS256", ecKey: null, rsaKey: rsa);
    }

    /// <summary>RFC 7638 JWK thumbprint of the public key.</summary>
    public string Thumbprint => JwkThumbprint.Compute(PublicJwk);
}
