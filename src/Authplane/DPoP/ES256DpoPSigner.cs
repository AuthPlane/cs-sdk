using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Authplane;

public sealed class ES256DpoPSigner : IDPoPSigner, IDisposable
{
    private readonly ECDsa _privateKey;
    private readonly string _thumbprint;
    private readonly IReadOnlyDictionary<string, object> _publicJwk;
    private bool _disposed;

    private ES256DpoPSigner(ECDsa privateKey)
    {
        _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));

        var pub = _privateKey.ExportParameters(false);
        if (pub.Q.X is null || pub.Q.Y is null)
        {
            throw new InvalidOperationException("ES256 requires P-256 public key parameters (Q.X, Q.Y).");
        }

        var x = Base64Url.Encode(pub.Q.X);
        var y = Base64Url.Encode(pub.Q.Y);

        _publicJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = x,
            ["y"] = y
        };

        _thumbprint = JwkThumbprint.Compute(_publicJwk);
    }

    public static Task<ES256DpoPSigner> CreateAsync(CancellationToken cancellationToken = default)
    {
        // P-256 recommended by RFC 9449 for compact/fast proofs.
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return Task.FromResult(new ES256DpoPSigner(ecdsa));
    }

    public static Task<ES256DpoPSigner> CreateFromPrivateKeyAsync(
        byte[] pkcs8,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pkcs8);

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
        }
        catch (Exception ex)
        {
            ecdsa.Dispose();
            throw new ArgumentException(
                "Failed to import ES256 key from PKCS8. Expected a P-256 ECDSA private key.",
                nameof(pkcs8),
                ex);
        }

        // ImportPkcs8PrivateKey accepts any EC key (P-384, secp256k1, …) and
        // the ctor below would unconditionally publish "crv":"P-256", producing
        // a structurally mislabeled JWK whose ES256 signatures cover wrong-size
        // coordinates. RFC 7518 §3.4 binds ES256 to NIST P-256 specifically.
        var ecParams = ecdsa.ExportParameters(false);
        const string P256Oid = "1.2.840.10045.3.1.7";
        var importedOid = ecParams.Curve.Oid?.Value ?? ecParams.Curve.Oid?.FriendlyName;
        if (!string.Equals(importedOid, P256Oid, StringComparison.Ordinal) &&
            !string.Equals(importedOid, "nistP256", StringComparison.Ordinal) &&
            !string.Equals(importedOid, "ECDSA_P256", StringComparison.Ordinal))
        {
            ecdsa.Dispose();
            throw new ArgumentException(
                $"ES256 requires a P-256 (secp256r1) key, but the PKCS8 contained curve '{importedOid}'.",
                nameof(pkcs8));
        }

        return Task.FromResult(new ES256DpoPSigner(ecdsa));
    }

    public Task<string> GenerateProofAsync(
        string method,
        string url,
        DPoPProofOptions? options,
        CancellationToken cancellationToken)
    {
        _ = cancellationToken;

        var creds = new SigningCredentials(new ECDsaSecurityKey(_privateKey), SecurityAlgorithms.EcdsaSha256);

        return Task.FromResult(DPoPProofBuilder.Build(
            creds: creds,
            publicJwk: _publicJwk,
            method: method,
            url: url,
            proofTtlSeconds: DPoPDefaults.MaxProofAgeSeconds,
            options: options));
    }

    public string Thumbprint() => _thumbprint;

    /// <summary>
    /// Release the underlying ECDsa private key. Every .NET
    /// AsymmetricAlgorithm is IDisposable and owns native handles; long-
    /// lived processes that rotate signers would have leaked them.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _privateKey.Dispose();
        _disposed = true;
    }
}

