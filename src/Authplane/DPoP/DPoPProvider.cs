using Microsoft.IdentityModel.Tokens;

namespace Authplane;

/// <summary>
/// High-level DPoP proof generator with nonce tracking.
/// Thread-safe — safe to share across concurrent requests.
/// </summary>
public sealed class DPoPProvider : IDPoPSigner
{
    private readonly DPoPKeyMaterial _keyMaterial;
    private readonly int _proofTtlSeconds;
    private readonly IDPoPNonceStore _nonceStore;

    /// <summary>The nonce store backing this provider — exposed so the
    /// <see cref="AuthplaneAuthClient"/> ctor overload can pull both signer
    /// and store from a single argument.</summary>
    public IDPoPNonceStore NonceStore => _nonceStore;

    public DPoPProvider(
        DPoPKeyMaterial keyMaterial,
        int proofTtlSeconds = (int)DPoPDefaults.MaxProofAgeSeconds,
        IDPoPNonceStore? nonceStore = null)
    {
        _keyMaterial = keyMaterial ?? throw new ArgumentNullException(nameof(keyMaterial));
        if (proofTtlSeconds <= 0)
        {
            throw new ArgumentException("proofTtlSeconds must be positive.", nameof(proofTtlSeconds));
        }
        _proofTtlSeconds = proofTtlSeconds;
        _nonceStore = nonceStore ?? new InMemoryDPoPNonceStore();
    }

    /// <summary>Store a server-provided DPoP-Nonce for the given URL's origin.</summary>
    public Task NoteNonceAsync(string url, string nonce, CancellationToken ct = default)
    {
        var origin = DeriveOrigin(url);
        return _nonceStore.SetAsync(origin, nonce, ct);
    }

    /// <summary>Return the last-seen DPoP-Nonce for the given URL's origin.</summary>
    public Task<string?> CurrentNonceAsync(string url, CancellationToken ct = default)
    {
        var origin = DeriveOrigin(url);
        return _nonceStore.GetAsync(origin, ct);
    }

    public string Thumbprint() => _keyMaterial.Thumbprint;

    public async Task<string> GenerateProofAsync(
        string method,
        string url,
        DPoPProofOptions? options,
        CancellationToken cancellationToken)
    {
        var nonce = options?.Nonce;
        if (string.IsNullOrWhiteSpace(nonce))
        {
            nonce = await CurrentNonceAsync(url, cancellationToken).ConfigureAwait(false);
        }

        SigningCredentials creds;
        if (_keyMaterial.EcKey is not null)
        {
            creds = new SigningCredentials(new ECDsaSecurityKey(_keyMaterial.EcKey), SecurityAlgorithms.EcdsaSha256);
        }
        else if (_keyMaterial.RsaKey is not null)
        {
            creds = new SigningCredentials(new RsaSecurityKey(_keyMaterial.RsaKey), SecurityAlgorithms.RsaSha256);
        }
        else
        {
            throw new InvalidOperationException("DPoPKeyMaterial has no signing key.");
        }

        var effectiveOptions = string.IsNullOrWhiteSpace(nonce) || nonce == options?.Nonce
            ? options
            : new DPoPProofOptions(accessToken: options?.AccessToken, nonce: nonce);

        return DPoPProofBuilder.Build(
            creds: creds,
            publicJwk: _keyMaterial.PublicJwk,
            method: method,
            url: url,
            proofTtlSeconds: _proofTtlSeconds,
            options: effectiveOptions);
    }

    /// <summary>
    /// Build DPoP headers dict for a request (proof + nonce auto-loaded).
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string>> BuildHeadersAsync(
        string method,
        string url,
        string accessToken = "",
        CancellationToken cancellationToken = default)
    {
        var proof = await GenerateProofAsync(method, url,
            new DPoPProofOptions(accessToken: accessToken),
            cancellationToken).ConfigureAwait(false);
        return new Dictionary<string, string> { ["DPoP"] = proof };
    }

    private static string DeriveOrigin(string url) => DPoPNonceOrigin.From(url);
}
