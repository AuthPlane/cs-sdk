using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers <see cref="DPoPKeyMaterial"/> factories and <see cref="DPoPProvider"/>
/// proof generation / nonce tracking. Outbound DPoP — uncovered prior to this
/// test file because verifier tests only exercise inbound paths.
/// </summary>
public sealed class DPoPProviderAndKeyMaterialTests
{
    // ---------------- DPoPKeyMaterial ----------------

    [Fact]
    public void CreateES256_BuildsPublicJwk_WithEcParams()
    {
        var mat = DPoPKeyMaterial.CreateES256();
        Assert.Equal("ES256", mat.Algorithm);
        Assert.Equal("EC", mat.PublicJwk["kty"]);
        Assert.Equal("P-256", mat.PublicJwk["crv"]);
        Assert.True(mat.PublicJwk.ContainsKey("x"));
        Assert.True(mat.PublicJwk.ContainsKey("y"));
        Assert.False(mat.PublicJwk.ContainsKey("d")); // no private material
    }

    [Fact]
    public void CreateRS256_BuildsPublicJwk_WithRsaParams()
    {
        var mat = DPoPKeyMaterial.CreateRS256();
        Assert.Equal("RS256", mat.Algorithm);
        Assert.Equal("RSA", mat.PublicJwk["kty"]);
        Assert.True(mat.PublicJwk.ContainsKey("n"));
        Assert.True(mat.PublicJwk.ContainsKey("e"));
        Assert.False(mat.PublicJwk.ContainsKey("d"));
    }

    [Fact]
    public void Thumbprint_RFC7638_StableForSameKey()
    {
        var mat = DPoPKeyMaterial.CreateES256();
        var t1 = mat.Thumbprint;
        var t2 = mat.Thumbprint;
        Assert.Equal(t1, t2);
        Assert.False(string.IsNullOrEmpty(t1));
    }

    [Fact]
    public void Thumbprint_DiffersForDifferentKeys()
    {
        Assert.NotEqual(DPoPKeyMaterial.CreateES256().Thumbprint, DPoPKeyMaterial.CreateES256().Thumbprint);
    }

    [Fact]
    public void Thumbprint_BothKeyTypes()
    {
        // RSA arm of the kty switch.
        var rsa = DPoPKeyMaterial.CreateRS256();
        Assert.False(string.IsNullOrEmpty(rsa.Thumbprint));
    }

    [Fact]
    public void FromPem_ES256_ImportsP256Key()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = ecdsa.ExportPkcs8PrivateKeyPem();

        var mat = DPoPKeyMaterial.FromPem(pem, "ES256");
        Assert.Equal("ES256", mat.Algorithm);
        Assert.Equal("EC", mat.PublicJwk["kty"]);
    }

    [Fact]
    public void FromPem_RS256_ImportsRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportPkcs8PrivateKeyPem();

        var mat = DPoPKeyMaterial.FromPem(pem, "RS256");
        Assert.Equal("RS256", mat.Algorithm);
        Assert.Equal("RSA", mat.PublicJwk["kty"]);
    }

    [Fact]
    public void FromPem_BlankPem_Throws()
    {
        Assert.Throws<ArgumentException>(() => DPoPKeyMaterial.FromPem("", "ES256"));
        Assert.Throws<ArgumentException>(() => DPoPKeyMaterial.FromPem("   ", "ES256"));
    }

    [Fact]
    public void FromPem_UnsupportedAlgorithm_Throws()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = ecdsa.ExportPkcs8PrivateKeyPem();
        Assert.Throws<ArgumentException>(() => DPoPKeyMaterial.FromPem(pem, "PS256"));
    }

    [Fact]
    public void FromPem_BadPem_ThrowsWithInnerException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            DPoPKeyMaterial.FromPem("-----BEGIN PRIVATE KEY-----\nnot-base64-at-all\n-----END PRIVATE KEY-----", "ES256"));
        Assert.NotNull(ex.InnerException);
    }

    [Fact]
    public void FromPem_ES256_RejectsNonP256Curve()
    {
        // RFC 7518 §3.4: ES256 is bound to NIST P-256 specifically. Importing a
        // P-384 PEM under algorithm="ES256" must fail rather than silently emit
        // a JWK mislabelled "P-256" with wrong-size point bytes.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var pem = ecdsa.ExportPkcs8PrivateKeyPem();

        var ex = Assert.Throws<ArgumentException>(() => DPoPKeyMaterial.FromPem(pem, "ES256"));
        Assert.Contains("P-256", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateFromPrivateKeyAsync_RejectsNonP256Curve()
    {
        // Same RFC 7518 §3.4 binding as FromPem above, applied to the PKCS8
        // factory on the signer. ECDsa.Create() (no curve) followed by
        // ImportPkcs8PrivateKey would otherwise accept a P-384 key and the
        // ctor would publish crv:P-256 from 48-byte x/y, producing an
        // unverifiable proof.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var pkcs8 = ecdsa.ExportPkcs8PrivateKey();

        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => ES256DpoPSigner.CreateFromPrivateKeyAsync(pkcs8));
        Assert.Contains("P-256", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateFromPrivateKeyAsync_AcceptsP256()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pkcs8 = ecdsa.ExportPkcs8PrivateKey();

        var signer = await ES256DpoPSigner.CreateFromPrivateKeyAsync(pkcs8);
        Assert.NotNull(signer.Thumbprint());
    }

    // ---------------- DPoPProvider ----------------

    [Fact]
    public void Ctor_NullKeyMaterial_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new DPoPProvider(keyMaterial: null!));
    }

    [Fact]
    public void Ctor_NonPositiveTtl_Throws()
    {
        var mat = DPoPKeyMaterial.CreateES256();
        Assert.Throws<ArgumentException>(() => new DPoPProvider(mat, proofTtlSeconds: 0));
        Assert.Throws<ArgumentException>(() => new DPoPProvider(mat, proofTtlSeconds: -5));
    }

    [Fact]
    public void Ctor_DefaultsToInMemoryNonceStore()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        Assert.IsType<InMemoryDPoPNonceStore>(provider.NonceStore);
    }

    [Fact]
    public void Thumbprint_DelegatesToKeyMaterial()
    {
        var mat = DPoPKeyMaterial.CreateES256();
        var provider = new DPoPProvider(mat);
        Assert.Equal(mat.Thumbprint, provider.Thumbprint());
    }

    [Fact]
    public async Task GenerateProofAsync_ES256_EmitsValidJwt_WithRequiredClaims()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        var proof = await provider.GenerateProofAsync(
            method: "POST",
            url: "https://api.example.com/resource",
            options: null,
            cancellationToken: CancellationToken.None);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(proof);

        Assert.Equal("dpop+jwt", jwt.Header["typ"]);
        Assert.NotNull(jwt.Header["jwk"]);
        Assert.Equal("POST", GetClaim(jwt, "htm"));
        Assert.Equal("https://api.example.com/resource", GetClaim(jwt, "htu"));
        Assert.False(string.IsNullOrEmpty(GetClaim(jwt, "jti")));
        Assert.False(string.IsNullOrEmpty(GetClaim(jwt, "iat")));
        Assert.False(string.IsNullOrEmpty(GetClaim(jwt, "exp")));
    }

    [Fact]
    public async Task GenerateProofAsync_RS256_AlsoSupported()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateRS256());
        var proof = await provider.GenerateProofAsync(
            method: "GET",
            url: "https://api.example.com/x",
            options: null,
            cancellationToken: CancellationToken.None);
        Assert.False(string.IsNullOrWhiteSpace(proof));
    }

    [Fact]
    public async Task GenerateProofAsync_WithAccessToken_AddsAthClaim()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        var proof = await provider.GenerateProofAsync(
            method: "POST",
            url: "https://api.example.com/r",
            options: new DPoPProofOptions(accessToken: "the-token"),
            cancellationToken: CancellationToken.None);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(proof);
        var ath = GetClaim(jwt, "ath");
        Assert.False(string.IsNullOrEmpty(ath));
    }

    [Fact]
    public async Task GenerateProofAsync_WithExplicitNonce_AddsNonceClaim()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        var proof = await provider.GenerateProofAsync(
            method: "POST",
            url: "https://api.example.com/r",
            options: new DPoPProofOptions(nonce: "server-nonce-xyz"),
            cancellationToken: CancellationToken.None);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(proof);
        Assert.Equal("server-nonce-xyz", GetClaim(jwt, "nonce"));
    }

    [Fact]
    public async Task NoteNonce_ThenCurrentNonce_RoundTripsPerOrigin()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        await provider.NoteNonceAsync("https://as1.example.com/token", "nonce-1");
        await provider.NoteNonceAsync("https://as2.example.com/token", "nonce-2");

        Assert.Equal("nonce-1", await provider.CurrentNonceAsync("https://as1.example.com/token"));
        Assert.Equal("nonce-2", await provider.CurrentNonceAsync("https://as2.example.com/token"));
        // Different path same origin → same nonce.
        Assert.Equal("nonce-1", await provider.CurrentNonceAsync("https://as1.example.com/revocation"));
    }

    [Fact]
    public async Task GenerateProofAsync_FallsBackToStoredNonce_WhenOptionsNonceBlank()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        await provider.NoteNonceAsync("https://as.example.com/token", "stored-nonce");

        var proof = await provider.GenerateProofAsync(
            method: "POST",
            url: "https://as.example.com/token",
            options: null,
            cancellationToken: CancellationToken.None);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(proof);
        Assert.Equal("stored-nonce", GetClaim(jwt, "nonce"));
    }

    [Fact]
    public async Task BuildHeadersAsync_ReturnsDPoPHeader()
    {
        var provider = new DPoPProvider(DPoPKeyMaterial.CreateES256());
        var headers = await provider.BuildHeadersAsync("POST", "https://api.example.com/r");
        Assert.True(headers.ContainsKey("DPoP"));
        Assert.False(string.IsNullOrWhiteSpace(headers["DPoP"]));
    }

    private static string GetClaim(JwtSecurityToken jwt, string name)
    {
        foreach (var claim in jwt.Claims)
        {
            if (string.Equals(claim.Type, name, StringComparison.Ordinal))
            {
                return claim.Value;
            }
        }
        return string.Empty;
    }
}
