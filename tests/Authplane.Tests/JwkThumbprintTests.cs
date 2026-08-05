using System.Text.Json;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Locks the canonical-JSON form of the RFC 7638 thumbprint produced by
/// <see cref="JwkThumbprint"/>. Three separate implementations of this digest
/// used to live in DPoPKeyMaterial, ES256DpoPSigner, and AuthplaneResource —
/// a drift between any two of them would silently break <c>cnf.jkt</c>
/// binding (the verifier would reject every DPoP-bound token from a signer
/// with the divergent helper, with no exception to point at the cause). A
/// fixed-vector test on the consolidated helper makes any future change to
/// member ordering, case normalisation, or padding strip immediately visible.
/// </summary>
public sealed class JwkThumbprintTests
{
    // Test vector adapted from RFC 7638 §3.1 (the spec's worked example uses
    // an RSA key; we mirror the shape here with the spec's exact expected
    // thumbprint to confirm member-order / canonicalisation match).
    private const string Rfc7638_N =
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z" +
        "wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    private const string Rfc7638_E = "AQAB";
    private const string Rfc7638_ExpectedThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    [Fact]
    public void ComputeRsa_MatchesRfc7638Example()
    {
        var thumbprint = JwkThumbprint.ComputeRsa(Rfc7638_E, Rfc7638_N);
        Assert.Equal(Rfc7638_ExpectedThumbprint, thumbprint);
    }

    [Fact]
    public void Compute_FromJsonElement_AndFromDictionary_AgreeForSameRsaKey()
    {
        // The two source-format overloads exist because the signer side holds
        // its JWK as a dictionary while the verifier deserialises the proof
        // header into a JsonElement. They MUST agree on the same key —
        // otherwise cnf.jkt binding would silently fail between the two paths.
        var dict = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["e"] = Rfc7638_E,
            ["n"] = Rfc7638_N,
        };
        var json = JsonSerializer.SerializeToElement(dict);

        Assert.Equal(JwkThumbprint.Compute(dict), JwkThumbprint.Compute(json));
        Assert.Equal(Rfc7638_ExpectedThumbprint, JwkThumbprint.Compute(json));
    }

    [Fact]
    public void Compute_EcKey_FromJsonElement_AndFromDictionary_Agree()
    {
        // EC vector — RFC 7638 doesn't ship a canonical EC example so we
        // generate it via the helper itself; the test asserts the two
        // overloads stay in lockstep regardless of what canonical bytes
        // they end up producing.
        var dict = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            ["y"] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        };
        var json = JsonSerializer.SerializeToElement(dict);

        var fromDict = JwkThumbprint.Compute(dict);
        var fromJson = JwkThumbprint.Compute(json);
        Assert.Equal(fromDict, fromJson);
        Assert.False(string.IsNullOrEmpty(fromDict));
    }

    [Theory]
    [InlineData("\"")]
    [InlineData("\\")]
    [InlineData("a\"b")]
    [InlineData("a,\"kty\":\"EC")]
    [InlineData("a b")]
    [InlineData("a\nb")]
    public void ComputeEc_RejectsNonBase64UrlChars_InEcMembers(string evil)
    {
        // Defense-in-depth: the canonical-JSON form is built by string
        // interpolation, which is only safe iff the member values are within
        // the base64url / JWA-registry alphabet. A JWK whose signature check
        // is somehow reached with a `"` or `\` in `x`/`y` must NOT be allowed
        // to produce a thumbprint via canonical-JSON injection.
        Assert.Throws<InvalidOperationException>(() =>
            JwkThumbprint.ComputeEc("P-256", evil, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"));
        Assert.Throws<InvalidOperationException>(() =>
            JwkThumbprint.ComputeEc("P-256", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", evil));
    }

    [Theory]
    [InlineData("\"")]
    [InlineData("\\")]
    [InlineData("AQAB\",\"kty\":\"RSA\",\"n\":\"hijack")]
    public void ComputeRsa_RejectsNonBase64UrlChars_InRsaMembers(string evil)
    {
        Assert.Throws<InvalidOperationException>(() =>
            JwkThumbprint.ComputeRsa(evil, Rfc7638_N));
        Assert.Throws<InvalidOperationException>(() =>
            JwkThumbprint.ComputeRsa(Rfc7638_E, evil));
    }

    [Fact]
    public void Compute_NormalisesKtyCase()
    {
        // RFC 7518 §6.1 registers "EC" / "RSA" in their uppercase form, and
        // RFC 7638 §3.2 mandates emitting kty in the canonical form for the
        // digest. A JWK with kty="ec" should still produce the same
        // thumbprint as kty="EC" — otherwise an interoperability bug looms
        // wherever a counter-party emits non-uppercase kty.
        var lower = new Dictionary<string, object>
        {
            ["kty"] = "ec",
            ["crv"] = "P-256",
            ["x"] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            ["y"] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        };
        var upper = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            ["y"] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        };

        Assert.Equal(JwkThumbprint.Compute(upper), JwkThumbprint.Compute(lower));
    }
}
