using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Covers <see cref="VerifiedClaims"/>: ctor null guards, scope helpers,
/// HasClaim with value-match, RFC 8693 actor accessors.
/// </summary>
public sealed class VerifiedClaimsTests
{
    private static VerifiedClaims Build(
        IReadOnlyList<string>? scopes = null,
        IReadOnlyDictionary<string, object?>? raw = null) =>
        new(
            sub: "user_1",
            clientId: "client_1",
            scopes: scopes ?? new[] { "tools/add", "tools/multiply" },
            agentId: "",
            agentChain: Array.Empty<string>(),
            issuer: "https://issuer.example.com",
            audience: new[] { "https://api.example.com" },
            expiresAt: 100,
            notBefore: 50,
            issuedAt: 60,
            jti: "jti_1",
            kid: "kid_1",
            raw: raw ?? new Dictionary<string, object?>(StringComparer.Ordinal));

    [Fact]
    public void HasScope_ExactMatchOnly()
    {
        var c = Build(new[] { "tools/add" });
        Assert.True(c.HasScope("tools/add"));
        Assert.False(c.HasScope("tools/multiply"));
        Assert.False(c.HasScope("TOOLS/ADD")); // case-sensitive
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void HasScope_BlankInput_ReturnsFalse(string? scope)
    {
        Assert.False(Build().HasScope(scope!));
    }

    [Fact]
    public void RequireScope_Throws_WhenMissing()
    {
        var c = Build(new[] { "tools/add" });
        var ex = Assert.Throws<InsufficientScopeException>(() => c.RequireScope("tools/multiply"));
        Assert.Contains("tools/multiply", ex.Message, StringComparison.Ordinal);
        Assert.Contains("tools/add", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RequireScope_DoesNotThrow_WhenPresent()
    {
        var c = Build(new[] { "tools/add" });
        c.RequireScope("tools/add"); // would throw on missing — survives = passed
    }

    [Fact]
    public void Act_ReturnsActSubFromRaw_WhenStructured()
    {
        var actDict = new Dictionary<string, object?>(StringComparer.Ordinal) { ["sub"] = "actor_1" };
        var raw = new Dictionary<string, object?>(StringComparer.Ordinal) { ["act"] = actDict };
        Assert.Equal("actor_1", Build(raw: raw).Act);
    }

    [Fact]
    public void Act_ReturnsEmpty_WhenAbsentOrWrongShape()
    {
        Assert.Equal(string.Empty, Build().Act);
        var rawWithString = new Dictionary<string, object?>(StringComparer.Ordinal) { ["act"] = "not_a_dict" };
        Assert.Equal(string.Empty, Build(raw: rawWithString).Act);
    }

    [Fact]
    public void MayAct_ReturnsMayActSubFromRaw_WhenStructured()
    {
        var mayActDict = new Dictionary<string, object?>(StringComparer.Ordinal) { ["sub"] = "delegate_1" };
        var raw = new Dictionary<string, object?>(StringComparer.Ordinal) { ["may_act"] = mayActDict };
        Assert.Equal("delegate_1", Build(raw: raw).MayAct);
    }

    [Fact]
    public void MayAct_ReturnsEmpty_WhenAbsent()
    {
        Assert.Equal(string.Empty, Build().MayAct);
    }

    [Fact]
    public void HasClaim_KeyOnly_ReturnsTrueIfKeyPresent()
    {
        var raw = new Dictionary<string, object?>(StringComparer.Ordinal) { ["custom"] = "x" };
        var c = Build(raw: raw);
        Assert.True(c.HasClaim("custom"));
        Assert.False(c.HasClaim("missing"));
    }

    [Fact]
    public void HasClaim_KeyAndValue_RequiresEqualValue()
    {
        var raw = new Dictionary<string, object?>(StringComparer.Ordinal) { ["custom"] = 42 };
        var c = Build(raw: raw);
        Assert.True(c.HasClaim("custom", 42));
        Assert.False(c.HasClaim("custom", 99));
    }

    [Fact]
    public void Ctor_NullArgsThrow()
    {
        var raw = new Dictionary<string, object?>(StringComparer.Ordinal);
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: null!, clientId: "c", scopes: Array.Empty<string>(), agentId: "", agentChain: Array.Empty<string>(),
            issuer: "i", audience: Array.Empty<string>(), expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: "k", raw: raw));
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: "s", clientId: null!, scopes: Array.Empty<string>(), agentId: "", agentChain: Array.Empty<string>(),
            issuer: "i", audience: Array.Empty<string>(), expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: "k", raw: raw));
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: "s", clientId: "c", scopes: null!, agentId: "", agentChain: Array.Empty<string>(),
            issuer: "i", audience: Array.Empty<string>(), expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: "k", raw: raw));
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: "s", clientId: "c", scopes: Array.Empty<string>(), agentId: "", agentChain: Array.Empty<string>(),
            issuer: null!, audience: Array.Empty<string>(), expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: "k", raw: raw));
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: "s", clientId: "c", scopes: Array.Empty<string>(), agentId: "", agentChain: Array.Empty<string>(),
            issuer: "i", audience: null!, expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: "k", raw: raw));
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: "s", clientId: "c", scopes: Array.Empty<string>(), agentId: "", agentChain: Array.Empty<string>(),
            issuer: "i", audience: Array.Empty<string>(), expiresAt: 0, notBefore: 0, issuedAt: 0, jti: null!, kid: "k", raw: raw));
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: "s", clientId: "c", scopes: Array.Empty<string>(), agentId: "", agentChain: Array.Empty<string>(),
            issuer: "i", audience: Array.Empty<string>(), expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: null!, raw: raw));
        Assert.Throws<ArgumentNullException>(() => new VerifiedClaims(
            sub: "s", clientId: "c", scopes: Array.Empty<string>(), agentId: "", agentChain: Array.Empty<string>(),
            issuer: "i", audience: Array.Empty<string>(), expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: "k", raw: null!));
    }

    [Fact]
    public void Ctor_NullAgentIdAndChain_DefaultToEmpty()
    {
        var c = new VerifiedClaims(
            sub: "s", clientId: "c", scopes: Array.Empty<string>(),
            agentId: null!, agentChain: null!,
            issuer: "i", audience: Array.Empty<string>(),
            expiresAt: 0, notBefore: 0, issuedAt: 0, jti: "j", kid: "k",
            raw: new Dictionary<string, object?>(StringComparer.Ordinal));
        Assert.Equal(string.Empty, c.AgentId);
        Assert.Empty(c.AgentChain);
    }
}
