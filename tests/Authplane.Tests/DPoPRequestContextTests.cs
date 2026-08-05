using Xunit;

namespace Authplane.Tests;

public sealed class DPoPRequestContextTests
{
    private const string Url = "https://api.example.com/mcp";

    [Fact]
    public void FromHeaderValues_ZeroProofs_ReturnsNull_BearerPath()
    {
        var ctx = DPoPRequestContext.FromHeaderValues("POST", Url, Array.Empty<string?>());
        Assert.Null(ctx);
    }

    [Fact]
    public void FromHeaderValues_WhitespaceOnlyProof_ReturnsNull_BearerPath()
    {
        var ctx = DPoPRequestContext.FromHeaderValues("POST", Url, new string?[] { "   " });
        Assert.Null(ctx);
    }

    [Fact]
    public void FromHeaderValues_SingleProof_IsTrimmed()
    {
        var ctx = DPoPRequestContext.FromHeaderValues("POST", Url, new string?[] { "  proof-jwt  " });
        Assert.NotNull(ctx);
        Assert.Equal("proof-jwt", ctx.Proof);
        Assert.Equal("POST", ctx.Method);
        Assert.Equal(Url, ctx.Url);
    }

    [Fact]
    public void FromHeaderValues_MultipleProofs_Throws()
    {
        // RFC 9449 §4.3 #1 — more than one DPoP header value rejects
        // before any proof validation.
        var ex = Assert.Throws<DPoPMultipleProofsException>(
            () => DPoPRequestContext.FromHeaderValues("POST", Url, new string?[] { "first", "second" }));
        Assert.Contains("RFC 9449", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FromHeaderValues_CommaFoldedSingleValue_Throws()
    {
        // RFC 9110 §5.3 permits an intermediary to fold repeated field
        // lines into one comma-separated value (NGINX/Envoy do), so the
        // two-proof request may arrive as a single entry. It must still
        // trip the §4.3 cardinality check — JWS compact serialization
        // never contains a literal comma, so the split is unambiguous.
        Assert.Throws<DPoPMultipleProofsException>(
            () => DPoPRequestContext.FromHeaderValues("POST", Url, new string?[] { "first,second" }));
    }

    [Fact]
    public void FromHeaderValues_CommaFoldedValueWithWhitespace_Throws()
    {
        Assert.Throws<DPoPMultipleProofsException>(
            () => DPoPRequestContext.FromHeaderValues("POST", Url, new string?[] { " first , second " }));
    }

    [Fact]
    public void FromHeaderValues_BlankSecondValue_TreatedAsSingleProof()
    {
        // An empty extra `DPoP:` field line is not a second proof — blank
        // entries are dropped before the cardinality check.
        var ctx = DPoPRequestContext.FromHeaderValues("POST", Url, new string?[] { "proof-jwt", "" });
        Assert.NotNull(ctx);
        Assert.Equal("proof-jwt", ctx.Proof);
    }

    [Fact]
    public void FromHeaderValues_AllBlankValues_ReturnsNull_BearerPath()
    {
        var ctx = DPoPRequestContext.FromHeaderValues("POST", Url, new string?[] { "", "   " });
        Assert.Null(ctx);
    }
}
