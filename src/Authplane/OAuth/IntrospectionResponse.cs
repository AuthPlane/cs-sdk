using System.Text.Json;

namespace Authplane;

/// <summary>
/// OAuth 2.1 token introspection response (RFC 7662).
/// </summary>
public sealed class IntrospectionResponse
{
    public bool Active { get; }
    public string? Scope { get; }
    public string? ClientId { get; }
    public string? Sub { get; }
    public string? TokenType { get; }
    public string? Iss { get; }
    public IReadOnlyList<string>? Aud { get; }
    public long? Exp { get; }
    public long? Iat { get; }
    public string? Jti { get; }

    // Authplane extension fields (optional).
    public string? AgentId { get; }
    public IReadOnlyList<string>? AgentChain { get; }

    /// <summary>
    /// Raw RFC 9449 §6.2 / RFC 7662 confirmation (<c>cnf</c>) object from the
    /// introspection response. Preserves extension members verbatim
    /// (<c>x5t#S256</c>, future RFC 9449 additions) for callers that need
    /// shapes the typed accessors don't expose. Null when the AS did not
    /// emit <c>cnf</c>, or when the value was a non-object scalar: a
    /// malformed AS does not pollute the typed shape. The returned
    /// <see cref="JsonElement"/> is cloned, so it survives independent of
    /// the parser's <see cref="JsonDocument"/> lifetime.
    /// </summary>
    public JsonElement? Cnf { get; }

    /// <summary>
    /// Convenience accessor for the DPoP key thumbprint at <c>cnf.jkt</c>
    /// (RFC 9449 §6.2). Null when the token is not DPoP-bound. Always
    /// derived from <see cref="Cnf"/> at parse time, so the two stay
    /// symmetric — a wire payload that pinned a top-level <c>cnf_jkt</c>
    /// disagreeing with its own <c>cnf.jkt</c> cannot mint a mismatched
    /// thumbprint.
    /// </summary>
    public string? CnfJkt { get; }

    public IntrospectionResponse(
        bool active,
        string? scope,
        string? clientId,
        string? sub,
        string? tokenType,
        string? iss,
        IReadOnlyList<string>? aud,
        long? exp,
        long? iat,
        string? jti,
        string? agentId,
        IReadOnlyList<string>? agentChain,
        JsonElement? cnf = null,
        string? cnfJkt = null)
    {
        Active = active;
        Scope = scope;
        ClientId = clientId;
        Sub = sub;
        TokenType = tokenType;
        Iss = iss;
        Aud = aud;
        Exp = exp;
        Iat = iat;
        Jti = jti;
        AgentId = agentId;
        AgentChain = agentChain;
        Cnf = cnf;
        CnfJkt = cnfJkt;
    }
}

