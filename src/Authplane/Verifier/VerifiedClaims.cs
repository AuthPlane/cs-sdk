namespace Authplane;

public sealed class VerifiedClaims
{
    public string Sub { get; }
    public string ClientId { get; }
    public IReadOnlyList<string> Scopes { get; }
    public string AgentId { get; }
    public IReadOnlyList<string> AgentChain { get; }
    public string Issuer { get; }
    public IReadOnlyList<string> Audience { get; }
    public long ExpiresAt { get; }
    public long NotBefore { get; }
    public long IssuedAt { get; }
    public string Jti { get; }
    public string Kid { get; }
    public IReadOnlyDictionary<string, object?> Raw { get; }

    public VerifiedClaims(
        string sub,
        string clientId,
        IReadOnlyList<string> scopes,
        string agentId,
        IReadOnlyList<string> agentChain,
        string issuer,
        IReadOnlyList<string> audience,
        long expiresAt,
        long notBefore,
        long issuedAt,
        string jti,
        string kid,
        IReadOnlyDictionary<string, object?> raw)
    {
        Sub = sub ?? throw new ArgumentNullException(nameof(sub));
        ClientId = clientId ?? throw new ArgumentNullException(nameof(clientId));
        Scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        AgentId = agentId ?? string.Empty;
        AgentChain = agentChain ?? Array.Empty<string>();
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        Audience = audience ?? throw new ArgumentNullException(nameof(audience));
        ExpiresAt = expiresAt;
        NotBefore = notBefore;
        IssuedAt = issuedAt;
        Jti = jti ?? throw new ArgumentNullException(nameof(jti));
        Kid = kid ?? throw new ArgumentNullException(nameof(kid));
        Raw = raw ?? throw new ArgumentNullException(nameof(raw));
    }

    public bool HasScope(string scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return false;
        }

        foreach (var s in Scopes)
        {
            if (string.Equals(s, scope, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public void RequireScope(string scope)
    {
        if (!HasScope(scope))
        {
            throw new InsufficientScopeException(
                $"Token missing required scope '{scope}'. Token has scopes: {string.Join(' ', Scopes)}");
        }
    }

    /// <summary>RFC 8693 §4.1 actor claim (<c>act.sub</c>), or empty if absent.</summary>
    public string Act => Raw.TryGetValue("act", out var v) && v is IDictionary<string, object?> d
        && d.TryGetValue("sub", out var sub) ? sub?.ToString() ?? string.Empty : string.Empty;

    /// <summary>RFC 8693 §4.2 authorized actor claim (<c>may_act.sub</c>), or empty if absent.</summary>
    public string MayAct => Raw.TryGetValue("may_act", out var v) && v is IDictionary<string, object?> d
        && d.TryGetValue("sub", out var sub) ? sub?.ToString() ?? string.Empty : string.Empty;

    public bool HasClaim(string key, object? value = null)
    {
        if (!Raw.TryGetValue(key, out var existing))
        {
            return false;
        }

        if (value is null)
        {
            return true;
        }

        return Equals(existing, value);
    }
}

