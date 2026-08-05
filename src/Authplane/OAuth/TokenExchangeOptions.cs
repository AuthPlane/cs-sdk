namespace Authplane;

/// <summary>
/// Options for an OAuth token exchange request (RFC 8693).
/// </summary>
public sealed class TokenExchangeOptions
{
    public string SubjectToken { get; }
    public string? SubjectTokenType { get; }
    public string? ActorToken { get; }
    public string? ActorTokenType { get; }
    public string? Scope { get; }

    /// <summary>
    /// RFC 8693 §2.1 OPTIONAL. The desired token type for the issued token
    /// (e.g. <c>urn:ietf:params:oauth:token-type:access_token</c>).
    /// </summary>
    public string? RequestedTokenType { get; }

    /// <summary>
    /// One or more resource indicators (RFC 8707). Each value is emitted as a separate
    /// <c>resource</c> form parameter. When a single string is provided via the legacy
    /// constructor overload it is wrapped into a single-element list.
    /// </summary>
    public IReadOnlyList<string>? Resources { get; }

    /// <summary>
    /// One or more audience values (RFC 8693 §2.1). Each value is emitted as a separate
    /// <c>audience</c> form parameter.
    /// </summary>
    public IReadOnlyList<string>? Audiences { get; }

    /// <summary>
    /// Backward-compatible constructor — accepts a single resource string.
    /// </summary>
    public TokenExchangeOptions(
        string subjectToken,
        string? subjectTokenType = null,
        string? actorToken = null,
        string? actorTokenType = null,
        string? scope = null,
        string? resource = null)
    {
        SubjectToken = !string.IsNullOrWhiteSpace(subjectToken)
            ? subjectToken
            : throw new ArgumentException("subjectToken is required.", nameof(subjectToken));
        SubjectTokenType = subjectTokenType;
        ActorToken = actorToken;
        ActorTokenType = actorTokenType;
        Scope = scope;
        Resources = resource is null ? null : new[] { resource };
        Audiences = null;
    }

    /// <summary>
    /// Full constructor with multi-resource and multi-audience support.
    /// </summary>
    public TokenExchangeOptions(
        string subjectToken,
        IReadOnlyList<string>? resources,
        IReadOnlyList<string>? audiences,
        string? subjectTokenType = null,
        string? actorToken = null,
        string? actorTokenType = null,
        string? scope = null)
    {
        SubjectToken = !string.IsNullOrWhiteSpace(subjectToken)
            ? subjectToken
            : throw new ArgumentException("subjectToken is required.", nameof(subjectToken));
        SubjectTokenType = subjectTokenType;
        ActorToken = actorToken;
        ActorTokenType = actorTokenType;
        Scope = scope;
        Resources = resources;
        Audiences = audiences;
    }

    /// <summary>
    /// Backward-compatible convenience property. Returns the first resource, or <c>null</c>.
    /// </summary>
    public string? Resource => Resources is { Count: > 0 } ? Resources[0] : null;
}
