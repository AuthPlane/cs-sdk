namespace Authplane;

/// <summary>
/// Helpers for assembling OAuth request parameter maps. Wire-level
/// <c>application/x-www-form-urlencoded</c> encoding is delegated to
/// <see cref="System.Net.Http.FormUrlEncodedContent"/> in
/// <see cref="OAuthHttpClient"/>; this class only builds the
/// key→value map.
/// </summary>
internal static class OAuthRequestBodies
{
    /// <summary>
    /// Build the parameter map for an RFC 7662 introspection request or
    /// RFC 7009 revocation request. Both shapes are <c>token</c> plus an
    /// optional <c>token_type_hint</c>. Previously inlined three times
    /// across <see cref="OAuthOperations.IntrospectAsync"/>,
    /// <see cref="OAuthOperations.RevokeAsync"/>, and the latter's
    /// retry-without-hint path.
    /// </summary>
    public static Dictionary<string, string> BuildTokenForm(string token, string? tokenTypeHint)
    {
        var parameters = new Dictionary<string, string>(System.StringComparer.Ordinal)
        {
            [OAuthConstants.Params.Token] = token,
        };
        if (!string.IsNullOrWhiteSpace(tokenTypeHint))
        {
            parameters[OAuthConstants.Params.TokenTypeHint] = tokenTypeHint;
        }
        return parameters;
    }
}
