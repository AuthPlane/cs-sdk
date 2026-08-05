namespace Authplane;

/// <summary>
/// Stateless OAuth client operations against the AS. The grant orchestration lives here
/// (parameter assembly, endpoint URL construction, response parsing); the network plumbing
/// (HTTP, DPoP nonce retry, response decoding) lives in
/// <see cref="OAuthHttpClient"/>.
/// </summary>
internal static partial class OAuthOperations
{
    /// <summary>
    /// Snapshot of the AS-bound configuration needed by every OAuth client operation.
    /// </summary>
    // `AuthProvider`, when set, replaces the fallback HTTP-Basic-from-
    // ClientId/ClientSecret path in OAuthHttpClient. Allows callers to plug
    // in alternate header-based client-authentication schemes (e.g. mTLS-fronted
    // setups that need additional headers) without modifying the OAuth client.
    // OAuth client-assertion schemes such as RFC 7523 `private_key_jwt` are out
    // of scope here — those mint a `client_assertion` form parameter, not an
    // HTTP header, and would belong in OAuthRequestBodies.
    internal sealed record Context(
        string IssuerUrl,
        string ClientId,
        string ClientSecret,
        HttpClient HttpClient,
        IDPoPSigner? DPoPSigner,
        FetchSettings FetchSettings,
        IDPoPNonceStore? DPoPNonceStore = null,
        IAuthProvider? AuthProvider = null);

    public static Task<TokenResponse> ClientCredentialsAsync(
        Context context,
        string? scope,
        string? resource,
        CancellationToken cancellationToken)
    {
        return ClientCredentialsAsync(
            context,
            scope,
            resource is null ? null : new[] { resource },
            cancellationToken);
    }

    public static Task<TokenResponse> ClientCredentialsAsync(
        Context context,
        string? scope,
        IReadOnlyList<string>? resources,
        CancellationToken cancellationToken)
    {
        var parameters = new List<KeyValuePair<string, string>>
        {
            new(OAuthConstants.Params.GrantType, OAuthConstants.GrantTypeClientCredentials)
        };
        if (!string.IsNullOrWhiteSpace(scope))
        {
            parameters.Add(new(OAuthConstants.Params.Scope, scope!));
        }

        if (resources is not null)
        {
            foreach (var r in resources)
            {
                if (!string.IsNullOrWhiteSpace(r))
                {
                    parameters.Add(new(OAuthConstants.Params.Resource, r));
                }
            }
        }

        return OAuthHttpClient.DoTokenRequestAsync(context, parameters, nonce: null, cancellationToken);
    }

    public static Task<TokenResponse> TokenExchangeAsync(
        Context context,
        TokenExchangeOptions opts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(opts);

        var parameters = new List<KeyValuePair<string, string>>
        {
            new(OAuthConstants.Params.GrantType, OAuthConstants.GrantTypeTokenExchange),
            new(OAuthConstants.Params.SubjectToken, opts.SubjectToken),
            new(OAuthConstants.Params.SubjectTokenType, opts.SubjectTokenType ?? OAuthConstants.TokenTypeAccessToken)
        };

        if (!string.IsNullOrWhiteSpace(opts.ActorToken))
        {
            parameters.Add(new(OAuthConstants.Params.ActorToken, opts.ActorToken!));
            parameters.Add(new(OAuthConstants.Params.ActorTokenType,
                opts.ActorTokenType ?? OAuthConstants.TokenTypeAccessToken));
        }

        if (!string.IsNullOrWhiteSpace(opts.RequestedTokenType))
        {
            parameters.Add(new(OAuthConstants.Params.RequestedTokenType, opts.RequestedTokenType!));
        }

        if (!string.IsNullOrWhiteSpace(opts.Scope))
        {
            parameters.Add(new(OAuthConstants.Params.Scope, opts.Scope!));
        }

        if (opts.Resources is not null)
        {
            foreach (var r in opts.Resources)
            {
                if (!string.IsNullOrWhiteSpace(r))
                {
                    parameters.Add(new(OAuthConstants.Params.Resource, r));
                }
            }
        }

        if (opts.Audiences is not null)
        {
            foreach (var a in opts.Audiences)
            {
                if (!string.IsNullOrWhiteSpace(a))
                {
                    parameters.Add(new(OAuthConstants.Params.Audience, a));
                }
            }
        }

        return OAuthHttpClient.DoTokenRequestAsync(context, parameters, nonce: null, cancellationToken,
            isTokenExchange: true);
    }

    public static async Task<IntrospectionResponse> IntrospectAsync(
        Context context,
        string token,
        CancellationToken cancellationToken,
        string tokenTypeHint = OAuthConstants.TokenTypeHintAccessToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var parameters = OAuthRequestBodies.BuildTokenForm(token, tokenTypeHint);

        var url = OAuthEndpoints.IntrospectionUrl(context.IssuerUrl);
        var body = await OAuthHttpClient.DoPostFormAsync(
            context,
            url,
            parameters,
            "introspection endpoint",
            cancellationToken).ConfigureAwait(false);
        return OAuthResponseParser.ParseIntrospectionResponse(body);
    }

}
