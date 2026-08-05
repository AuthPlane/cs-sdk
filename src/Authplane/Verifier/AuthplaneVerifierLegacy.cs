namespace Authplane;

/// <summary>
/// Legacy compatibility wrapper.
/// Prefer using <see cref="AuthplaneResource"/> going forward.
/// </summary>
[Obsolete("AuthplaneVerifier is a thin wrapper kept for source compatibility. Use AuthplaneResource directly. Will be removed in v0.2.0.", false)]
public sealed class AuthplaneVerifier : IAsyncDisposable
{
    private readonly AuthplaneResource _resource;

    private AuthplaneVerifier(AuthplaneResource resource)
    {
        _resource = resource ?? throw new ArgumentNullException(nameof(resource));
    }

    public string Issuer => _resource.Issuer;
    public string Resource => _resource.Resource;
    public IReadOnlyList<string> Scopes => _resource.Scopes;
    public FetchSettings FetchSettings => _resource.FetchSettings;

    public static async Task<AuthplaneVerifier> CreateAsync(
        string issuer,
        string resource,
        IEnumerable<string> scopes,
        FetchSettings? fetchSettings = null,
        CancellationToken cancellationToken = default)
    {
        var resourceInstance = await AuthplaneResource.CreateAsync(
            issuer: issuer,
            resource: resource,
            scopes: scopes,
            fetchSettings: fetchSettings,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return new AuthplaneVerifier(resourceInstance);
    }

    public Task<VerifiedClaims> VerifyAsync(
        string token,
        CancellationToken cancellationToken = default) =>
        _resource.VerifyAsync(token, cancellationToken);

    public Task<VerifiedClaims> VerifyAsync(
        string token,
        DPoPRequestContext? dpopRequest,
        CancellationToken cancellationToken = default) =>
        _resource.VerifyAsync(token, dpopRequest, cancellationToken);

    public ProtectedResourceMetadata GetProtectedResourceMetadata() =>
        _resource.GetProtectedResourceMetadata();

    public ValueTask DisposeAsync() => _resource.DisposeAsync();
}

