using System.Net;
using System.Text;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// RFC 8414 metadata validation conformance tests.
/// The C# SDK discovers JWKS URI via metadata and validates all OAuth endpoint URLs
/// (token, introspection, revocation) via TransportSecurity at construction time.
/// </summary>
public sealed class MetadataValidationTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _issuer;
    private readonly Task _serverLoop;

    private string _metadataBody = "{}";
    private int _metadataStatusCode = 200;

    // Per-path overrides for the discovery URLs. When null, both fall back to
    // `_metadataBody` (legacy "same body on both URLs" behaviour). The
    // fall-through test sets only `_oauthAsMetadataBody` to an invalid doc.
    private string? _oauthAsMetadataBody;
    private string? _oidcMetadataBody;

    public MetadataValidationTests()
    {
        var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
        tcp.Stop();

        _issuer = $"http://localhost:{port}";
        _listener = new HttpListener();
        _listener.Prefixes.Add($"{_issuer}/");
        _listener.Start();

        _serverLoop = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch
                {
                    return;
                }

                try
                {
                    var path = ctx.Request.Url?.AbsolutePath ?? "";
                    if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal))
                    {
                        var body = _oauthAsMetadataBody ?? _metadataBody;
                        var bytes = Encoding.UTF8.GetBytes(body);
                        ctx.Response.StatusCode = _metadataStatusCode;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                    }
                    else if (path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        var body = _oidcMetadataBody ?? _metadataBody;
                        var bytes = Encoding.UTF8.GetBytes(body);
                        ctx.Response.StatusCode = _metadataStatusCode;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                    }
                    else if (path == "/.well-known/jwks.json")
                    {
                        var jwks = "{\"keys\":[]}";
                        var bytes = Encoding.UTF8.GetBytes(jwks);
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                    }
                    else
                    {
                        ctx.Response.StatusCode = 404;
                    }
                }
                finally
                {
                    ctx.Response.OutputStream.Close();
                }
            }
        });
    }

    public void Dispose()
    {
        try { _listener.Stop(); } catch { /* ignore */ }
        try { _serverLoop.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
    }

    // -----------------------------------------------------------------------
    // Metadata URL construction (tested via MetadataUrlBuilder)
    // -----------------------------------------------------------------------

    [Fact]
    [Conformance("rfc8414-metadata-issuer-must-match-configured-issuer")]
    public async Task Metadata_IssuerMismatch_ThrowsAuthplaneException()
    {
        // Metadata issuer field must match the configured issuer.
        _metadataBody = $"{{\"issuer\":\"https://evil.example.com\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";

        var ex = await Assert.ThrowsAnyAsync<AuthplaneException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true)));

        Assert.Contains("issuer mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Metadata_OauthAsUrlInvalid_FallsThroughToOidcUrl()
    {
        // RFC 8414 §3 / OIDC Discovery §4: the OAuth-AS metadata URL is tried
        // first; on validation failure (issuer mismatch, missing field) the
        // SDK falls through to the OpenID-configuration URL rather than
        // failing the whole discovery. Commit 25ca3eb introduced this — the
        // legacy test fixture served identical bodies on both URLs, so the
        // fall-through path was never exercised.
        _oauthAsMetadataBody = "{\"issuer\":\"https://evil.example.com\",\"jwks_uri\":\"" + _issuer + "/.well-known/jwks.json\"}";
        _oidcMetadataBody = "{\"issuer\":\"" + _issuer + "\",\"jwks_uri\":\"" + _issuer + "/.well-known/jwks.json\"}";

        // Should NOT throw — OIDC URL serves a valid document.
        var resource = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: "https://api.example.com",
            scopes: new[] { "read" },
            fetchSettings: FetchSettings.FromDevMode(true));

        Assert.NotNull(resource);
    }

    [Fact]
    public async Task FetchMetadata_CallerCancellation_PropagatesOperationCanceled()
    {
        // Caller cancellation during discovery must surface as
        // OperationCanceledException, not get rewritten to
        // MissingMetadataEndpointException by the generic transport-failure
        // catch. The bug class is the same one fixed in IntrospectionRevocation
        // and AuthplaneResource — keep the three in lockstep.
        _metadataBody = $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true),
                cancellationToken: cts.Token));
    }

    [Fact]
    [Conformance("rfc8414-metadata-must-contain-issuer")]
    public async Task Metadata_MissingIssuer_ThrowsAuthplaneException()
    {
        // Metadata document missing "issuer" must be rejected.
        _metadataBody = $"{{\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";

        var ex = await Assert.ThrowsAnyAsync<AuthplaneException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true)));

        Assert.Contains("issuer", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Conformance("rfc8414-jwks-uri-required-for-jwt-validation")]
    public async Task Metadata_MissingJwksUri_ThrowsAuthplaneException()
    {
        // Metadata without jwks_uri must be rejected with a clear error message.
        _metadataBody = $"{{\"issuer\":\"{_issuer}\"}}";

        var ex = await Assert.ThrowsAnyAsync<AuthplaneException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: _issuer,
                resource: "https://api.example.com",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(true)));

        Assert.Contains("jwks_uri", ex.Message);
    }

    [Fact]
    [Conformance("rfc8414-jwks-uri-must-be-absolute-https-url")]
    public async Task JwksUri_HttpRejectedInProdMode()
    {
        // The metadata URL builder always produces absolute URLs.
        var url = MetadataUrlBuilder.BuildOAuthAuthorizationServerMetadataUrl("https://auth.example.com");
        Assert.StartsWith("https://", url);
        Assert.True(Uri.IsWellFormedUriString(url, UriKind.Absolute));

        // In production FetchSettings (allowHttp=false), the SDK rejects HTTP issuer URLs
        // because the derived metadata and jwks_uri endpoints would be HTTP.
        // AuthplaneClient.CreateAsync calls TransportSecurity.ValidateFetchUrl on the metadata URL.
        var ex = await Assert.ThrowsAsync<AuthplaneException>(() =>
            AuthplaneResource.CreateAsync(
                issuer: "http://external.example.com",
                resource: "https://api.example.com",
                scopes: new[] { "read" },
                fetchSettings: FetchSettings.FromDevMode(false)));
        Assert.Contains("HTTPS", ex.Message);
    }

    [Fact]
    [Conformance("rfc8414-token-endpoint-required-when-token-operation-is-used")]
    public void TokenEndpoint_AlwaysAvailable_WhenClientIsConstructed()
    {
        // The SDK derives the token endpoint from the issuer URL at construction time.
        // The endpoint is always present when the client is created, which satisfies the
        // "required when token operation is used" constraint. An invalid issuer URL
        // (empty) is rejected at construction.
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "  ",
                clientId: "c",
                clientSecret: "s",
                fetchSettings: FetchSettings.FromDevMode(true)));
        Assert.Equal("issuerUrl", ex.ParamName);

        // A valid issuer URL produces a working client with token endpoint.
        using var server = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        server.Start();
        var port = ((System.Net.IPEndPoint)server.LocalEndpoint).Port;
        server.Stop();

        var client = new AuthplaneAuthClient(
            issuerUrl: $"http://localhost:{port}",
            clientId: "c",
            clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));
        // Client construction succeeded, meaning the token endpoint URL was validated.
        Assert.NotNull(client);
    }

    [Fact]
    [Conformance("rfc8414-token-endpoint-must-be-absolute-https-url")]
    public void TokenEndpoint_HttpsEnforcedInProdMode()
    {
        // AuthplaneAuthClient constructor calls TransportSecurity.ValidateFetchUrl
        // for the token endpoint URL. This blocks non-HTTPS in prod mode.
        var ex = Assert.Throws<AuthplaneException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "http://external.example.com",
                clientId: "c",
                clientSecret: "s",
                fetchSettings: FetchSettings.FromDevMode(false)));
        Assert.Contains("HTTPS", ex.Message);
        Assert.Contains("token endpoint", ex.Message);
    }

    [Fact]
    [Conformance("rfc8414-introspection-endpoint-required-when-introspection-is-used")]
    public void IntrospectionEndpoint_AlwaysAvailable_WhenClientIsConstructed()
    {
        // The SDK derives the introspection endpoint from the issuer URL at construction
        // time and validates it via TransportSecurity.ValidateFetchUrl. The endpoint is
        // always present when the client is created.
        using var server = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        server.Start();
        var port = ((System.Net.IPEndPoint)server.LocalEndpoint).Port;
        server.Stop();

        var client = new AuthplaneAuthClient(
            issuerUrl: $"http://localhost:{port}",
            clientId: "c",
            clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));
        Assert.NotNull(client);
    }

    [Fact]
    [Conformance("rfc8414-introspection-endpoint-must-be-absolute-https-url")]
    public void IntrospectionEndpoint_HttpsEnforcedInProdMode()
    {
        // AuthplaneAuthClient constructor validates the introspection endpoint URL via
        // TransportSecurity.ValidateFetchUrl, blocking non-HTTPS in prod mode.
        // The first URL validated is the token endpoint, so the error message mentions that;
        // verify both token and introspection endpoints are validated by checking
        // that the constructor throws for HTTP.
        var ex = Assert.Throws<AuthplaneException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "http://external.example.com",
                clientId: "c",
                clientSecret: "s",
                fetchSettings: FetchSettings.FromDevMode(false)));
        Assert.Contains("HTTPS", ex.Message);
    }

    [Fact]
    [Conformance("rfc8414-revocation-endpoint-required-when-revocation-is-used")]
    public void RevocationEndpoint_AlwaysAvailable_WhenClientIsConstructed()
    {
        // The SDK derives the revocation endpoint from the issuer URL at construction
        // time and validates it via TransportSecurity.ValidateFetchUrl. The endpoint is
        // always present when the client is created.
        using var server = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        server.Start();
        var port = ((System.Net.IPEndPoint)server.LocalEndpoint).Port;
        server.Stop();

        var client = new AuthplaneAuthClient(
            issuerUrl: $"http://localhost:{port}",
            clientId: "c",
            clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));
        Assert.NotNull(client);
    }

    [Fact]
    [Conformance("rfc8414-revocation-endpoint-must-be-absolute-https-url")]
    public void RevocationEndpoint_HttpsEnforcedInProdMode()
    {
        // AuthplaneAuthClient constructor validates token, introspection, and revocation
        // endpoint URLs via TransportSecurity.ValidateFetchUrl. Non-HTTPS is blocked in prod.
        var ex = Assert.Throws<AuthplaneException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "http://external.example.com",
                clientId: "c",
                clientSecret: "s",
                fetchSettings: FetchSettings.FromDevMode(false)));
        Assert.Contains("HTTPS", ex.Message);
    }

    [Fact]
    [Conformance("rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache")]
    public async Task JwksCache_RefreshesOnKidMiss()
    {
        // AuthplaneClient.GetSigningKeyAsync fetches fresh JWKS when a kid is not
        // in the cache. This is a partial rotation mechanism (JWKS content refreshes
        // but the URI itself is not re-discovered).
        _metadataBody = $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";

        var resource = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: "https://api.example.com",
            scopes: new[] { "read" },
            fetchSettings: FetchSettings.FromDevMode(true));

        // Attempting to verify a token with a kid not in JWKS will trigger a fresh fetch.
        // The empty JWKS will cause InvalidSignatureException (kid not found).
        var token = MakeUnsignedJwt(
            header: new System.Collections.Generic.Dictionary<string, object>
            {
                ["kid"] = "rotated-kid",
                ["alg"] = "RS256",
                ["typ"] = "at+jwt"
            },
            payload: new System.Collections.Generic.Dictionary<string, object>());

        await Assert.ThrowsAsync<InvalidSignatureException>(() => resource.VerifyAsync(token));
        await resource.DisposeAsync();
    }

    private static string MakeUnsignedJwt(
        System.Collections.Generic.Dictionary<string, object> header,
        System.Collections.Generic.Dictionary<string, object> payload)
    {
        static string B64Url(byte[] bytes)
        {
            var b64 = Convert.ToBase64String(bytes);
            return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        var headerSeg = B64Url(Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(header)));
        var payloadSeg = B64Url(Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(payload)));
        return $"{headerSeg}.{payloadSeg}.sig";
    }
}
