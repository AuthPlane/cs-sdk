using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Authplane.Tests;

public sealed class AuthplaneAuthClientPhase3Tests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly int _port;
    private readonly string _issuerUrl;
    private readonly string _tokenPath = "/oauth/token";
    private readonly string _introspectPath = "/oauth/introspect";

    private int _tokenCallIndex;
    private string? _lastDpopNonce;

    private readonly string _clientId = "clientA";
    private readonly string _clientSecret = "secretA";

    public AuthplaneAuthClientPhase3Tests()
    {
        _listener = new HttpListener();
        _port = GetFreePort();
        _issuerUrl = $"http://127.0.0.1:{_port}";

        _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
        _listener.Start();

        _ = Task.Run(() => HandleLoopAsync(CancellationToken.None));
    }

    public void Dispose()
    {
        try
        {
            if (_listener.IsListening)
            {
                _listener.Stop();
            }
        }
        catch
        {
            // ignore
        }
    }

    [Fact]
    public async Task IntrospectAsync_ReturnsActiveAndScope()
    {
        _tokenCallIndex = 0;

        var client = new AuthplaneAuthClient(
            issuerUrl: _issuerUrl,
            clientId: _clientId,
            clientSecret: _clientSecret,
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            dpopSigner: null);

        var resp = await client.IntrospectAsync(
            token: "access-token-123",
            cancellationToken: CancellationToken.None);

        Assert.True(resp.Active);
        Assert.Equal("tools/add", resp.Scope);
        Assert.Equal("clientA", resp.ClientId);
    }

    [Fact]
    public async Task TokenExchangeAsync_SendsDpopWithoutNonceClaimOnFirstRequest()
    {
        _tokenCallIndex = 0;
        _lastDpopNonce = null;

        var dpopSigner = await ES256DpoPSigner.CreateAsync(CancellationToken.None);

        var client = new AuthplaneAuthClient(
            issuerUrl: _issuerUrl,
            clientId: _clientId,
            clientSecret: _clientSecret,
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            dpopSigner: dpopSigner);

        var resp = await client.TokenExchangeAsync(
            new TokenExchangeOptions(
                subjectToken: "subject-token-xyz",
                subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
                scope: "tools/add",
                resource: null),
            cancellationToken: CancellationToken.None);

        Assert.Equal("DPoP", resp.TokenType);
        Assert.Null(_lastDpopNonce);
    }

    [Fact]
    public async Task TokenExchangeAsync_InvalidExpiresIn_Throws()
    {
        _tokenCallIndex = 1;
        _lastDpopNonce = null;

        var dpopSigner = await ES256DpoPSigner.CreateAsync(CancellationToken.None);

        var client = new AuthplaneAuthClient(
            issuerUrl: _issuerUrl,
            clientId: _clientId,
            clientSecret: _clientSecret,
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            dpopSigner: dpopSigner);

        await Assert.ThrowsAsync<AuthplaneTokenResponseParsingException>(() =>
            client.TokenExchangeAsync(
                new TokenExchangeOptions(
                    subjectToken: "subject-token-xyz",
                    scope: "tools/add",
                    resource: (string?)null),
                CancellationToken.None));
    }

    private async Task HandleLoopAsync(CancellationToken cancellationToken)
    {
        while (_listener.IsListening && !cancellationToken.IsCancellationRequested)
        {
            HttpListenerContext? ctx = null;
            try
            {
                ctx = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch
            {
                return;
            }

            if (ctx is null)
            {
                continue;
            }

            await HandleContextAsync(ctx).ConfigureAwait(false);
        }
    }

    private async Task HandleContextAsync(HttpListenerContext ctx)
    {
        var path = ctx.Request.Url?.AbsolutePath ?? "";
        if (path == _introspectPath)
        {
            ctx.Response.ContentType = "application/json";
            var payload = Encoding.UTF8.GetBytes(
                "{\"active\":true,\"scope\":\"tools/add\",\"client_id\":\"clientA\"}");
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
            return;
        }

        if (path != _tokenPath)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.NotFound;
            ctx.Response.OutputStream.Close();
            return;
        }

        var dpopProof = ctx.Request.Headers["DPoP"];
        var payloadJson = DecodeJwtSegment(dpopProof, 1);

        _lastDpopNonce = payloadJson.RootElement.TryGetProperty("nonce", out var nonceProp) &&
                          nonceProp.ValueKind == JsonValueKind.String
            ? nonceProp.GetString()
            : null;

        ctx.Response.ContentType = "application/json";

        if (_tokenCallIndex == 0)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            var ok = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"abc-token\",\"token_type\":\"DPoP\",\"expires_in\":3600,\"scope\":\"tools/add\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}");
            await ctx.Response.OutputStream.WriteAsync(ok);
            ctx.Response.OutputStream.Close();
            _tokenCallIndex = 99;
            return;
        }

        if (_tokenCallIndex == 1)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            var ok = Encoding.UTF8.GetBytes(
                "{\"access_token\":\"abc-token\",\"token_type\":\"DPoP\",\"expires_in\":-1,\"scope\":\"tools/add\"}");
            await ctx.Response.OutputStream.WriteAsync(ok);
            ctx.Response.OutputStream.Close();
            _tokenCallIndex = 99;
            return;
        }

        ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        ctx.Response.OutputStream.Close();
    }

    private static JsonDocument DecodeJwtSegment(string? jwt, int segmentIndex)
    {
        if (string.IsNullOrWhiteSpace(jwt))
        {
            throw new InvalidOperationException("Missing DPoP proof.");
        }

        var parts = jwt.Split('.');
        if (parts.Length < segmentIndex + 1)
        {
            throw new InvalidOperationException("Invalid JWT format.");
        }

        var seg = parts[segmentIndex];
        var padded = seg + new string('=', (4 - (seg.Length % 4)) % 4);
        var bytes = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
        var json = Encoding.UTF8.GetString(bytes);
        return JsonDocument.Parse(json);
    }

    private static int GetFreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}

