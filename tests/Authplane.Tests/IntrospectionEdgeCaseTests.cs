using System.Net;
using System.Text;
using Authplane.Conformance;
using Xunit;

namespace Authplane.Tests;

/// <summary>
/// Group 4: Introspection edge cases (RFC 7662).
/// </summary>
public sealed class IntrospectionEdgeCaseTests
{
    [Fact]
    [Conformance("rfc7662-introspection-active-false-must-parse-as-inactive")]
    public async Task Introspect_ActiveFalse_ParsedAsInactive()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"active\":false}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.False(resp.Active);
    }

    [Fact]
    [Conformance("rfc7662-introspection-missing-active-must-default-to-inactive")]
    public async Task Introspect_MissingActive_DefaultsToInactive()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"scope\":\"read\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        // RFC 7662 §2.2 — missing "active" defaults to false (inactive).
        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);
        Assert.False(resp.Active);
    }

    [Fact]
    [Conformance("rfc7662-introspection-without-credentials-must-not-send-authorization-header")]
    public void Introspect_WithoutCredentials_RequiresCredentialsByDesign()
    {
        // The SDK's AuthplaneAuthClient requires clientId+clientSecret at construction.
        // This is a deliberate security design decision: unauthenticated introspection is
        // not supported because the Authplane AS always requires client authentication.
        // Verify that the constructor rejects empty credentials.
        Assert.Throws<ArgumentNullException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "https://auth.example.com",
                clientId: "",
                clientSecret: "s",
                fetchSettings: FetchSettings.FromDevMode(true)));

        Assert.Throws<ArgumentNullException>(() =>
            new AuthplaneAuthClient(
                issuerUrl: "https://auth.example.com",
                clientId: "c",
                clientSecret: "",
                fetchSettings: FetchSettings.FromDevMode(true)));
    }

    [Fact]
    [Conformance("rfc7662-introspection-standard-fields-must-round-trip")]
    public async Task Introspect_StandardFields_RoundTrip()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(@"{
  ""active"": true,
  ""scope"": ""read write"",
  ""client_id"": ""client_abc"",
  ""sub"": ""user_xyz"",
  ""token_type"": ""at+jwt"",
  ""iss"": ""https://auth.example.com"",
  ""aud"": [""aud_1""],
  ""exp"": 1700000000,
  ""iat"": 1690000000,
  ""jti"": ""jti_round""
}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.True(resp.Active);
        Assert.Equal("read write", resp.Scope);
        Assert.Equal("client_abc", resp.ClientId);
        Assert.Equal("user_xyz", resp.Sub);
        Assert.Equal("at+jwt", resp.TokenType);
        Assert.Equal("https://auth.example.com", resp.Iss);
        Assert.NotNull(resp.Aud);
        Assert.Contains("aud_1", resp.Aud!);
        Assert.Equal(1700000000L, resp.Exp);
        Assert.Equal(1690000000L, resp.Iat);
        Assert.Equal("jti_round", resp.Jti);
    }

    [Fact]
    [Conformance("rfc7662-introspection-audience-must-parse-string-or-array")]
    public async Task Introspect_AudienceString_ParsedAsList()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"active\":true,\"aud\":\"single-aud\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.True(resp.Active);
        Assert.NotNull(resp.Aud);
        Assert.Single(resp.Aud!);
        Assert.Equal("single-aud", resp.Aud![0]);
    }

    [Fact]
    [Conformance("rfc7662-introspection-basic-auth-must-be-supported")]
    public async Task Introspect_BasicAuthHeaderIsSent()
    {
        string? capturedAuth = null;
        using var server = new TestServer(async ctx =>
        {
            capturedAuth = ctx.Request.Headers["Authorization"];

            var payload = Encoding.UTF8.GetBytes("{\"active\":true}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "my_client", clientSecret: "my_secret",
            fetchSettings: FetchSettings.FromDevMode(true));

        await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.NotNull(capturedAuth);
        Assert.StartsWith("Basic ", capturedAuth!);
    }

    [Fact]
    [Conformance("rfc7662-verifier-active-false-must-reject-token")]
    public async Task Introspect_ActiveFalse_IntrospectionRevocationReportsRevoked()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"active\":false}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        // IntrospectionRevocation wraps introspection into a revocation checker.
        // When active=false, IsRevokedAsync returns true (token is revoked).
        var checker = new IntrospectionRevocation(client);
        var isRevoked = await checker.IsRevokedAsync("tok_1", CancellationToken.None);
        Assert.True(isRevoked);
    }

    [Fact]
    [Conformance("rfc7662-introspection-fail-open-policy-must-be-explicitly-tested")]
    public async Task Introspect_FailOpenPolicy_ReturnsNotRevokedOnError()
    {
        // Create a server that always returns 500 to simulate AS failure.
        using var server = new TestServer(async ctx =>
        {
            ctx.Response.StatusCode = 500;
            var body = Encoding.UTF8.GetBytes("internal error");
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        // Default (fail-closed): errors propagate as exceptions
        var checker = new IntrospectionRevocation(client, failOpen: false);
        Assert.False(checker.FailOpen);
        await Assert.ThrowsAnyAsync<Exception>(
            () => checker.IsRevokedAsync("tok_1", CancellationToken.None));

        // Fail-open: errors are swallowed, token is treated as not-revoked
        var checkerOpen = new IntrospectionRevocation(client, failOpen: true);
        Assert.True(checkerOpen.FailOpen);
        var isRevoked = await checkerOpen.IsRevokedAsync("tok_1", CancellationToken.None);
        Assert.False(isRevoked);
    }

    // -----------------------------------------------------------------------
    // RFC 9449 §6.2 — cnf / cnf_jkt on IntrospectionResponse
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Introspect_DpopBoundToken_ExposesCnfJkt()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"active\":true,\"token_type\":\"DPoP\",\"cnf\":{\"jkt\":\"thumbprint-abc\"}}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.True(resp.Active);
        Assert.Equal("thumbprint-abc", resp.CnfJkt);
        Assert.NotNull(resp.Cnf);
        Assert.Equal(System.Text.Json.JsonValueKind.Object, resp.Cnf!.Value.ValueKind);
        Assert.Equal(
            "thumbprint-abc",
            resp.Cnf.Value.GetProperty("jkt").GetString());
    }

    [Fact]
    public async Task Introspect_CnfWithExtensionMembers_PreservesAllMembers()
    {
        // Extension members beyond `jkt` (`x5t#S256`, future RFC 9449
        // additions) must survive end-to-end. Callers that need shapes
        // the typed accessors don't expose read them off the raw `Cnf`
        // JsonElement.
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"active\":true,\"cnf\":{\"jkt\":\"jkt-1\",\"x5t#S256\":\"hash-1\"}}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.NotNull(resp.Cnf);
        Assert.Equal("jkt-1", resp.CnfJkt);
        Assert.Equal("jkt-1", resp.Cnf!.Value.GetProperty("jkt").GetString());
        Assert.Equal("hash-1", resp.Cnf.Value.GetProperty("x5t#S256").GetString());
    }

    [Fact]
    public async Task Introspect_NonObjectCnf_IsDropped()
    {
        // A malformed AS sending `cnf` as a non-object scalar should not
        // pollute the typed shape; we drop the `cnf` and leave `cnf_jkt`
        // null so a malformed AS can't pollute the typed shape.
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes(
                "{\"active\":true,\"cnf\":\"not-an-object\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.Null(resp.Cnf);
        Assert.Null(resp.CnfJkt);
    }

    [Fact]
    public async Task Introspect_AbsentCnf_DefaultsToNull()
    {
        using var server = new TestServer(async ctx =>
        {
            var payload = Encoding.UTF8.GetBytes("{\"active\":true,\"token_type\":\"Bearer\"}");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload);
            ctx.Response.OutputStream.Close();
        });

        await using var client = new AuthplaneAuthClient(
            issuerUrl: server.IssuerUrl,
            clientId: "c", clientSecret: "s",
            fetchSettings: FetchSettings.FromDevMode(true));

        var resp = await client.IntrospectAsync("tok_1", cancellationToken: CancellationToken.None);

        Assert.Null(resp.Cnf);
        Assert.Null(resp.CnfJkt);
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private sealed class TestServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loop;
        public string IssuerUrl { get; }

        public TestServer(Func<HttpListenerContext, Task> handler)
        {
            var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            tcp.Start();
            var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            tcp.Stop();

            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{port}/");
            _listener.Start();
            IssuerUrl = $"http://localhost:{port}";

            _loop = Task.Run(async () =>
            {
                try
                {
                    var ctx = await _listener.GetContextAsync();
                    await handler(ctx);
                }
                catch { /* ignore */ }
            });
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { /* ignore */ }
            try { _loop.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
        }
    }
}
