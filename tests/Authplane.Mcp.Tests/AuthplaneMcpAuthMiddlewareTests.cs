using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Authplane.Mcp.Tests;

public sealed class AuthplaneMcpAuthMiddlewareTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly int _port;
    private readonly string _issuer;
    private readonly string _resource;
    private readonly string _kid;
    private readonly ECDsa _ecdsa;

    public AuthplaneMcpAuthMiddlewareTests()
    {
        _ecdsa = Ecdsa.GenerateP256();
        (_issuer, _listener) = LoopbackHttpListener.Start();
        _port = new Uri(_issuer).Port;
        _resource = "http://localhost:8080/mcp";
        _kid = "kid_1";

        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext? ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().WaitAsync(TimeSpan.FromSeconds(1));
                }
                catch
                {
                    continue;
                }

                if (ctx is null)
                {
                    continue;
                }

                try
                {
                    if (ctx.Request.Url is null)
                    {
                        ctx.Response.StatusCode = 404;
                        continue;
                    }

                    var path = ctx.Request.Url.AbsolutePath.TrimEnd('/');
                    if (string.Equals(path, "/.well-known/jwks.json", StringComparison.Ordinal))
                    {
                        var jwks = JwksForEs256(_ecdsa, _kid);
                        var bytes = Encoding.UTF8.GetBytes(jwks);
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes);
                    }
                    else if (path.StartsWith("/.well-known/oauth-authorization-server", StringComparison.Ordinal) ||
                             path.StartsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
                    {
                        var meta = $"{{\"issuer\":\"{_issuer}\",\"jwks_uri\":\"{_issuer}/.well-known/jwks.json\"}}";
                        var bytes = Encoding.UTF8.GetBytes(meta);
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

        _ecdsa.Dispose();
    }

    [Fact]
    public async Task BearerDPoPBound_MissingDPoPHeader_Returns401()
    {
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" });

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: "test-jkt",
            scope: "tools/add");

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);

        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "add");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task MultipleDPoPHeaders_Returns401_WithInvalidDPoPProofCode()
    {
        // RFC 9449 §4.3 #1 — two DPoP headers on the same request must be
        // rejected before any proof validation, on the DPoP-scheme
        // challenge with error="invalid_dpop_proof" (RFC 9449 §7.1). This
        // is the one DPoP failure carrying that code; the others stay on
        // invalid_token.
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" });

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: "test-jkt",
            scope: "tools/add");

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);

        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "add",
            dpopHeaders: new[] { "proof-one", "proof-two" });

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.StartsWith("DPoP", www, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_dpop_proof\"", www, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CommaFoldedDPoPHeader_Returns401_WithInvalidDPoPProofCode()
    {
        // RFC 9110 §5.3 — a header-folding proxy (NGINX/Envoy) may combine
        // the two DPoP field lines into one comma-separated value before
        // the request reaches the middleware. The §4.3 cardinality check
        // must still fire on the folded shape.
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" });

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: "test-jkt",
            scope: "tools/add");

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);

        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "add",
            dpopHeaders: new[] { "proof-one,proof-two" });

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.StartsWith("DPoP", www, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_dpop_proof\"", www, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SingleValidDPoPProof_Returns200()
    {
        // Success path through the middleware's FromHeaderValues hand-off
        // and URL/htu construction: one real proof, DPoP-bound token,
        // VerifyAsync succeeds. The DPoPHtu_* tests below cover the same
        // path under adversarial request shapes; this pins the plain one.
        var ctx = await InvokeBoundDpopRequestAsync(
            spoofedHost: new HostString("localhost", 8080),
            spoofedScheme: "http",
            spoofedPath: "/mcp");

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task ScopeEnforcement_DerivedFromToolsCall_Returns403()
    {
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" });

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);

        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "multiply");

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task ScopeEnforcement_DerivedFromToolsCall_Returns200_WhenScopeMatches()
    {
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" });

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);

        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "add");

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task ScopeEnforcement_HeaderOverridesToolsCallPayload()
    {
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" });

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);

        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "add",
            requiredScopesHeader: "tools/multiply");

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task GetProtectedResourceMetadata_WithoutAuth_Returns200Json()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokePrmDocumentGetAsync(requestDelegate, provider);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.Equal("application/json; charset=utf-8", ctx.Response.ContentType);

        ctx.Response.Body.Position = 0;
        using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(_resource, doc.RootElement.GetProperty("resource").GetString());
        Assert.Equal(_issuer, doc.RootElement.GetProperty("authorization_servers")[0].GetString());
    }

    [Fact]
    public async Task GetProtectedResourceMetadata_AtRootWellKnownPath_AlsoReturns200Json()
    {
        // MCP authorization spec discovery uses /.well-known/oauth-protected-resource
        // (root) regardless of the resource URI's path. RFC 9728 §3.1 prefers the
        // per-resource suffix but treats the root as the default location, so we
        // serve both. Without this, Claude Code / Inspector stay stuck in the
        // pre-auth state because their PRM probe gets 401.
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = new DefaultHttpContext
        {
            RequestServices = provider,
        };
        ctx.Request.Scheme = "http";
        ctx.Request.Host = new HostString("localhost", 8080);
        ctx.Request.PathBase = PathString.Empty;
        ctx.Request.Path = "/.well-known/oauth-protected-resource"; // ← root, NOT /mcp
        ctx.Request.Method = HttpMethods.Get;
        ctx.Response.Body = new System.IO.MemoryStream();

        await requestDelegate(ctx);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.Equal("application/json; charset=utf-8", ctx.Response.ContentType);
        ctx.Response.Body.Position = 0;
        using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(_resource, doc.RootElement.GetProperty("resource").GetString());
    }

    [Fact]
    public async Task ResourceWithQuery_ChallengeAdvertisesQuery_AndPrmRouteStaysPathKeyed()
    {
        // RFC 9728 §3 — the well-known string goes "between the host component
        // and the path and/or query components, if any", so a resource
        // identifier carrying a query advertises a query-bearing document URL
        // in the WWW-Authenticate challenge. Routing stays path-keyed: the
        // same path serves the document regardless of the request's query.
        var queryResource = "http://localhost:8080/mcp?tenant=a";
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: queryResource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true));
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: queryResource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.Contains(
            "resource_metadata=\"http://localhost:8080/.well-known/oauth-protected-resource/mcp?tenant=a\"",
            www,
            StringComparison.Ordinal);

        // A GET of the advertised URL *verbatim* — path and query — is the one
        // request a client that just read `resource_metadata` will perform.
        // ASP.NET Core routes on Request.Path (the query lands in
        // Request.QueryString), so the query-bearing GET must serve the
        // document too.
        var verbatimCtx = await InvokePrmDocumentGetAsync(
            requestDelegate, provider, queryString: "?tenant=a");
        Assert.Equal(StatusCodes.Status200OK, verbatimCtx.Response.StatusCode);
        verbatimCtx.Response.Body.Position = 0;
        using (var verbatimReader = new System.IO.StreamReader(
            verbatimCtx.Response.Body, Encoding.UTF8, leaveOpen: true))
        {
            var verbatimBody = await verbatimReader.ReadToEndAsync();
            using var verbatimDoc = JsonDocument.Parse(verbatimBody);
            Assert.Equal(queryResource, verbatimDoc.RootElement.GetProperty("resource").GetString());
        }

        // The bare path (query excluded) also serves the PRM document, whose
        // `resource` field echoes the identifier verbatim, query included.
        var getCtx = await InvokePrmDocumentGetAsync(requestDelegate, provider);
        Assert.Equal(StatusCodes.Status200OK, getCtx.Response.StatusCode);
        getCtx.Response.Body.Position = 0;
        using var reader = new System.IO.StreamReader(getCtx.Response.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(queryResource, doc.RootElement.GetProperty("resource").GetString());
    }

    [Fact]
    public async Task MissingAuthorizationHeader_Returns401WithWwwAuthenticate()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.StartsWith("Bearer", www, StringComparison.Ordinal);
        Assert.Contains("resource_metadata=", www, StringComparison.Ordinal);
        Assert.Contains(
            "http://localhost:8080/.well-known/oauth-protected-resource/mcp",
            www,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingAuthorizationHeader_WithRealm_IncludesRealmInWwwAuthenticate()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true,
            realm: "mcp-server");
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.StartsWith("Bearer", www, StringComparison.Ordinal);
        Assert.Contains("realm=\"mcp-server\"", www, StringComparison.Ordinal);
        Assert.Contains("resource_metadata=", www, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingAuthorizationHeader_BearerAndDPoP_EmitsTwoFieldLines()
    {
        // RFC 7235 §4.1 allows a comma-joined single line or two distinct
        // field lines. We chose the latter so that a
        // header-value comma in an auth-param (e.g. error_description) can't
        // be misparsed as a scheme separator. `.ToString()` on a multi-value
        // header collapses to a comma string and would not catch a regression
        // back to a single field line — assert on the raw count.
        //
        // The two-field-line shape only applies when the resource accepts both
        // Bearer and DPoP; pass an InboundDPoPOptions so verifier.InboundDPoP
        // is non-null and Required is false, which selects the combined
        // challenge in the middleware.
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" },
            inboundDpop: new InboundDPoPOptions());
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Equal(2, ctx.Response.Headers.WWWAuthenticate.Count);
        Assert.StartsWith("Bearer", ctx.Response.Headers.WWWAuthenticate[0]!, StringComparison.Ordinal);
        Assert.StartsWith("DPoP", ctx.Response.Headers.WWWAuthenticate[1]!, StringComparison.Ordinal);
    }

    /// <summary>
    /// H-PRM regression: when the resource is configured Bearer-only (no
    /// InboundDPoPOptions) the pre-token WWW-Authenticate challenge must
    /// advertise Bearer alone — not Bearer+DPoP. Previously the middleware
    /// emitted both schemes regardless of verifier state, so clients
    /// negotiated DPoP and then had every request rejected with
    /// DPoPNotSupportedException. PRM also omits DPoP fields in this mode,
    /// so the three surfaces (challenge, PRM, verifier) now agree.
    /// </summary>
    [Fact]
    public async Task MissingAuthorizationHeader_BearerOnlyWhenInboundDpopNull()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        Assert.Null(verifier.InboundDPoP);

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Equal(1, ctx.Response.Headers.WWWAuthenticate.Count);
        Assert.StartsWith("Bearer", ctx.Response.Headers.WWWAuthenticate[0]!, StringComparison.Ordinal);
        Assert.DoesNotContain("DPoP", ctx.Response.Headers.WWWAuthenticate[0]!.Substring(0, 10));
    }

    /// <summary>
    /// H-PRM regression: when InboundDPoPOptions.Required is true the
    /// pre-token challenge must advertise DPoP alone, since any Bearer token
    /// without a DPoP binding will be rejected. Pairs with the Bearer-only
    /// regression above to lock in the three-way scheme selection.
    /// </summary>
    [Fact]
    public async Task MissingAuthorizationHeader_DPoPOnlyWhenInboundDpopRequired()
    {
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" },
            inboundDpop: new InboundDPoPOptions(required: true));
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Equal(1, ctx.Response.Headers.WWWAuthenticate.Count);
        Assert.StartsWith("DPoP", ctx.Response.Headers.WWWAuthenticate[0]!, StringComparison.Ordinal);
        // No Bearer scheme should leak in.
        Assert.DoesNotContain("Bearer", ctx.Response.Headers.WWWAuthenticate[0]!);
    }

    [Fact]
    public async Task MissingAuthorizationHeader_InboundDpopAllowedAlgs_ReflectedInChallenge()
    {
        // RFC 9449 §7.1: the DPoP challenge `algs` parameter SHOULD reflect
        // what the resource accepts. When InboundDPoPOptions narrows the set
        // (e.g. ES256-only), the challenge must mirror that, not the default
        // "ES256 RS256" — otherwise the challenge over-advertises algorithms
        // the resource will reject, contradicting PRM's
        // `dpop_signing_alg_values_supported`.
        var inbound = new InboundDPoPOptions(
            required: false,
            allowedProofAlgorithms: new[] { "ES256" });
        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" },
            inboundDpop: inbound);
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        // The DPoP challenge (second field line) carries the narrowed algs.
        var dpopChallenge = ctx.Response.Headers.WWWAuthenticate[1]!;
        Assert.Contains("algs=\"ES256\"", dpopChallenge, StringComparison.Ordinal);
        Assert.DoesNotContain("RS256", dpopChallenge, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InvalidAuthorizationHeaderFormat_Returns401()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: $"Token {accessToken}",
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task EmptyBearerToken_Returns401()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: "Bearer   ",
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task MalformedBody_SkipsDerivedScope_AndAllowsRequest()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: $"Bearer {accessToken}",
            bodyJson: "{not-json");

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task NonToolsCallMethod_SkipsScopeDerivation_AndAllowsRequest()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}";
        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: $"Bearer {accessToken}",
            bodyJson: body);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task ToolsCallWithoutName_SkipsScopeDerivation_AndAllowsRequest()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";
        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: $"Bearer {accessToken}",
            bodyJson: body);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task RequiredScopesHeader_CommaSeparated_IsEnforced()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: null,
            scope: "tools/add");
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "add",
            requiredScopesHeader: "tools/add, tools/multiply");

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    // DPoP `htu` (RFC 9449 §4.2) verification must use the operator-configured
    // `resource` origin, not header-derived values from the inbound request. The
    // four tests below pin that contract: spoofed Host, absent Host, X-Forwarded-Proto
    // downgrade, and default-port normalization all still verify because the
    // comparison URL is built from `options.Resource`, not `Request.Host`/`Scheme`.

    [Fact]
    public async Task DPoPHtu_SpoofedHostHeader_StillValidatesAgainstConfiguredResourceOrigin()
    {
        // Proof minted with htu matching configured resource. A spoofed inbound Host
        // (`attacker.example`) must not be used to reconstruct the comparison URL —
        // otherwise an intermediary could redirect DPoP proofs across resources.
        var ctx = await InvokeBoundDpopRequestAsync(
            spoofedHost: new HostString("attacker.example"),
            spoofedScheme: "http",
            spoofedPath: "/mcp");

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task DPoPHtu_AbsentHostHeader_StillValidatesAgainstConfiguredResourceOrigin()
    {
        // The pre-fix code substituted `Request.Host` directly — when Host is missing
        // ASP.NET Core's HostString.ToString() yields the empty string, producing a
        // malformed comparison URL `http:///mcp` (parses, but with empty host). The
        // configured-origin path produces the correct `http://localhost:8080/mcp`.
        var ctx = await InvokeBoundDpopRequestAsync(
            spoofedHost: default,
            spoofedScheme: "http",
            spoofedPath: "/mcp");

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task DPoPHtu_XForwardedProtoFlipped_StillValidatesAgainstConfiguredResourceOrigin()
    {
        // Simulate a proxy that flips `Request.Scheme` to `https` (e.g. via
        // UseForwardedHeaders honouring `X-Forwarded-Proto`) while the configured
        // resource is `http://...`. The inbound scheme is *upgraded* relative
        // to the configured origin, but the proof was minted against the
        // configured origin and must verify regardless of the inbound scheme.
        // The symmetric flip (https-configured / http-inbound) reduces to the
        // same comparison — both rely on the configured origin, not on
        // `Request.Scheme`.
        var ctx = await InvokeBoundDpopRequestAsync(
            spoofedHost: new HostString("localhost", 8080),
            spoofedScheme: "https",
            spoofedPath: "/mcp");

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task DPoPHtu_DefaultPortNormalization_ProofWithExplicitPortStillValidates()
    {
        // RFC 9449 §4.2 + DPoPHtu.Normalize strip default ports (80 for http, 443 for
        // https) on both sides of the comparison. The middleware must not regress that:
        // a proof minted with htu carrying explicit `:80` against an http resource
        // configured without a port must validate. The configured resource URI is
        // built locally with explicit `:80` to exercise the Uri parser's automatic
        // default-port elision in `GetLeftPart(UriPartial.Authority)`.
        var defaultPortResource = "http://localhost:80/mcp";
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: defaultPortResource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            inboundDpop: new InboundDPoPOptions(required: true),
            cancellationToken: CancellationToken.None);

        var keyMaterial = DPoPKeyMaterial.CreateES256();
        var dpopProvider = new DPoPProvider(keyMaterial);
        var jkt = keyMaterial.Thumbprint;

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: defaultPortResource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: jkt,
            scope: "tools/add");

        // Proof's htu has the explicit `:80` port; the middleware-built URL (from
        // configured-origin) will have `:80` elided by `Uri.GetLeftPart`. Both
        // forms must normalize identically via `DPoPHtu.Normalize`.
        var proof = await dpopProvider.GenerateProofAsync(
            method: "POST",
            url: "http://localhost:80/mcp",
            options: new DPoPProofOptions(accessToken: accessToken),
            cancellationToken: CancellationToken.None);

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        services.AddSingleton<IDPoPReplayStore, InMemoryDPoPReplayStore>();
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: defaultPortResource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeWithDpopAsync(
            requestDelegate,
            provider,
            token: accessToken,
            dpopProof: proof,
            host: new HostString("localhost"),
            scheme: "http",
            path: "/mcp");

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    private async Task<HttpContext> InvokeBoundDpopRequestAsync(
        HostString spoofedHost,
        string spoofedScheme,
        string spoofedPath)
    {
        var keyMaterial = DPoPKeyMaterial.CreateES256();
        var dpopProvider = new DPoPProvider(keyMaterial);
        var jkt = keyMaterial.Thumbprint;

        var verifier = await CreateResourceAsync(
            tokenScopes: new[] { "tools/add" },
            inboundDpop: new InboundDPoPOptions(required: true));

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: jkt,
            scope: "tools/add");

        // Proof's htu is built from the configured resource (the operator-controlled
        // origin) — the same value the middleware must derive from `options.Resource`.
        var proof = await dpopProvider.GenerateProofAsync(
            method: "POST",
            url: _resource,
            options: new DPoPProofOptions(accessToken: accessToken),
            cancellationToken: CancellationToken.None);

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        services.AddSingleton<IDPoPReplayStore, InMemoryDPoPReplayStore>();
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        return await InvokeWithDpopAsync(
            requestDelegate,
            provider,
            token: accessToken,
            dpopProof: proof,
            host: spoofedHost,
            scheme: spoofedScheme,
            path: spoofedPath);
    }

    private static async Task<HttpContext> InvokeWithDpopAsync(
        RequestDelegate requestDelegate,
        ServiceProvider provider,
        string token,
        string dpopProof,
        HostString host,
        string scheme,
        string path)
    {
        var ctx = new DefaultHttpContext { RequestServices = provider };
        ctx.Request.Scheme = scheme;
        ctx.Request.Host = host;
        ctx.Request.PathBase = PathString.Empty;
        ctx.Request.Path = path;
        ctx.Request.Method = "POST";
        ctx.Request.ContentType = "application/json";
        ctx.Request.Headers["Authorization"] = $"DPoP {token}";
        ctx.Request.Headers["DPoP"] = dpopProof;

        var bodyJson = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"add\",\"arguments\":{\"a\":2,\"b\":3}}}";
        ctx.Request.Body = new System.IO.MemoryStream(Encoding.UTF8.GetBytes(bodyJson));
        ctx.Response.Body = new System.IO.MemoryStream();

        await requestDelegate(ctx);
        return ctx;
    }

    private static RequestDelegate BuildPipeline(
        ServiceProvider provider,
        AuthplaneMcpAuth.Options options)
    {
        var builder = new ApplicationBuilder(provider);
        builder.UseAuthplaneMcpAuth(options);
        builder.Run(_ =>
        {
            _.Response.StatusCode = StatusCodes.Status200OK;
            return Task.CompletedTask;
        });
        return builder.Build();
    }

    private async Task<AuthplaneResource> CreateResourceAsync(
        IReadOnlyList<string> tokenScopes,
        InboundDPoPOptions? inboundDpop = null)
    {
        // Scopes passed here are only used for PRM metadata in this minimal verifier implementation.
        // The middleware enforcement comes from token's "scope" claim and VerifiedClaims.RequireScope().
        return await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: tokenScopes,
            fetchSettings: FetchSettings.FromDevMode(devMode: true),
            inboundDpop: inboundDpop,
            cancellationToken: CancellationToken.None);
    }

    private string MintAccessToken(
        string issuer,
        string audience,
        ECDsa ecdsa,
        string kid,
        string? cnfJkt,
        string scope)
    {
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();

        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString("n");
        var exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();

        var ecdsaKey = new ECDsaSecurityKey(ecdsa)
        {
            KeyId = kid
        };

        var signingCredentials = new SigningCredentials(
            ecdsaKey,
            SecurityAlgorithms.EcdsaSha256);

        var subjectClaims = new List<System.Security.Claims.Claim>
        {
            new("sub", "user_1"),
            new("client_id", "client_1"),
            new("scope", scope),
            new("jti", jti),
            new("iat", iat.ToString()),
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime,
            NotBefore = DateTimeOffset.FromUnixTimeSeconds(iat).AddSeconds(-10).UtcDateTime,
            SigningCredentials = signingCredentials,
            TokenType = "at+jwt",
            Subject = new System.Security.Claims.ClaimsIdentity(subjectClaims),
        };

        var token = handler.CreateToken(descriptor);
        // Set cnf as a proper JSON object per RFC 7800.
        if (!string.IsNullOrWhiteSpace(cnfJkt) && token is JwtSecurityToken jwt)
        {
            jwt.Payload["cnf"] = new Dictionary<string, object> { ["jkt"] = cnfJkt };
        }
        return handler.WriteToken(token);
    }

    private async Task<HttpContext> InvokeAsync(
        RequestDelegate requestDelegate,
        ServiceProvider provider,
        string token,
        string authScheme,
        string? dpopHeader,
        string mcpToolCallName,
        string? requiredScopesHeader = null,
        string[]? dpopHeaders = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.RequestServices = provider;

        ctx.Request.Scheme = "http";
        ctx.Request.Host = new Microsoft.AspNetCore.Http.HostString("localhost", 8080);
        ctx.Request.PathBase = "";
        ctx.Request.Path = "/mcp";

        ctx.Request.Method = "POST";
        ctx.Request.ContentType = "application/json";

        ctx.Request.Headers["Authorization"] = $"{authScheme} {token}";
        if (dpopHeaders is not null)
        {
            ctx.Request.Headers["DPoP"] = new Microsoft.Extensions.Primitives.StringValues(dpopHeaders);
        }
        else if (!string.IsNullOrWhiteSpace(dpopHeader))
        {
            ctx.Request.Headers["DPoP"] = dpopHeader;
        }

        if (!string.IsNullOrWhiteSpace(requiredScopesHeader))
        {
            ctx.Request.Headers["x-authplane-required-scopes"] = requiredScopesHeader;
        }

        var toolCallJson = JsonSerializer.Serialize(
            new Dictionary<string, object?>
            {
                ["jsonrpc"] = "2.0",
                ["id"] = 2,
                ["method"] = "tools/call",
                ["params"] = new
                {
                    name = mcpToolCallName,
                    arguments = new { a = 2, b = 3 },
                },
            });
        var bodyBytes = Encoding.UTF8.GetBytes(toolCallJson);
        ctx.Request.Body = new System.IO.MemoryStream(bodyBytes);

        await requestDelegate(ctx);
        return ctx;
    }

    private async Task<HttpContext> InvokePrmDocumentGetAsync(
        RequestDelegate requestDelegate,
        ServiceProvider provider,
        string? queryString = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.RequestServices = provider;
        ctx.Request.Scheme = "http";
        ctx.Request.Host = new HostString("localhost", 8080);
        ctx.Request.PathBase = PathString.Empty;
        ctx.Request.Path = "/.well-known/oauth-protected-resource/mcp";
        ctx.Request.QueryString = queryString is null ? QueryString.Empty : new QueryString(queryString);
        ctx.Request.Method = HttpMethods.Get;
        ctx.Response.Body = new System.IO.MemoryStream();

        await requestDelegate(ctx).ConfigureAwait(false);
        return ctx;
    }

    private async Task<HttpContext> InvokeRawAsync(
        RequestDelegate requestDelegate,
        ServiceProvider provider,
        string? authorizationHeader,
        string bodyJson)
    {
        var ctx = new DefaultHttpContext();
        ctx.RequestServices = provider;

        ctx.Request.Scheme = "http";
        ctx.Request.Host = new Microsoft.AspNetCore.Http.HostString("localhost", 8080);
        ctx.Request.PathBase = "";
        ctx.Request.Path = "/mcp";
        ctx.Request.Method = "POST";
        ctx.Request.ContentType = "application/json";

        if (authorizationHeader is not null)
        {
            ctx.Request.Headers["Authorization"] = authorizationHeader;
        }

        var bodyBytes = Encoding.UTF8.GetBytes(bodyJson);
        ctx.Request.Body = new System.IO.MemoryStream(bodyBytes);

        ctx.Response.Body = new System.IO.MemoryStream();

        await requestDelegate(ctx);
        return ctx;
    }


    private static string JwksForEs256(ECDsa ecdsa, string kid)
    {
        var p = ecdsa.ExportParameters(false);

        static string Base64UrlEncode(byte[] bytes)
        {
            var b64 = Convert.ToBase64String(bytes);
            return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        var x = Base64UrlEncode(p.Q!.X!);
        var y = Base64UrlEncode(p.Q!.Y!);

        return $@"{{
  ""keys"": [
    {{
      ""kty"": ""EC"",
      ""crv"": ""P-256"",
      ""kid"": ""{kid}"",
      ""use"": ""sig"",
      ""alg"": ""ES256"",
      ""x"": ""{x}"",
      ""y"": ""{y}""
    }}
  ]
}}";
    }

    private static class Ecdsa
    {
        public static ECDsa GenerateP256() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }
}

