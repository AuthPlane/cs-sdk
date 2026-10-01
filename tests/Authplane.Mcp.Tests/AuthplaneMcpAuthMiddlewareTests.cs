using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Authplane.Mcp.Tests;

public sealed class AuthplaneMcpAuthMiddlewareTests
    : IClassFixture<KestrelPathGroundTruth>, IDisposable
{
    private readonly KestrelPathGroundTruth _kestrel;
    private readonly HttpListener _listener;
    private readonly int _port;
    private readonly string _issuer;
    private readonly string _resource;
    private readonly string _kid;
    private readonly ECDsa _ecdsa;

    public AuthplaneMcpAuthMiddlewareTests(KestrelPathGroundTruth kestrel)
    {
        _kestrel = kestrel;
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
    public async Task Rejection_LogsTheCause_WhileTheBodyKeepsTheFixedDescription()
    {
        // The body and challenge deliberately withhold the exception's own
        // message. The operator still needs it, and this middleware is the
        // last place that holds it, so it goes to the log instead of the wire
        // — the two halves of the same decision.
        //
        // Debug, not Warning: reaching a rejection takes no credentials, so
        // logging every one higher would let an unauthenticated caller choose
        // this server's log volume.
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });

        var accessToken = MintAccessToken(
            issuer: _issuer,
            audience: _resource,
            ecdsa: _ecdsa,
            kid: _kid,
            cnfJkt: "test-jkt",
            scope: "tools/add");

        var loggerFactory = new CapturingLoggerFactory(LogLevel.Debug);
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        services.AddSingleton<ILoggerFactory>(loggerFactory);
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

        var record = Assert.Single(loggerFactory.Records);
        Assert.Equal(LogLevel.Debug, record.Level);
        Assert.NotNull(record.Exception);
        Assert.IsAssignableFrom<AuthplaneException>(record.Exception);
        Assert.Equal("Authplane.Mcp", loggerFactory.Category);

        // The message the log now carries is the one the response must not.
        ctx.Response.Body.Position = 0;
        using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        Assert.DoesNotContain(record.Exception!.Message, body, StringComparison.Ordinal);
        Assert.DoesNotContain(
            record.Exception!.Message,
            ctx.Response.Headers.WWWAuthenticate.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejection_WithNoLoggerFactoryRegistered_StillAnswers()
    {
        // Logging is optional. A host that registers none gets null from
        // GetService<ILoggerFactory>, and the call has to be a no-op rather
        // than a NullReferenceException on the rejection path — where it
        // would turn every 401 into a 500.
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });

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
    public async Task PrmDocument_IsServedAtTheAdvertisedUrl()
    {
        // The one request a client that just read `resource_metadata` will
        // perform: a GET of the derived document URL, verbatim. Driven
        // through the middleware end to end, with the request shaped the way
        // a real server delivers it — encoded bytes in
        // IHttpRequestFeature.RawTarget, decoded path in Request.Path.
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

        var documentUrl = verifier.GetProtectedResourceMetadataDocumentUrl();
        Assert.Equal("http://localhost:8080/.well-known/oauth-protected-resource/mcp", documentUrl);

        var ctx = await InvokeAdvertisedDocumentUrlGetAsync(requestDelegate, provider, documentUrl);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        ctx.Response.Body.Position = 0;
        using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(_resource, doc.RootElement.GetProperty("resource").GetString());
    }

    [Fact]
    public async Task PrmDocument_IsServedAtTheAdvertisedUrl_WhenPathCarriesAPreservedPercentEncoding()
    {
        // The %7E row: the derivation preserves the percent-encoding
        // byte-exact, so the advertised URL carries `%7E` while the decoded
        // request path carries `~`. Routing compares the encoded request
        // target against the path sliced off the derived URL, so the URL the
        // challenge advertises is the URL that answers — previously the
        // expected path was re-parsed through Uri.AbsolutePath (which
        // unescapes `%7E`) and compared against the decoded request path,
        // which happened to serve this row only by double-decoding.
        var resource = "http://localhost:8080/m%7Ecp";
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true));
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var documentUrl = verifier.GetProtectedResourceMetadataDocumentUrl();
        Assert.Equal("http://localhost:8080/.well-known/oauth-protected-resource/m%7Ecp", documentUrl);

        var ctx = await InvokeAdvertisedDocumentUrlGetAsync(requestDelegate, provider, documentUrl);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        ctx.Response.Body.Position = 0;
        using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(resource, doc.RootElement.GetProperty("resource").GetString());
    }

    [Fact]
    public async Task PrmDocument_IsServedAtTheAdvertisedUrl_WhenPathCarriesAPercentEncodedSlash()
    {
        // The %2F row — the one escape where Kestrel's path decoder and
        // Uri.UnescapeDataString disagree. Kestrel leaves %2F encoded in
        // Request.Path (decoding it would change segment structure), so a
        // fallback that unescaped the expected path with UnescapeDataString
        // compared `…/mcp/` (trimmed to `…/mcp`) against a request path still
        // carrying `…/mcp%2F`: the identifier's own advertised URL answered
        // 401 on hosts without RawTarget, and the URL a different, %2F-less
        // identifier advertises falsely matched — serving a document whose
        // `resource` member says `/mcp%2F` to a client that derived `/mcp`,
        // the exact RFC 9728 §3.3 mismatch this routing exists to avoid.
        var resource = "http://localhost:8080/mcp%2F";
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true));
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var documentUrl = verifier.GetProtectedResourceMetadataDocumentUrl();
        Assert.Equal("http://localhost:8080/.well-known/oauth-protected-resource/mcp%2F", documentUrl);

        // Served at its own advertised URL — both on a host exposing the raw
        // request target (primary comparison) and on one that does not
        // (decoded fallback).
        foreach (var populateRawTarget in new[] { true, false })
        {
            var ctx = await InvokeAdvertisedDocumentUrlGetAsync(
                requestDelegate, provider, documentUrl, populateRawTarget);

            Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
            ctx.Response.Body.Position = 0;
            using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            Assert.Equal(resource, doc.RootElement.GetProperty("resource").GetString());
        }

        // And NOT at the URL a different identifier (`…/mcp`) advertises:
        // that request must fall through to auth, not receive a document
        // whose `resource` member disagrees with the URL it was fetched from.
        var other = await InvokeAdvertisedDocumentUrlGetAsync(
            requestDelegate,
            provider,
            "http://localhost:8080/.well-known/oauth-protected-resource/mcp");
        Assert.Equal(StatusCodes.Status401Unauthorized, other.Response.StatusCode);
    }

    [Fact]
    public async Task Kestrel_DecodesEveryEscapeExceptPercent2F_Measured()
    {
        // The observed behaviour every decoded-path assertion in this file
        // rests on, and the only place it is stated as a measurement rather
        // than assumed: a real Kestrel bound to a loopback port, handed the
        // literal bytes of a request line over a socket, echoing back the
        // Request.Path it produced. Pinned here so a runtime that changes
        // this fails one obvious test instead of a scattering of routing
        // ones — and so the SDK's model of the decoder
        // (DecodePathLikeKestrel) has something to be wrong against.

        // %2F stays encoded: decoding it would add a segment boundary the
        // client did not send. Byte-exact, so the client's hex casing
        // survives — which is why the path comparison folds case.
        Assert.Equal("/mcp%2F", await _kestrel.DecodePathAsync("/mcp%2F"));
        Assert.Equal("/mcp%2f", await _kestrel.DecodePathAsync("/mcp%2f"));

        // %5C does NOT stay encoded — Kestrel decodes it to a backslash like
        // any other escape. The SDK's decoder used to hold it back, and its
        // doc comment asserted this behaviour rather than measuring it; the
        // last row shows the two escapes really are treated differently
        // side by side, so holding %5C back was never a spelling variant of
        // the %2F rule.
        Assert.Equal("/m\\cp", await _kestrel.DecodePathAsync("/m%5Ccp"));
        Assert.Equal("/m\\cp", await _kestrel.DecodePathAsync("/m%5ccp"));
        Assert.Equal("/a\\b%2Fc~d", await _kestrel.DecodePathAsync("/a%5Cb%2Fc%7Ed"));

        // Everything else decodes, including the escapes that would otherwise
        // look structural: %25 is not re-scanned as the start of an escape.
        Assert.Equal("/m~cp", await _kestrel.DecodePathAsync("/m%7Ecp"));
        Assert.Equal("/m cp", await _kestrel.DecodePathAsync("/m%20cp"));
        Assert.Equal("/m%cp", await _kestrel.DecodePathAsync("/m%25cp"));
    }

    [Fact]
    public async Task PrmDocument_IsServedAtTheAdvertisedUrl_WhenPathCarriesAPercentEncodedBackslash()
    {
        // The %5C row. `ThrowIfWhitespaceOrBackslash` rejects a raw backslash
        // in a resource identifier, but `%5C` is a well-formed escape that
        // the path validator's `%` branch steps over — so this identifier
        // constructs, and derives a document URL that keeps the escape.
        //
        // Kestrel decodes `%5C` (see the ground-truth test above), so on
        // the fallback branch `Request.Path` carries `m\cp`. A decoder that
        // preserved `%5C` on the expected side would leave the two spellings
        // unequal and answer 401 at the identifier's own advertised URL —
        // the %2F defect above with the sign flipped. The row exists so that
        // branch executes.
        var resource = "http://localhost:8080/m%5Ccp";
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true));
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: resource,
            scopes: new[] { "tools/add" },
            devMode: true);
        var requestDelegate = BuildPipeline(provider, options);

        var documentUrl = verifier.GetProtectedResourceMetadataDocumentUrl();
        Assert.Equal("http://localhost:8080/.well-known/oauth-protected-resource/m%5Ccp", documentUrl);

        // Served at its own advertised URL both on a host exposing the raw
        // request target (primary comparison) and on one that does not
        // (decoded fallback) — the fallback is the branch under test.
        foreach (var populateRawTarget in new[] { true, false })
        {
            var ctx = await InvokeAdvertisedDocumentUrlGetAsync(
                requestDelegate, provider, documentUrl, populateRawTarget);

            Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
            ctx.Response.Body.Position = 0;
            using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            Assert.Equal(resource, doc.RootElement.GetProperty("resource").GetString());
        }

        // And not at the URL a different, escape-less identifier advertises:
        // decoding `%5C` must not collapse two identifiers onto one document.
        var other = await InvokeAdvertisedDocumentUrlGetAsync(
            requestDelegate,
            provider,
            "http://localhost:8080/.well-known/oauth-protected-resource/mcp");
        Assert.Equal(StatusCodes.Status401Unauthorized, other.Response.StatusCode);
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

    /// <summary>
    /// RFC 9728 §5.1 leaves the PRM document's location to the deployment: it
    /// is the URL the challenge names, not a path the resource must serve
    /// itself. authserver 0.2.0 publishes one document per registered Resource
    /// at <c>{issuer}/.well-known/oauth-protected-resource/{ref}</c>, which a
    /// resource server that cannot host well-known paths of its own points at
    /// instead. The test above pins the default — the derived resource-hosted
    /// URL — so the two together show the option changes that and nothing else.
    /// </summary>
    [Fact]
    public async Task ResourceMetadataUrlOverride_IsAdvertisedOn401()
    {
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var asHostedUrl = $"{_issuer}/.well-known/oauth-protected-resource/mcp";
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true,
            resourceMetadataUrl: asHostedUrl);
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeRawAsync(
            requestDelegate,
            provider,
            authorizationHeader: null,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.Contains($"resource_metadata=\"{asHostedUrl}\"", www, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "http://localhost:8080/.well-known/oauth-protected-resource/mcp",
            www,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResourceMetadataUrlOverride_IsAdvertisedOnInsufficientScope403()
    {
        // The 403 matters as much as the 401: a client that only ever presents
        // an under-scoped token reaches the AS through this challenge alone.
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

        var asHostedUrl = $"{_issuer}/.well-known/oauth-protected-resource/mcp";
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add", "tools/multiply" },
            devMode: true,
            resourceMetadataUrl: asHostedUrl);

        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokeAsync(
            requestDelegate,
            provider,
            token: accessToken,
            authScheme: "Bearer",
            dpopHeader: null,
            mcpToolCallName: "multiply");

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.Contains("error=\"insufficient_scope\"", www, StringComparison.Ordinal);
        Assert.Contains($"resource_metadata=\"{asHostedUrl}\"", www, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResourceMetadataUrlOverride_LeavesThePrmDocumentRouteOnTheDerivedUrl()
    {
        // The override redirects discovery, not hosting: the well-known path
        // this middleware answers is derived from the resource identifier and
        // has nothing to do with where the advertised document lives. Keying
        // the route off the override would take the resource-hosted document
        // offline the moment an operator pointed clients at the AS-hosted one,
        // which is a migration step nobody asked for.
        var verifier = await CreateResourceAsync(tokenScopes: new[] { "tools/add" });
        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();
        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true,
            resourceMetadataUrl: $"{_issuer}/.well-known/oauth-protected-resource/mcp");
        var requestDelegate = BuildPipeline(provider, options);

        var ctx = await InvokePrmDocumentGetAsync(requestDelegate, provider);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        ctx.Response.Body.Position = 0;
        using var reader = new System.IO.StreamReader(ctx.Response.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        // RFC 9728 §3.3 — whichever document a client ends up reading, its
        // `resource` must equal the identifier byte for byte.
        Assert.Equal(_resource, doc.RootElement.GetProperty("resource").GetString());
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

    /// <summary>
    /// GET the advertised PRM document URL through the middleware, shaping
    /// the request the way a real server delivers it: the encoded bytes of
    /// the request line in <see cref="IHttpRequestFeature.RawTarget"/>
    /// (unless <paramref name="populateRawTarget"/> is false, modelling a
    /// host that does not expose the raw target), and in <c>Request.Path</c>
    /// the decoded path a real Kestrel actually produces for those bytes,
    /// measured by <see cref="KestrelPathGroundTruth"/>.
    /// </summary>
    /// <remarks>
    /// The decoded side is measured rather than modelled on purpose. The
    /// middleware's fallback branch compares <c>Request.Path</c> against the
    /// expected path put through the SDK's own model of Kestrel's decoder; a
    /// second copy of that model on the request-shaping side would reduce the
    /// assertion to <c>PathsMatch(f(p), f(p))</c> — true whatever <c>f</c>
    /// does, so a model that disagrees with Kestrel would still pass green.
    /// It did: the model claimed Kestrel preserves <c>%5C</c>, and Kestrel
    /// decodes it. See
    /// <see cref="Kestrel_DecodesEveryEscapeExceptPercent2F_Measured"/>.
    /// </remarks>
    private async Task<HttpContext> InvokeAdvertisedDocumentUrlGetAsync(
        RequestDelegate requestDelegate,
        ServiceProvider provider,
        string documentUrl,
        bool populateRawTarget = true)
    {
        var target = documentUrl[documentUrl.IndexOf("/.well-known/", StringComparison.Ordinal)..];
        var queryStart = target.IndexOf('?', StringComparison.Ordinal);
        var rawPath = queryStart >= 0 ? target[..queryStart] : target;

        var ctx = new DefaultHttpContext();
        ctx.RequestServices = provider;
        ctx.Request.Scheme = "http";
        ctx.Request.Host = new HostString("localhost", 8080);
        ctx.Request.PathBase = PathString.Empty;
        ctx.Request.Path = new PathString(await _kestrel.DecodePathAsync(rawPath).ConfigureAwait(false));
        ctx.Request.QueryString = queryStart >= 0 ? new QueryString(target[queryStart..]) : QueryString.Empty;
        if (populateRawTarget)
        {
            ctx.Features.Get<IHttpRequestFeature>()!.RawTarget = target;
        }

        ctx.Request.Method = HttpMethods.Get;
        ctx.Response.Body = new System.IO.MemoryStream();

        await requestDelegate(ctx).ConfigureAwait(false);
        return ctx;
    }

    // -----------------------------------------------------------------------
    // Error bodies: RFC 6750 §3 JSON, fixed description, no message
    // -----------------------------------------------------------------------

    [Fact]
    public async Task NoCredentials_Returns401_WithNoErrorCodeInEitherHalf()
    {
        // A request that presented nothing gets no `error` in the challenge
        // (RFC 6750 §3.1 defines the codes for a request that did present
        // credentials, and ties `invalid_request` to a malformed request
        // answered with 400), and the body makes the same omission rather than
        // inventing a code the header does not carry.
        var (ctx, _) = await InvokeUnauthenticatedAsync(authorizationHeader: null);

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Equal("application/json; charset=utf-8", ctx.Response.ContentType);

        var (error, description) = ReadErrorBody(ctx);
        Assert.Null(error);
        Assert.Equal("The request did not carry a usable access token", description);

        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.DoesNotContain("error=", www, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownScheme_Returns401_WithNoErrorCodeInEitherHalf()
    {
        var (ctx, _) = await InvokeUnauthenticatedAsync(authorizationHeader: "Basic abc");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        var (error, description) = ReadErrorBody(ctx);
        Assert.Null(error);
        Assert.Equal("The request did not carry a usable access token", description);

        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        Assert.DoesNotContain("error=", www, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RejectedToken_Returns401_WithFixedDescriptionAndNoInternalMessage()
    {
        // The body used to be `invalid_token: {ex.Message}` — the verifier's
        // own sentence, naming the unknown kid or the claim that failed, to a
        // caller who by definition has not authenticated. Both halves of the
        // response now carry the per-code sentence instead.
        var (ctx, _) = await InvokeUnauthenticatedAsync(
            authorizationHeader: "Bearer not-a-real-token");

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Equal("application/json; charset=utf-8", ctx.Response.ContentType);

        var (error, description) = ReadErrorBody(ctx);
        Assert.Equal("invalid_token", error);
        Assert.Equal(
            "The access token is missing or not valid for this resource",
            description);

        // Neither half leaks: no JWT/claim vocabulary in either.
        var www = ctx.Response.Headers.WWWAuthenticate.ToString();
        foreach (var leak in new[] { "kid", "claim", "signature", "token-", "JWT" })
        {
            Assert.DoesNotContain(leak, description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(leak, www, StringComparison.OrdinalIgnoreCase);
        }
    }

    private async Task<(HttpContext Context, ServiceProvider Provider)> InvokeUnauthenticatedAsync(
        string? authorizationHeader)
    {
        var verifier = await AuthplaneResource.CreateAsync(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            fetchSettings: FetchSettings.FromDevMode(devMode: true));

        var services = new ServiceCollection();
        services.AddSingleton(verifier);
        var provider = services.BuildServiceProvider();

        var options = new AuthplaneMcpAuth.Options(
            issuer: _issuer,
            resource: _resource,
            scopes: new[] { "tools/add" },
            devMode: true);

        var ctx = await InvokeRawAsync(
            BuildPipeline(provider, options),
            provider,
            authorizationHeader,
            bodyJson: "{\"method\":\"tools/call\",\"params\":{\"name\":\"add\"}}");

        return (ctx, provider);
    }

    // Error is null when the body omits the member, which is the
    // no-credentials case: RFC 6750 §3 leaves `error` out of the challenge
    // there, and the body follows it.
    private static (string? Error, string Description) ReadErrorBody(HttpContext ctx)
    {
        ctx.Response.Body.Seek(0, System.IO.SeekOrigin.Begin);
        using var reader = new System.IO.StreamReader(ctx.Response.Body);
        using var doc = JsonDocument.Parse(reader.ReadToEnd());
        return (
            doc.RootElement.TryGetProperty("error", out var error) ? error.GetString() : null,
            doc.RootElement.GetProperty("error_description").GetString()!);
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

