using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace Authplane.Mcp;

public static class AuthplaneMcpAuthExtensions
{
    private static string ProtectedResourceMetadataUrl(AuthplaneResource resource) =>
        resource.GetProtectedResourceMetadataDocumentUrl();

    /// <summary>
    /// Extracts token + optional DPoP proof from the request and enforces the required scope
    /// for the MCP tool call (either from `x-authplane-required-scopes` or from the `tools/call` payload).
    /// </summary>
    public static IApplicationBuilder UseAuthplaneMcpAuth(
        this IApplicationBuilder app,
        AuthplaneMcpAuth.Options options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);

        // DPoP `htu` (RFC 9449 §4.2) is the request target URI — origin + path.
        // The origin (scheme + host + port) is operator-controlled and comes
        // from the configured `resource`; deriving it from inbound `Host` /
        // `X-Forwarded-Proto` would let an intermediary (or, when the app is
        // reachable directly, the requester) decide which `htu` the proof is
        // checked against, neutering DPoP's cross-endpoint anti-replay
        // defense. Only the path varies per-request. A path-rewriting reverse
        // proxy still breaks `htu` matching — the mitigation is to forward the
        // original path, not to fall back to request-derived origin.
        var parsedResource = new Uri(options.Resource, UriKind.Absolute);
        var resourceOrigin = parsedResource.GetLeftPart(UriPartial.Authority);
        var resourceDefaultPath = string.IsNullOrEmpty(parsedResource.AbsolutePath)
            ? "/"
            : parsedResource.AbsolutePath;

        return app.Use(async (context, next) =>
        {
            // RFC 9728 §4 — PRM document is public (no auth).
            //
            // Two paths are served:
            //   • /.well-known/oauth-protected-resource           — the MCP
            //     authorization spec discovery path. MCP clients (Claude,
            //     Inspector) probe this regardless of the resource path.
            //   • /.well-known/oauth-protected-resource/<path>    — the
            //     per-resource path RFC 9728 §3.1 prefers when the resource
            //     URI has a non-root path component.
            // Both return identical bodies.
            if (HttpMethods.IsGet(context.Request.Method))
            {
                var authplaneResource = context.RequestServices.GetRequiredService<AuthplaneResource>();
                var documentUrl = ProtectedResourceMetadataUrl(authplaneResource);
                var expectedPath = new Uri(documentUrl, UriKind.Absolute).AbsolutePath;
                var requestPath = context.Request.Path.Value ?? string.Empty;
                if (PathsMatch(requestPath, expectedPath) ||
                    PathsMatch(requestPath, "/.well-known/oauth-protected-resource"))
                {
                    context.Response.ContentType = "application/json; charset=utf-8";
                    context.Response.Headers[HeaderNames.CacheControl] = "public, max-age=3600";
                    await context.Response
                        .WriteAsync(authplaneResource.GetProtectedResourceMetadata().ToRfc9728Json())
                        .ConfigureAwait(false);
                    return;
                }
            }

            var verifier = context.RequestServices.GetRequiredService<AuthplaneResource>();
            var resourceMetadataUrl = ProtectedResourceMetadataUrl(verifier);
            // RFC 9449 §7.1: the DPoP challenge `algs` parameter SHOULD reflect
            // what the resource actually accepts. When InboundDPoPOptions narrows
            // the set (e.g. ES256-only) we must mirror that — otherwise the
            // challenge over-advertises algorithms the resource will then reject,
            // contradicting PRM's `dpop_signing_alg_values_supported`.
            var acceptedAlgs = verifier.InboundDPoP?.AllowedProofAlgorithms
                ?? AuthplaneResource.AcceptedDPoPAlgorithms;
            var dpopAlgs = string.Join(' ', acceptedAlgs);
            // H-PRM: pre-token challenges must match what the verifier will
            // actually accept. When the resource is Bearer-only (InboundDPoP
            // null) advertising DPoP causes clients to negotiate it and then
            // have every request rejected as DPoPNotSupportedException; when
            // Required=true, Bearer must not be advertised since any Bearer
            // token will be rejected for missing DPoP binding.
            var defaultScheme = verifier.InboundDPoP switch
            {
                null => ChallengeScheme.BearerOnly,
                { Required: true } => ChallengeScheme.DPoPOnly,
                _ => ChallengeScheme.BearerAndDPoP,
            };

            // 1) Extract Authorization header and the scheme used. Track `usedDpopScheme`
            //    so subsequent challenges can match what the client tried (RFC 9449 §7.1).
            var authHeader = context.Request.Headers.Authorization.ToString();
            if (string.IsNullOrWhiteSpace(authHeader))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    defaultScheme,
                    resourceMetadataUrl,
                    error: null,
                    description: null,
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("Missing Authorization header.").ConfigureAwait(false);
                return;
            }

            string token;
            bool usedDpopScheme;
            if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                token = authHeader["Bearer ".Length..].Trim();
                usedDpopScheme = false;
            }
            else if (authHeader.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
            {
                token = authHeader["DPoP ".Length..].Trim();
                usedDpopScheme = true;
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    defaultScheme,
                    resourceMetadataUrl,
                    error: null,
                    description: null,
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("Invalid Authorization header format.").ConfigureAwait(false);
                return;
            }

            if (string.IsNullOrWhiteSpace(token))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    defaultScheme,
                    resourceMetadataUrl,
                    error: null,
                    description: null,
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("Missing access token.").ConfigureAwait(false);
                return;
            }

            // 2) DPoP proof is expected in the `DPoP` header (RFC 9449).
            // Header extraction only — the RFC 9449 §4.3 #1 cardinality check
            // lives in DPoPRequestContext.FromHeaderValues so every
            // integration shares it. StringValues.ToString() would silently
            // join multiple headers into one comma-separated unparseable
            // proof, so the raw values are passed through instead.
            var dpopHeaderValues = context.Request.Headers["DPoP"];
            IDPoPReplayStore? replayStore = context.RequestServices.GetService<IDPoPReplayStore>();

            DPoPRequestContext? dpopRequest = null;
            if (dpopHeaderValues.Count > 0)
            {
                // `PathString.Add` only concatenates PathBase + Path — no query
                // string. The query is intentionally excluded: RFC 9449 §4.2 `htu`
                // is the request target URI without query/fragment, and
                // `DPoPHtu.Normalize` strips queries from both sides of the
                // comparison anyway.
                var path = context.Request.PathBase.Add(context.Request.Path).Value;
                if (string.IsNullOrEmpty(path))
                {
                    path = resourceDefaultPath;
                }
                var url = resourceOrigin + path;
                try
                {
                    dpopRequest = DPoPRequestContext.FromHeaderValues(
                        method: context.Request.Method,
                        url: url,
                        proofs: dpopHeaderValues,
                        replayStore: replayStore);
                }
                catch (DPoPMultipleProofsException)
                {
                    // RFC 9449 §4.3 #1 → §7.1: the one DPoP failure that
                    // carries error="invalid_dpop_proof"; every other DPoP
                    // rejection stays on invalid_token. The challenge is
                    // DPoP-scheme even when defaultScheme is BearerOnly:
                    // unlike the pre-token challenges above, this is not
                    // capability advertisement but a direct §7.1 response
                    // to a malformed DPoP attempt the client already made,
                    // and it matches AuthplaneErrors.WwwAuthenticate's
                    // scheme selection for the same exception.
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.Headers.WWWAuthenticate = BuildChallenge(
                        ChallengeScheme.DPoPOnly,
                        resourceMetadataUrl,
                        error: OAuthConstants.ErrorCodes.InvalidDPoPProof,
                        description: "multiple_dpop_proofs",
                        realm: options.Realm,
                        dpopAlgs: dpopAlgs);
                    await context.Response.WriteAsync("invalid_dpop_proof: multiple_dpop_proofs").ConfigureAwait(false);
                    return;
                }
            }

            // 3) Header-only required-scope fast path. Cheap, no body read; safe pre-auth.
            //    Body-based scope derivation runs AFTER VerifyAsync to deny unauthenticated
            //    callers any work proportional to the body size.
            var requiredScopes = TryResolveRequiredScopesFromHeader(context);

            VerifiedClaims claims;
            try
            {
                claims = await verifier.VerifyAsync(token, dpopRequest, context.RequestAborted).ConfigureAwait(false);

                // 4) Post-auth body-based scope derivation. Only authenticated requests get
                //    here, so the 64 KB body read is no longer reachable by anon callers.
                if (requiredScopes is null)
                {
                    requiredScopes = await ResolveRequiredScopesFromBodyAsync(context, options).ConfigureAwait(false);
                }

                // 5) Enforce required scopes (when we know what tool is being called).
                if (requiredScopes is not null)
                {
                    foreach (var scope in requiredScopes)
                    {
                        claims.RequireScope(scope);
                    }
                }
            }
            catch (InsufficientScopeException)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                // Match the scheme the client actually used: if they presented DPoP, the
                // 403 stays DPoP; otherwise Bearer (RFC 9449 §7.1).
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    usedDpopScheme ? ChallengeScheme.DPoPOnly : ChallengeScheme.BearerOnly,
                    resourceMetadataUrl,
                    error: "insufficient_scope",
                    description: "Insufficient scope",
                    realm: options.Realm,
                    scope: requiredScopes is { Length: > 0 } ? string.Join(' ', requiredScopes) : null,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("insufficient_scope").ConfigureAwait(false);
                return;
            }
            catch (DPoPProofMissingException)
            {
                // RFC 9449 §7.1 — DPoP errors use the DPoP challenge scheme.
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: "dpop_proof_missing",
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("invalid_token: dpop_proof_missing").ConfigureAwait(false);
                return;
            }
            catch (InvalidDPoPProofException)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: "invalid_dpop_proof",
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("invalid_token: invalid_dpop_proof").ConfigureAwait(false);
                return;
            }
            catch (DPoPBindingMismatchException)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: "dpop_binding_mismatch",
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("invalid_token: dpop_binding_mismatch").ConfigureAwait(false);
                return;
            }
            catch (DPoPReplayDetectedException)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: "dpop_replay_detected",
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync("invalid_token: dpop_replay_detected").ConfigureAwait(false);
                return;
            }
            catch (AuthplaneException ex)
            {
                // Non-DPoP-specific token rejection — advertise whatever the
                // resource actually accepts. RFC 9449 §7.1 calls for combined
                // challenges when both schemes are accepted; here defaultScheme
                // collapses to BearerOnly when InboundDPoP is null and
                // DPoPOnly when Required=true. DPoPNotSupportedException, which
                // a Bearer-only verifier throws on inbound DPoP signal, falls
                // into this branch — advertising Bearer alone is what stops
                // the negotiate-DPoP-then-reject loop.
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    defaultScheme,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: ex.Message,
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await context.Response.WriteAsync($"invalid_token: {ex.Message}").ConfigureAwait(false);
                return;
            }

            // Attach auth context and call next() OUTSIDE the try-catch so
            // downstream AuthplaneExceptions aren't swallowed as 401s.
            var identity = new ClaimsIdentity("authplane");
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, claims.Sub));
            identity.AddClaim(new Claim("client_id", claims.ClientId));
            foreach (var scope in claims.Scopes)
            {
                identity.AddClaim(new Claim("scope", scope));
            }

            context.User = new ClaimsPrincipal(identity);

            await next(context).ConfigureAwait(false);
        });
    }

    /// <summary>Which scheme(s) to advertise in a single <c>WWW-Authenticate</c> header value.</summary>
    private enum ChallengeScheme
    {
        BearerOnly,
        DPoPOnly,
        /// <summary>RFC 9449 §7.1 — combined challenge when both schemes are accepted.</summary>
        BearerAndDPoP,
    }

    /// <summary>
    /// Build the WWW-Authenticate header values for a 401/403. Returns one or two
    /// values: a single Bearer or DPoP challenge as a single value; the combined
    /// Bearer+DPoP form as two SEPARATE values so the caller can assign both
    /// (RFC 7235 §4.1 permits either comma-joined or two-field-line shapes, but
    /// the latter is unambiguous when an auth-param value happens to contain
    /// a comma).
    /// </summary>
    private static Microsoft.Extensions.Primitives.StringValues BuildChallenge(
        ChallengeScheme scheme,
        string resourceMetadataUrl,
        string? error,
        string? description,
        string? realm = null,
        string? scope = null,
        string? dpopAlgs = null)
    {
        return scheme switch
        {
            ChallengeScheme.BearerOnly => BuildSingleChallenge("Bearer", resourceMetadataUrl, error, description, realm, scope, dpopAlgs: null),
            ChallengeScheme.DPoPOnly => BuildSingleChallenge("DPoP", resourceMetadataUrl, error, description, realm, scope, dpopAlgs),
            ChallengeScheme.BearerAndDPoP => new Microsoft.Extensions.Primitives.StringValues(new[]
            {
                BuildSingleChallenge("Bearer", resourceMetadataUrl, error, description, realm, scope, dpopAlgs: null),
                BuildSingleChallenge("DPoP", resourceMetadataUrl, error, description, realm, scope, dpopAlgs),
            }),
            _ => BuildSingleChallenge("Bearer", resourceMetadataUrl, error, description, realm, scope, dpopAlgs: null),
        };
    }

    private static string BuildSingleChallenge(
        string schemeToken,
        string resourceMetadataUrl,
        string? error,
        string? description,
        string? realm,
        string? scope,
        string? dpopAlgs)
    {
        var sb = new StringBuilder(schemeToken);

        if (!string.IsNullOrWhiteSpace(realm))
        {
            sb.Append(" realm=\"").Append(EscapeChallengeString(realm)).Append('"');
        }

        if (schemeToken == "DPoP" && !string.IsNullOrWhiteSpace(dpopAlgs))
        {
            // RFC 9449 §7.1 — `algs` parameter on the DPoP challenge.
            sb.Append(", algs=\"").Append(EscapeChallengeString(dpopAlgs)).Append('"');
        }

        if (!string.IsNullOrWhiteSpace(error))
        {
            sb.Append(", error=\"").Append(EscapeChallengeString(error)).Append('"');
        }

        if (!string.IsNullOrWhiteSpace(description))
        {
            sb.Append(", error_description=\"").Append(EscapeChallengeString(description)).Append('"');
        }

        if (!string.IsNullOrWhiteSpace(scope))
        {
            sb.Append(", scope=\"").Append(EscapeChallengeString(scope)).Append('"');
        }

        sb.Append(", resource_metadata=\"").Append(EscapeChallengeString(resourceMetadataUrl)).Append('"');
        return sb.ToString();
    }

    private static string EscapeChallengeString(string value)
    {
        // RFC 7230/9110 forbids all CTLs (0x00-0x1F and 0x7F) in header field values.
        // Strip them before escaping so attacker-controlled fragments of `ex.Message`
        // cannot inject continuation lines, tabs, or other control characters into the
        // WWW-Authenticate header. CR/LF are the canonical injection vector; the rest
        // are defence in depth against proxies/CDNs with looser parsers.
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (c <= 0x1F || c == 0x7F)
            {
                continue;
            }

            if (c == '\\')
            {
                sb.Append("\\\\");
            }
            else if (c == '"')
            {
                sb.Append("\\\"");
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    private static bool PathsMatch(string requestPath, string expectedPath)
    {
        var a = requestPath.TrimEnd('/');
        var b = expectedPath.TrimEnd('/');
        if (a.Length == 0)
        {
            a = "/";
        }

        if (b.Length == 0)
        {
            b = "/";
        }

        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Synchronous header-only fast path for dynamic required-scope discovery — does
    /// not touch the body, so it is safe to run before token validation. The body-based
    /// branch (used only when no header is present) runs post-auth in
    /// <see cref="ResolveRequiredScopesFromBodyAsync"/>.
    /// </summary>
    private static string[]? TryResolveRequiredScopesFromHeader(HttpContext context)
    {
        var header = context.Request.Headers["x-authplane-required-scopes"].ToString();
        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        var scopes = header
            .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return scopes.Length > 0 ? scopes : null;
    }

    /// <summary>
    /// Body-based required-scope derivation from the MCP <c>tools/call</c> payload.
    /// Only invoked AFTER token validation succeeds, so unauthenticated callers
    /// never trigger the body read. The 64 KB cap is retained as defence-in-depth.
    /// </summary>
    private static async Task<string[]?> ResolveRequiredScopesFromBodyAsync(
        HttpContext context,
        AuthplaneMcpAuth.Options options)
    {
        const int maxBodySize = 65_536;
        context.Request.EnableBuffering();
        string? bodyText = null;
        try
        {
            if (context.Request.ContentLength is > maxBodySize)
            {
                bodyText = null;
            }
            else
            {
                var buffer = new byte[maxBodySize];
                var bytesRead = await context.Request.Body.ReadAsync(
                    buffer.AsMemory(0, maxBodySize)).ConfigureAwait(false);
                context.Request.Body.Position = 0;

                if (bytesRead == 0)
                {
                    bodyText = null;
                }
                else
                {
                    bodyText = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                }
            }
        }
        catch
        {
            try { context.Request.Body.Position = 0; } catch { /* ignore */ }
        }

        if (string.IsNullOrWhiteSpace(bodyText))
        {
            return null;
        }

        if (!TryExtractMcpToolName(bodyText, out var toolName))
        {
            return null;
        }

        // Match tool scope using exact "tools/{toolName}" convention only.
        var expectedScope = "tools/" + toolName;
        var toolScopeCandidates = options.Scopes
            .Where(s => string.Equals(s, expectedScope, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return toolScopeCandidates.Length > 0 ? toolScopeCandidates : null;
    }

    private static bool TryExtractMcpToolName(string bodyText, out string toolName)
    {
        toolName = string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(bodyText);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!doc.RootElement.TryGetProperty("method", out var methodProp) ||
                methodProp.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            if (!string.Equals(methodProp.GetString(), "tools/call", StringComparison.Ordinal))
            {
                return false;
            }

            if (!doc.RootElement.TryGetProperty("params", out var paramsProp) ||
                paramsProp.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!paramsProp.TryGetProperty("name", out var nameProp) ||
                nameProp.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var name = nameProp.GetString();
            if (string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            toolName = name;
            return true;
        }
        catch
        {
            return false;
        }
    }
}

