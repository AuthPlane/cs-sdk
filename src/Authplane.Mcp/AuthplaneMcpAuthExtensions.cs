using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Authplane.Mcp;

public static class AuthplaneMcpAuthExtensions
{
    private const string WellKnownPrmPath = "/.well-known/oauth-protected-resource";

    /// <summary>
    /// The URL a challenge advertises as <c>resource_metadata</c>: the
    /// configured <see cref="AuthplaneMcpAuth.Options.ResourceMetadataUrl"/>
    /// when set, otherwise the URL derived from the resource identifier.
    /// Challenges only — the PRM GET route below keys off the derived URL,
    /// which is the one document this middleware serves.
    /// </summary>
    private static string ProtectedResourceMetadataUrl(
        AuthplaneMcpAuth.Options options,
        AuthplaneResource resource) =>
        options.ResourceMetadataUrl ?? resource.GetProtectedResourceMetadataDocumentUrl();

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
        //
        // `options.Resource` is pre-gated: the Options constructor is the only
        // way to build an Options instance and it runs the full identifier
        // gate set, so this parse cannot see a relative or scheme-relative
        // value and silently anchor `htu` on the runtime's implicit `file`
        // origin.
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
                // Always the derived URL, never Options.ResourceMetadataUrl:
                // that override points challenges at a document hosted
                // elsewhere (the authorization server), whose path says
                // nothing about where this middleware answers. The
                // resource-hosted document stays served either way.
                var documentUrl = authplaneResource.GetProtectedResourceMetadataDocumentUrl();
                // Routing is path-keyed, and compares like against like. The
                // derived document URL is byte-exact with respect to the
                // configured identifier, so the expected path is sliced off it
                // rather than re-parsed: `Uri.AbsolutePath` re-renders what it
                // returns (`%7E` becomes `~`) — the canonicalization the
                // derivation itself stopped applying — and comparing its
                // output against the *decoded* `Request.Path` left an
                // advertised `…/m%7Ecp` answered 401 at its own URL. The
                // slice boundaries are the derivation's own: the authority
                // cannot contain '/', so the first occurrence of the
                // well-known string is the inserted one, and the path cannot
                // contain a raw '?', so the first '?' after it starts the
                // query. The query is excluded on both sides (a resource
                // identifier with a query keeps it in the derived URL per
                // RFC 9728 §3), so the one configured document is served
                // regardless of the request's query string. Serving distinct
                // documents per query value is not supported.
                // The derivation unconditionally inserts the well-known
                // string (OAuthProtectedResourceMetadata.GetDocumentUrl), so
                // this IndexOf cannot miss. That invariant lives in another
                // class, and this is the only site that depends on it — the
                // guard pins it here, where without it a regression would
                // surface as an ArgumentOutOfRangeException from the '?'
                // IndexOf on every unauthenticated GET.
                var wellKnownStart = documentUrl.IndexOf(WellKnownPrmPath, StringComparison.Ordinal);
                string? expectedPath = null;
                if (wellKnownStart >= 0)
                {
                    var expectedQueryStart = documentUrl.IndexOf('?', wellKnownStart);
                    expectedPath = expectedQueryStart >= 0
                        ? documentUrl[wellKnownStart..expectedQueryStart]
                        : documentUrl[wellKnownStart..];
                }

                // The primary comparison is over the encoded request target —
                // `IHttpRequestFeature.RawTarget`, the bytes of the request
                // line — because that is the representation the advertised URL
                // is expressed in: a client that reads `resource_metadata` and
                // fetches it sends those bytes. The decoded comparison stays
                // as a fallback for hosts that do not populate `RawTarget` and
                // for a client requesting an RFC 3986 §6.2.2.2-equivalent form
                // of the advertised path. Its expected side is decoded the way
                // Kestrel decodes into `Request.Path` — everything except
                // `%2F` — so the two sides stay like for like on the server
                // that decoding was measured against; see DecodePathLikeKestrel
                // for why `Uri.UnescapeDataString` is the wrong decoder here.
                var requestPath = context.Request.Path.Value ?? string.Empty;
                var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
                string? rawRequestPath = null;
                if (!string.IsNullOrEmpty(rawTarget))
                {
                    var rawQueryStart = rawTarget.IndexOf('?', StringComparison.Ordinal);
                    rawRequestPath = rawQueryStart >= 0 ? rawTarget[..rawQueryStart] : rawTarget;
                }

                if ((expectedPath is not null &&
                        ((rawRequestPath is not null && PathsMatch(rawRequestPath, expectedPath)) ||
                         PathsMatch(requestPath, DecodePathLikeKestrel(expectedPath)))) ||
                    PathsMatch(requestPath, WellKnownPrmPath))
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
            var resourceMetadataUrl = ProtectedResourceMetadataUrl(options, verifier);
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
                await WriteErrorBodyAsync(context, AuthplaneErrors.ErrorResponseBody()).ConfigureAwait(false);
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
                await WriteErrorBodyAsync(context, AuthplaneErrors.ErrorResponseBody()).ConfigureAwait(false);
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
                await WriteErrorBodyAsync(context, AuthplaneErrors.ErrorResponseBody()).ConfigureAwait(false);
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
                catch (DPoPMultipleProofsException ex)
                {
                    LogFailure(context, ex, StatusCodes.Status401Unauthorized);
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
                        description: AuthplaneErrors.ErrorDescriptionFor(OAuthConstants.ErrorCodes.InvalidDPoPProof),
                        realm: options.Realm,
                        dpopAlgs: dpopAlgs);
                    await WriteErrorBodyAsync(context,
                        AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.InvalidDPoPProof))
                        .ConfigureAwait(false);
                    return;
                }
            }

            // 3) Header-only required-scope fast path. Cheap, no body read; safe pre-auth.
            //    Body-based scope derivation runs AFTER VerifyAsync to deny unauthenticated
            //    callers any work proportional to the body size.
            var requiredScopes = TryResolveRequiredScopesFromHeader(context);

            // Nullable only for definite assignment across the catch blocks:
            // every catch returns, so past the try-catch `claims` is the
            // successful VerifyAsync result, and inside a catch it is non-null
            // exactly when VerifyAsync succeeded before the throw (i.e. the
            // scope-check path).
            VerifiedClaims? claims = null;
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
            catch (InsufficientScopeException ex)
            {
                LogFailure(context, ex, StatusCodes.Status403Forbidden);
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                // RFC 9449 §8.2 lets the server supply a nonce on any
                // response: the proof was accepted before the scope check
                // threw, so a rotation-due nonce would otherwise lose its
                // hint here and cost the client the 401 round trip later.
                if (!string.IsNullOrEmpty(claims?.NextDPoPNonce))
                {
                    context.Response.Headers[OAuthConstants.Headers.DPoPNonce] = claims.NextDPoPNonce;
                }
                // Match the scheme the client actually used: if they presented DPoP, the
                // 403 stays DPoP; otherwise Bearer (RFC 9449 §7.1).
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    usedDpopScheme ? ChallengeScheme.DPoPOnly : ChallengeScheme.BearerOnly,
                    resourceMetadataUrl,
                    error: "insufficient_scope",
                    description: AuthplaneErrors.ErrorDescriptionFor(OAuthConstants.ErrorCodes.InsufficientScope),
                    realm: options.Realm,
                    scope: requiredScopes is { Length: > 0 } ? string.Join(' ', requiredScopes) : null,
                    dpopAlgs: dpopAlgs);
                await WriteErrorBodyAsync(context,
                    AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.InsufficientScope))
                    .ConfigureAwait(false);
                return;
            }
            catch (DPoPProofMissingException ex)
            {
                LogFailure(context, ex, StatusCodes.Status401Unauthorized);
                // RFC 9449 §7.1 — DPoP errors use the DPoP challenge scheme.
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: AuthplaneErrors.ErrorDescriptionFor(OAuthConstants.ErrorCodes.InvalidToken),
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await WriteErrorBodyAsync(context,
                    AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.InvalidToken))
                    .ConfigureAwait(false);
                return;
            }
            catch (InvalidDPoPProofException ex)
            {
                LogFailure(context, ex, StatusCodes.Status401Unauthorized);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: AuthplaneErrors.ErrorDescriptionFor(OAuthConstants.ErrorCodes.InvalidToken),
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await WriteErrorBodyAsync(context,
                    AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.InvalidToken))
                    .ConfigureAwait(false);
                return;
            }
            catch (DPoPBindingMismatchException ex)
            {
                LogFailure(context, ex, StatusCodes.Status401Unauthorized);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: AuthplaneErrors.ErrorDescriptionFor(OAuthConstants.ErrorCodes.InvalidToken),
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await WriteErrorBodyAsync(context,
                    AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.InvalidToken))
                    .ConfigureAwait(false);
                return;
            }
            catch (DPoPReplayDetectedException ex)
            {
                LogFailure(context, ex, StatusCodes.Status401Unauthorized);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: "invalid_token",
                    description: AuthplaneErrors.ErrorDescriptionFor(OAuthConstants.ErrorCodes.InvalidToken),
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await WriteErrorBodyAsync(context,
                    AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.InvalidToken))
                    .ConfigureAwait(false);
                return;
            }
            catch (DPoPNonceRequiredException ex)
            {
                LogFailure(context, ex, StatusCodes.Status401Unauthorized);
                // RFC 9449 §9 choreography: 401 with a DPoP-scheme challenge
                // carrying error="use_dpop_nonce" AND the fresh nonce in the
                // DPoP-Nonce response header. The client re-signs its proof
                // with that nonce and retries — this is a negotiation step,
                // not a proof-validity verdict, which is why it carries
                // neither invalid_token nor invalid_dpop_proof. The extra
                // headers come from AuthplaneErrors.ResponseHeaders so this
                // middleware and framework-agnostic adapters share one
                // exception-to-header mapping.
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                foreach (var (name, value) in AuthplaneErrors.ResponseHeaders(ex))
                {
                    context.Response.Headers[name] = value;
                }
                context.Response.Headers.WWWAuthenticate = BuildChallenge(
                    ChallengeScheme.DPoPOnly,
                    resourceMetadataUrl,
                    error: OAuthConstants.ErrorCodes.UseDpopNonce,
                    description: AuthplaneErrors.ErrorDescriptionFor(OAuthConstants.ErrorCodes.UseDpopNonce),
                    realm: options.Realm,
                    dpopAlgs: dpopAlgs);
                await WriteErrorBodyAsync(context,
                    AuthplaneErrors.ErrorResponseBody(OAuthConstants.ErrorCodes.UseDpopNonce))
                    .ConfigureAwait(false);
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
                var status = AuthplaneErrors.HttpStatus(ex);
                LogFailure(context, ex, status);
                context.Response.StatusCode = status;
                if (status == StatusCodes.Status401Unauthorized)
                {
                    context.Response.Headers.WWWAuthenticate = BuildChallenge(
                        defaultScheme,
                        resourceMetadataUrl,
                        error: AuthplaneErrors.ErrorCodeFor(ex),
                        description: AuthplaneErrors.ErrorDescriptionFor(AuthplaneErrors.ErrorCodeFor(ex)),
                        realm: options.Realm,
                        dpopAlgs: dpopAlgs);
                    await WriteErrorBodyAsync(context,
                        AuthplaneErrors.ErrorResponseBody(AuthplaneErrors.ErrorCodeFor(ex)))
                        .ConfigureAwait(false);
                }
                else
                {
                    // 5xx means the server side is at fault (JWKS/metadata
                    // outage, misconfigured verifier extension). No
                    // WWW-Authenticate: a challenge would direct the client to
                    // fix credentials that are not the problem.
                    await WriteErrorBodyAsync(context,
                        AuthplaneErrors.ErrorResponseBody(AuthplaneErrors.ServerErrorCodeFor(status)))
                        .ConfigureAwait(false);
                }
                return;
            }

            // RFC 9449 §8.2 (applied to resource servers via §9): when the
            // verifier accepted a rotation-due nonce it hands back the next
            // one, advertised here on the success response so an active
            // client rotates without ever taking the 401 round trip. Set
            // before next() runs — headers are frozen once the downstream
            // handler starts the response body.
            if (!string.IsNullOrEmpty(claims.NextDPoPNonce))
            {
                context.Response.Headers[OAuthConstants.Headers.DPoPNonce] = claims.NextDPoPNonce;
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

    /// <summary>
    /// Write the RFC 6750 §3 JSON error body, with the media type that says so.
    ///
    /// The bodies used to be prose ("Missing Authorization header.") or a
    /// colon-joined pair ("invalid_token: dpop_proof_missing"), neither of
    /// which a client can parse; every sibling SDK in this family answers with
    /// the RFC's <c>{"error": ..., "error_description": ...}</c> object, so
    /// this one does too.
    /// </summary>
    private static Task WriteErrorBodyAsync(HttpContext context, string json)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        return context.Response.WriteAsync(json);
    }

    /// <summary>
    /// The category the middleware logs under. Named for the assembly so an
    /// operator can raise this one path to Debug without raising the host's.
    /// </summary>
    private const string LogCategory = "Authplane.Mcp";

    /// <summary>
    /// Pre-compiled by <see cref="LoggerMessage"/> rather than called through
    /// the <c>ILogger.Log*</c> extensions: CA1848 is an error in this
    /// repository, and this sits on the request path.
    /// </summary>
    private static readonly Action<ILogger, string, string, int, Exception?> LogServerFailure =
        LoggerMessage.Define<string, string, int>(
            LogLevel.Error,
            new EventId(1, "AuthplaneVerificationFailed"),
            "Authplane could not verify {Method} {Path} and answered {Status}.");

    private static readonly Action<ILogger, string, string, int, Exception?> LogRejection =
        LoggerMessage.Define<string, string, int>(
            LogLevel.Debug,
            new EventId(2, "AuthplaneRequestRejected"),
            "Authplane rejected {Method} {Path} with {Status}.");

    /// <summary>
    /// Record why the request failed before the response discards it. The body
    /// and challenge carry a fixed description chosen by the error code, never
    /// the exception's own message — the caller has by definition not
    /// authenticated, and the SDK's messages name the unknown <c>kid</c>, the
    /// claim that did not validate, or the <c>aud</c> the resource expects. The
    /// operator still needs that detail, and this middleware is the last place
    /// that holds it: every arm below catches, answers, and returns.
    ///
    /// Logging is optional, not required. A host with no logging registered
    /// gets <c>null</c> from <see cref="ILoggerFactory"/> and this is a no-op,
    /// so adding the call cannot turn a working host into a failing one.
    ///
    /// A rejection is logged at Debug, not Warning: reaching it takes no
    /// credentials, so an unauthenticated caller would otherwise choose this
    /// server's log volume. An operator diagnosing a rejection turns the
    /// category up for as long as it takes. A 5xx is the server's own fault,
    /// cannot be provoked by a caller, and is what an operator needs to see
    /// without having been told to look, so it goes to Error.
    /// </summary>
    private static void LogFailure(HttpContext context, Exception ex, int status)
    {
        var logger = context.RequestServices.GetService<ILoggerFactory>()?.CreateLogger(LogCategory);
        if (logger is null)
        {
            return;
        }

        if (status >= StatusCodes.Status500InternalServerError)
        {
            LogServerFailure(logger, context.Request.Method, context.Request.Path.Value ?? string.Empty, status, ex);
        }
        else if (logger.IsEnabled(LogLevel.Debug))
        {
            LogRejection(logger, context.Request.Method, context.Request.Path.Value ?? string.Empty, status, ex);
        }
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

    /// <summary>
    /// Decodes a percent-encoded path the way Kestrel decodes the request
    /// target into <c>Request.Path</c> (measured; the other ASP.NET Core
    /// servers are unmeasured): every escape except <c>%2F</c>, which stays
    /// encoded because decoding it would add a segment boundary the client
    /// never sent. It is not <see cref="Uri.UnescapeDataString(string)"/>
    /// (nor <c>PathString.FromUriComponent</c>) — those decode every escape,
    /// and the difference bites on exactly <c>%2F</c>: unescaping the
    /// expected path turned an identifier's <c>mcp%2F</c> into <c>mcp/</c>,
    /// which after the trailing-slash trim both failed to match the
    /// identifier's own advertised document URL and falsely matched the URL
    /// a different, <c>%2F</c>-less identifier advertises.
    /// </summary>
    /// <remarks>
    /// <c>%2F</c> is the only exception. This decoder used to hold back
    /// <c>%5C</c> as well, on the reasoning that a backslash is a segment
    /// separator too — it is not, to Kestrel, which decodes <c>%5C</c> like
    /// any other escape. A <c>%5C</c>-bearing resource identifier therefore
    /// answered 401 at its own advertised metadata URL wherever the raw
    /// request target is unavailable and this fallback decides. The claim is
    /// now measured against a live Kestrel rather than asserted; the test
    /// project's <c>Kestrel_DecodesEveryEscapeExceptPercent2F_Measured</c>
    /// is the measurement.
    /// </remarks>
    private static string DecodePathLikeKestrel(string encodedPath)
    {
        StringBuilder? sb = null;
        var start = 0;
        for (var i = 0; i + 2 < encodedPath.Length; i++)
        {
            if (encodedPath[i] != '%' ||
                !Uri.IsHexDigit(encodedPath[i + 1]) ||
                !Uri.IsHexDigit(encodedPath[i + 2]))
            {
                continue;
            }

            var octet = (Uri.FromHex(encodedPath[i + 1]) << 4) | Uri.FromHex(encodedPath[i + 2]);
            if (octet != '/')
            {
                continue;
            }

            sb ??= new StringBuilder(encodedPath.Length);
            sb.Append(Uri.UnescapeDataString(encodedPath[start..i]));
            sb.Append(encodedPath, i, 3);
            i += 2;
            start = i + 1;
        }

        if (sb is null)
        {
            return Uri.UnescapeDataString(encodedPath);
        }

        sb.Append(Uri.UnescapeDataString(encodedPath[start..]));
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

        // OrdinalIgnoreCase stays deliberately now that the expected side is
        // the operator's exact bytes. The compared strings are paths only —
        // the scheme and host, the components RFC 3986 §6.2.2.1 makes
        // case-insensitive, never reach them — but the one case-insensitive
        // part of an encoded path is the hex digits of a percent-escape
        // (§6.2.2.1 again: `%2f` and `%2F` name the same octet), and the raw
        // request target carries the client's casing of them. The folding is
        // broader than that (it also matches a case-variant of the path
        // letters themselves), which is pre-existing laxity, not a routing
        // hazard: there is one document, so a lax match can only serve it,
        // never a different identifier's.
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

