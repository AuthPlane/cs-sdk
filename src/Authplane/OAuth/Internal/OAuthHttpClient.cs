using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Authplane;

/// <summary>
/// Stateless HTTP plumbing for OAuth client operations: form-urlencoded POST with
/// pluggable client authentication (the configured <see cref="IAuthProvider"/>; HTTP
/// Basic from client_id/client_secret as the fallback), optional outbound DPoP proof,
/// and one nonce-retry on <c>error=use_dpop_nonce</c>. Higher-level orchestration
/// (circuit breaker, retries) lives in <see cref="AuthplaneAuthClient"/>.
/// </summary>
internal static class OAuthHttpClient
{
    /// <summary>
    /// POST to the <c>/oauth/token</c> endpoint with the supplied parameters.
    /// Re-issues the request once with a nonce header if the AS responds 400 with
    /// <c>error=use_dpop_nonce</c>. RFC 9449 §8 prescribes a single retry; a
    /// hostile or misbehaving AS that keeps returning <c>use_dpop_nonce</c> is
    /// surfaced as a TokenRequestException to avoid unbounded recursion.
    /// Accepts a list of key-value pairs to support duplicate keys (e.g. multiple <c>resource</c>
    /// or <c>audience</c> entries per RFC 8693/8707).
    /// </summary>
    public static async Task<TokenResponse> DoTokenRequestAsync(
        OAuthOperations.Context context,
        IReadOnlyList<KeyValuePair<string, string>> parameters,
        string? nonce,
        CancellationToken cancellationToken,
        bool isTokenExchange = false)
    {
        var tokenUrl = OAuthEndpoints.TokenUrl(context.IssuerUrl);

        var (response, respBody) = await SendOAuthRequestAsync(
            context,
            tokenUrl,
            parameters,
            endpointLabel: "token endpoint",
            dpopNonce: nonce,
            retryCount: 0,
            cancellationToken).ConfigureAwait(false);

        using (response)
        {
            if (response.IsSuccessStatusCode)
            {
                // Response Content-Type is deliberately not validated. Strict
                // parse on the body still catches non-JSON 2xx responses.
                return OAuthResponseParser.ParseTokenResponse(
                    respBody,
                    expectDPoP: context.DPoPSigner is not null,
                    requireIssuedTokenType: isTokenExchange);
            }

            throw BuildTokenRequestException(response, respBody);
        }
    }

    /// <summary>
    /// POST to a generic OAuth endpoint (introspection, revocation) with the
    /// context's configured client auth (typed <see cref="IAuthProvider"/>, or
    /// HTTP Basic from legacy <c>ClientId</c>/<c>ClientSecret</c>) and optional
    /// DPoP proof. Returns the response body as a string on 2xx; throws on
    /// non-success. Re-issues once on <c>use_dpop_nonce</c> (C3). RFC 9449 §8
    /// prescribes a single retry; a hostile or misbehaving AS that keeps
    /// returning <c>use_dpop_nonce</c> is surfaced as a TokenRequestException
    /// to avoid unbounded recursion.
    /// </summary>
    public static async Task<string> DoPostFormAsync(
        OAuthOperations.Context context,
        string url,
        Dictionary<string, string> parameters,
        string endpointLabel,
        CancellationToken cancellationToken,
        string? dpopNonce = null)
    {
        // Dictionary's IEnumerable<KVP<string,string>> already supplies the
        // shape SendOAuthRequestAsync expects. Materializing to a list keeps
        // the parameter snapshot stable across the use_dpop_nonce retry —
        // the dictionary itself is internal and not mutated, but the
        // contract is clearer with a fixed list.
        var parameterList = parameters.ToList();

        var (response, respBody) = await SendOAuthRequestAsync(
            context,
            url,
            parameterList,
            endpointLabel,
            dpopNonce,
            retryCount: 0,
            cancellationToken).ConfigureAwait(false);

        using (response)
        {
            if (response.IsSuccessStatusCode)
            {
                // Response Content-Type is deliberately not validated.
                // RFC 7009 §2.2 already lets a successful revocation
                // respond with an empty body and no Content-Type, and
                // introspection callers run a strict JSON parse downstream.
                return respBody;
            }

            // Route every non-token endpoint failure (introspect / revoke) through
            // AuthplaneErrors.MapOAuthError so error_description / error_uri /
            // typed subclass dispatch / 5xx-ServerError / bare-401-InvalidClient
            // are applied uniformly across token, introspect, revoke, exchange.
            throw BuildTokenRequestException(response, respBody);
        }
    }

    /// <summary>
    /// Shared HTTP pipeline for every form-urlencoded OAuth POST (token,
    /// introspection, revocation). Used to be duplicated between
    /// DoTokenRequestAsync and DoPostFormAsync — ~90 LOC of near-identical
    /// SSRF check, header setup, DPoP proof attachment, nonce store
    /// read/write, and use_dpop_nonce retry. The two copies had already
    /// diverged on a security property (unbounded recursion on
    /// use_dpop_nonce) before this consolidation; one source of truth makes
    /// future fixes apply uniformly. Returns the response (caller must
    /// dispose) along with the already-read body.
    /// </summary>
    private static async Task<(HttpResponseMessage response, string body)> SendOAuthRequestAsync(
        OAuthOperations.Context context,
        string url,
        IReadOnlyList<KeyValuePair<string, string>> parameters,
        string endpointLabel,
        string? dpopNonce,
        int retryCount,
        CancellationToken cancellationToken)
    {
        TransportSecurity.ValidateFetchUrl(url, context.FetchSettings, endpointLabel);

        // FormUrlEncodedContent does the WebUtility.UrlEncode key/value
        // encoding, the `&` joining, and the
        // `Content-Type: application/x-www-form-urlencoded` header
        // assignment in one constructor — replacing the hand-rolled
        // OAuthRequestBodies.BuildFormBody pipeline. The cast to
        // `string?` is required because the BCL signature accepts
        // `IEnumerable<KeyValuePair<string, string?>>` (.NET 6+); our
        // values are non-null by construction.
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new FormUrlEncodedContent(
                parameters.Select(kv => KeyValuePair.Create<string, string?>(kv.Key, kv.Value)))
        };
        request.Headers.Add(OAuthConstants.Headers.Accept, OAuthConstants.MediaTypes.Json);

        ApplyAuthHeaders(request, context);

        if (context.DPoPSigner is not null)
        {
            if (dpopNonce is null && context.DPoPNonceStore is not null)
            {
                var origin = DPoPNonceOrigin.From(url);
                dpopNonce = await context.DPoPNonceStore.GetAsync(origin, cancellationToken)
                    .ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(dpopNonce))
                {
                    dpopNonce = null;
                }
            }

            var proof = await context.DPoPSigner.GenerateProofAsync(
                method: "POST",
                url: url,
                options: new DPoPProofOptions(nonce: dpopNonce),
                cancellationToken: cancellationToken).ConfigureAwait(false);
            request.Headers.Add(OAuthConstants.Headers.DPoP, proof);
        }

        HttpResponseMessage response;
        try
        {
            response = await context.HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new ServerError($"authplane: {endpointLabel} request failed: {ex.Message}");
        }

        var respBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        // RFC 9449 — persist DPoP-Nonce from ANY response (success or error)
        // for the next request to this origin. .NET HttpResponseMessage.Headers
        // matching is already case-insensitive.
        //
        // Use CancellationToken.None for the write: this is a post-success
        // side-effect, not part of the request the caller can cancel. If the
        // caller's CT fires the instant after the response arrives we still
        // want the nonce persisted — otherwise the next request to this origin
        // will need an extra round-trip to learn the same nonce again.
        if (response.Headers.TryGetValues(OAuthConstants.Headers.DPoPNonce, out var responseNonceValues))
        {
            var latestNonce = responseNonceValues.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(latestNonce)
                && context.DPoPSigner is not null
                && context.DPoPNonceStore is not null)
            {
                var origin = DPoPNonceOrigin.From(url);
                await context.DPoPNonceStore.SetAsync(origin, latestNonce!, CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }

        if (response.IsSuccessStatusCode)
        {
            return (response, respBody);
        }

        // RFC 9449 §8 — a 400 with `error=use_dpop_nonce` and a fresh
        // DPoP-Nonce header signals the AS expects a nonce in the proof.
        // Bounded to one retry to avoid unbounded recursion if a hostile or
        // misbehaving AS keeps demanding new nonces; the second failure
        // surfaces via the caller's BuildTokenRequestException path.
        if (context.DPoPSigner is not null
            && response.StatusCode == HttpStatusCode.BadRequest
            && retryCount == 0
            && response.Headers.TryGetValues(OAuthConstants.Headers.DPoPNonce, out var retryNonceValues))
        {
            var nonceHeader = retryNonceValues.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(nonceHeader))
            {
                var err = OAuthErrorResponse.TryParse(respBody).Error;
                if (string.Equals(err, OAuthConstants.ErrorCodes.UseDpopNonce, StringComparison.Ordinal))
                {
                    response.Dispose();
                    return await SendOAuthRequestAsync(
                        context,
                        url,
                        parameters,
                        endpointLabel,
                        dpopNonce: nonceHeader,
                        retryCount: retryCount + 1,
                        cancellationToken).ConfigureAwait(false);
                }
            }
        }

        return (response, respBody);
    }

    /// <summary>
    /// Apply client authentication headers to the outbound request. Prefers the
    /// pluggable <see cref="IAuthProvider"/> on <c>context.AuthProvider</c>; falls
    /// back to HTTP Basic from <c>ClientId</c>/<c>ClientSecret</c> for legacy
    /// callers that construct <see cref="AuthplaneAuthClient"/> with raw credentials.
    /// </summary>
    private static void ApplyAuthHeaders(HttpRequestMessage request, OAuthOperations.Context context)
    {
        if (context.AuthProvider is not null)
        {
            foreach (var kv in context.AuthProvider.AuthHeaders())
            {
                if (string.Equals(kv.Key, OAuthConstants.Headers.Authorization, StringComparison.OrdinalIgnoreCase))
                {
                    // Always go through the strongly-typed accessor. A value
                    // without a space (no parameter) means scheme-only, which
                    // is unusual for Authorization but allowed — assign the
                    // whole value as the scheme so the header still validates.
                    var space = kv.Value.IndexOf(' ');
                    request.Headers.Authorization = space > 0
                        ? new AuthenticationHeaderValue(kv.Value[..space], kv.Value[(space + 1)..])
                        : new AuthenticationHeaderValue(kv.Value);
                }
                else
                {
                    request.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
                }
            }
            return;
        }

        // Legacy path: RFC 6749 §2.3.1 credentials form-URL-encoded before base64.
        var encodedId = Uri.EscapeDataString(context.ClientId);
        var encodedSecret = Uri.EscapeDataString(context.ClientSecret);
        var basic = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{encodedId}:{encodedSecret}"));
        request.Headers.Authorization = new AuthenticationHeaderValue(OAuthConstants.AuthSchemes.Basic, basic);
    }

    private static AuthplaneAuthClientException BuildTokenRequestException(
        HttpResponseMessage response,
        string respBody)
    {
        var oauth = OAuthErrorResponse.TryParse(respBody);
        return AuthplaneErrors.MapOAuthError(
            oauthError: oauth.Error,
            httpStatus: (int)response.StatusCode,
            errorDescription: oauth.ErrorDescription,
            errorUri: oauth.ErrorUri,
            serviceId: oauth.ServiceId,
            cause: oauth.Cause,
            consentUrl: oauth.ConsentUrl);
    }

}
