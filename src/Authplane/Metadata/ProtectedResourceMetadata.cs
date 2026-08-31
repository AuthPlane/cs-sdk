using System.Text.Json;

namespace Authplane;

public sealed class ProtectedResourceMetadata
{
    public string Resource { get; }
    public string Issuer { get; }
    public IReadOnlyList<string> Scopes { get; }

    /// <summary>
    /// Optional list of DPoP signing algorithms supported by this resource (e.g. "ES256").
    /// When non-null/non-empty, advertised as <c>dpop_signing_alg_values_supported</c> in PRM JSON.
    /// </summary>
    public IReadOnlyList<string>? DpopSigningAlgValuesSupported { get; }

    /// <summary>
    /// When true, PRM advertises <c>dpop_bound_access_tokens_required: true</c>
    /// (RFC 9728 §2). Defaults to false; only emitted when the resource has
    /// opted into inbound DPoP via <see cref="InboundDPoPOptions"/>.
    /// </summary>
    public bool DpopBoundAccessTokensRequired { get; }

    public ProtectedResourceMetadata(
        string resource,
        string issuer,
        IReadOnlyList<string> scopes,
        IReadOnlyList<string>? dpopSigningAlgValuesSupported = null,
        bool allowHttp = false,
        bool dpopBoundAccessTokensRequired = false)
    {
        Resource = resource ?? throw new ArgumentNullException(nameof(resource));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        Scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
        DpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported;
        DpopBoundAccessTokensRequired = dpopBoundAccessTokensRequired;

        // This class is the one that *emits* the identifier: ToRfc9728Json writes
        // `resource` verbatim. Gating only the derivation half (GetDocumentUrl)
        // would leave the RFC 9728 §3.3 mismatch constructible through public
        // API — a document naming `…/mcp#frag` served at the URL derived from
        // `…/mcp`, which a conformant client discards with nothing logged here.
        //
        // The same argument carries every axis whose defect makes the derived
        // URL disagree with the emitted identifier, so all four run here. Only
        // the query gate is excluded, and for a reason specific to it: a query
        // is carried into the derived URL, so emitting one raises no mismatch
        // for this type to prevent.
        ResourceIdentifiers.ThrowIfFragment(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfWhitespaceOrBackslash(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfMalformedPort(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfNotAbsoluteUrl(resource, nameof(resource));
        ResourceIdentifiers.ThrowIfUserInfo(resource, nameof(resource));

        // RFC 9728 §3.6 routes `authorization_servers` entries to RFC 8414 §2,
        // which requires each issuer identifier to be an https URL. Allow http only
        // when an explicit dev-mode opt-in (`allowHttp`) is passed, matching the
        // outbound TransportSecurity policy.
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
        {
            throw new ArgumentException($"Issuer must be an absolute URL, got '{issuer}'.", nameof(issuer));
        }

        if (issuerUri.Scheme == Uri.UriSchemeHttps)
        {
            // ok
        }
        else if (allowHttp && issuerUri.Scheme == Uri.UriSchemeHttp)
        {
            // ok (dev mode)
        }
        else
        {
            throw new ArgumentException(
                $"authorization_servers entry must use https (got scheme '{issuerUri.Scheme}', issuer='{issuer}').",
                nameof(issuer));
        }
    }

    public static ProtectedResourceMetadata Build(
        string issuer,
        string resource,
        IReadOnlyList<string> scopes,
        IReadOnlyList<string>? dpopSigningAlgValuesSupported = null,
        bool allowHttp = false,
        bool dpopBoundAccessTokensRequired = false)
    {
        return new ProtectedResourceMetadata(
            resource, issuer, scopes,
            dpopSigningAlgValuesSupported,
            allowHttp,
            dpopBoundAccessTokensRequired);
    }

    /// <summary>
    /// Serializes this metadata as RFC 9728 JSON (snake_case member names).
    /// </summary>
    public string ToRfc9728Json()
    {
        var scopesArray = Scopes is string[] already ? already : Scopes.ToArray();
        var dict = new Dictionary<string, object?>
        {
            ["resource"] = Resource,
            ["authorization_servers"] = new[] { Issuer },
            ["bearer_methods_supported"] = new[] { "header" },
            ["resource_signing_alg_values_supported"] = new[] { "RS256", "ES256" },
            ["scopes_supported"] = scopesArray,
        };

        // RFC 9728 §2: DPoP support is signalled by the presence of
        // `dpop_signing_alg_values_supported`. When DPoP is configured we
        // emit BOTH that array AND the `dpop_bound_access_tokens_required`
        // boolean (true OR false). Emitting just one of the two told
        // discovery clients "this resource supports DPoP" but kept them
        // guessing whether bearer tokens are also allowed.
        if (DpopSigningAlgValuesSupported is not null && DpopSigningAlgValuesSupported.Count > 0)
        {
            dict["dpop_signing_alg_values_supported"] = DpopSigningAlgValuesSupported is string[] arr
                ? arr
                : DpopSigningAlgValuesSupported.ToArray();
            dict["dpop_bound_access_tokens_required"] = DpopBoundAccessTokensRequired;
        }
        else if (DpopBoundAccessTokensRequired)
        {
            // Defensive: a caller that built the metadata with
            // `dpopBoundAccessTokensRequired:true` but no advertised algs is
            // signalling DPoP-required intent without a complete capability
            // surface. Surface the required flag rather than silently dropping
            // it.
            dict["dpop_bound_access_tokens_required"] = true;
        }

        return JsonSerializer.Serialize(dict);
    }
}

