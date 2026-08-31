# Authplane.Sdk — User Guide

Reference for the framework-agnostic Authplane .NET SDK. This package is what you install when you need to validate Authplane-issued OAuth 2.1 JWT access tokens, perform token operations against the AS, and support DPoP-bound flows from your own resource server (MCP, ASP.NET Core, or any other host).

## 1. Install

```sh
dotnet add package Authplane.Sdk
```

Requires .NET 10. The package only depends on `System.IdentityModel.Tokens.Jwt`.

## 2. Quickstart

```csharp
using Authplane;

await using var client = await AuthplaneClient.CreateAsync(
    issuer: "https://auth.example.com",
    fetchSettings: FetchSettings.FromDevMode(devMode: false));

await using var resource = await client.CreateResourceAsync(
    resource: "https://api.example.com/mcp",
    scopes: new[] { "tools/echo" });

var claims = await resource.VerifyAsync(accessToken, dpopRequest: null);
claims.RequireScope("tools/echo");
```

Always `await using` the client so background JWKS / metadata refresh tasks stop on shutdown.

## 3. Core concepts

| Type | Role |
|---|---|
| `AuthplaneClient` | Issuer-scoped infrastructure: discovery (RFC 8414), shared `HttpClient`, JWKS cache, circuit breaker, optional outbound DPoP signer. |
| `AuthplaneResource` | Per-resource verifier. Owns the `aud` URI and required scopes. Implements `IAsyncDisposable`. |
| `AuthplaneAuthClient` | OAuth client operations (client credentials, introspection, token exchange, revocation) with circuit breaker. Separate from token verification. |
| `VerifiedClaims` | Immutable claim set returned from `VerifyAsync`. `RequireScope` for enforcement. |
| `ProtectedResourceMetadata` | RFC 9728 PRM payload; `ToRfc9728Json()` for the wire format. |
| `OAuthProtectedResourceMetadata` | Computes the PRM document URL (`/.well-known/oauth-protected-resource{path}{resource-query}`). |

## 4. Basic usage

### Verify a bearer token

```csharp
var claims = await resource.VerifyAsync(token);
```

`VerifyAsync` returns `VerifiedClaims` or throws an `AuthplaneException` subclass.

### Verify a DPoP-bound token

```csharp
using Authplane;

var requestContext = new DPoPRequestContext(
    method: "POST",
    url: "https://api.example.com/mcp",
    proof: request.Headers["DPoP"].FirstOrDefault(),
    replayStore: serviceProvider.GetRequiredService<IDPoPReplayStore>());

var claims = await resource.VerifyAsync(token, requestContext);
claims.RequireScope("tools/query");
```

Register `InMemoryDPoPReplayStore` (or your distributed implementation) at startup so `htm` / `htu` / `ath` checks have a replay window.

### Server-provided DPoP nonces (RFC 9449 §9)

A resource server can require every inbound proof to carry a nonce it issued, bounding how far ahead clients can pre-generate proofs. Pass a `nonceIssuer` on `InboundDPoPOptions`, next to the `replayStore`:

```csharp
var resource = await AuthplaneResource.CreateAsync(
    issuer: "https://auth.example.com",
    resource: "https://api.example.com",
    scopes: new[] { "tools/query" },
    inboundDpop: new InboundDPoPOptions(
        replayStore: sharedReplayStore,
        nonceIssuer: new HmacDPoPNonceIssuer(nonceKey)));
```

Operational notes:

- **Opt-in.** `nonceIssuer: null` (the default) leaves nonce enforcement off and every existing deployment byte-identical. Non-null makes the nonce mandatory on every inbound proof.
- **Multi-replica deployments must share the HMAC key.** `HmacDPoPNonceIssuer` nonces are stateless — any instance holding the same key accepts any sibling's nonce — so load the key from configuration or a secret store and pass the same bytes to every replica. `HmacDPoPNonceIssuer.CreateEphemeral()` is the explicit single-process alternative: its key is random and per-process, so behind a load balancer a nonce issued by one replica is rejected by the next and every request degenerates into a hard 401 loop.
- **Outside `Authplane.Mcp`, the adapter must do two things by hand.** On failure, catch `DPoPNonceRequiredException` and — alongside `AuthplaneErrors.HttpStatus` and `AuthplaneErrors.WwwAuthenticate` — copy every entry from `AuthplaneErrors.ResponseHeaders(ex)` onto the response; that is what carries the `DPoP-Nonce` header a `use_dpop_nonce` challenge is unsatisfiable without. On success, forward `VerifiedClaims.NextDPoPNonce` (when non-null) as the `DPoP-Nonce` response header so active clients rotate without a 401 round trip.

## 5. Main API reference

### `AuthplaneClient`

```csharp
public static Task<AuthplaneClient> CreateAsync(
    string issuer,
    FetchSettings? fetchSettings = null,
    IDPoPSigner? outboundDPoPSigner = null,
    CancellationToken cancellationToken = default);

public Task<AuthplaneResource> CreateResourceAsync(
    string resource,
    IEnumerable<string> scopes,
    CancellationToken cancellationToken = default);
```

### `AuthplaneResource`

```csharp
public Task<VerifiedClaims> VerifyAsync(string token, CancellationToken ct = default);
public Task<VerifiedClaims> VerifyAsync(
    string token,
    DPoPRequestContext? dpopRequest,
    CancellationToken ct = default);

public ProtectedResourceMetadata GetProtectedResourceMetadata();
public string GetProtectedResourceMetadataDocumentUrl();
```

### `AuthplaneAuthClient`

```csharp
public Task<TokenResponse> ClientCredentialsAsync(
    string? scope, string? resource = null, CancellationToken ct = default);

public Task<IntrospectionResponse> IntrospectAsync(string token, CancellationToken ct = default);

public Task<TokenResponse> TokenExchangeAsync(
    TokenExchangeOptions opts, CancellationToken ct = default);

public Task RevokeAsync(string token, string? tokenTypeHint = null, CancellationToken ct = default);
```

## 6. Configuration

### `FetchSettings`

| Property | Type | Default | Notes |
|---|---|---|---|
| `SsrfProtection` | `bool` | `true` | DNS pinning + private-IP block + cloud-metadata block. |
| `AllowHttp` | `bool` | `false` | When `true`, plain HTTP is permitted. Dev mode only. |
| `AllowLocalhost` | `bool` | `false` | When `true`, `127.0.0.1` / `::1` / `localhost` are reachable. |
| `AllowPrivateNetworks` | `bool` | `false` | When `true`, RFC 1918 ranges are reachable. |
| `TimeoutSeconds` | `double` | `10` | Per-request timeout. |

`FetchSettings.FromDevMode(true)` flips on `AllowHttp`, `AllowLocalhost`, `AllowPrivateNetworks`, and disables `SsrfProtection` for local demos. **Do not enable `devMode` in production.**

### `JwksFetchSettings` and `MetadataFetchSettings`

Subclasses of `FetchSettings` with defaults tuned for each endpoint (longer timeout for metadata, response-size cap for JWKS). Pass either or both to `AuthplaneClient.CreateAsync` for asymmetric outbound policy.

### `AuthplaneAuthResilienceOptions`

| Property | Default | Notes |
|---|---|---|
| `CircuitBreakerThreshold` | `5` | Consecutive failures before opening the breaker. |
| `CircuitBreakerCooldownSeconds` | `30` | Cooldown before half-open probing. |

## 7. Intermediate features

### Outbound DPoP (token endpoint)

Configure `IDPoPSigner` (e.g. `ES256DpoPSigner`) on `AuthplaneAuthClient` for token-endpoint calls that require DPoP. The client retries once on `error=use_dpop_nonce` using the `DPoP-Nonce` header.

```csharp
var dpop = ES256DpoPSigner.Generate();
await using var auth = new AuthplaneAuthClient(
    issuerUrl: "https://auth.example.com",
    clientId: "my-resource",
    clientSecret: "secret",
    dpopSigner: dpop);
```

### RFC 9728 — Protected Resource Metadata

```csharp
var documentUrl = OAuthProtectedResourceMetadata.GetDocumentUrl(resourceUri);
var json = resource.GetProtectedResourceMetadata().ToRfc9728Json();
```

The `Authplane.Mcp` middleware serves this document publicly on `GET` before auth runs.

### Token exchange (RFC 8693)

```csharp
var exchanged = await auth.TokenExchangeAsync(new TokenExchangeOptions(
    subjectToken: incomingToken,
    audience: "https://downstream.example.com"));
```

When the AS surfaces `consent_required` / `interaction_required`, the call throws `ConsentRequiredException`. Adapters (e.g. `Authplane.Mcp`) translate that into framework-specific responses; see `UrlElicitationSupport` in the MCP adapter for the MCP `-32042` mapping.

### Token revocation (RFC 7009)

```csharp
await auth.RevokeAsync(token, tokenTypeHint: "access_token");
```

## 8. Advanced features

### Verifying with revocation check

```csharp
var resource = await client.CreateResourceAsync(
    resource: "https://api.example.com",
    scopes: new[] { "read" },
    revocationChecker: new IntrospectionRevocation(authClient),
    failClosed: true);
```

`failClosed: true` rejects tokens whenever the revocation check itself errors; default `false` allows the verification to succeed when the AS is unreachable.

### JWKS resilience

`AuthplaneClient` keeps the JWKS hot via:

- **Background refresh** at 80 % of the configured TTL (default 300 s).
- **Stale-cache fallback** — if a refresh fetch fails, the previous `kid` set continues to be used while a warning is logged.
- **Force-refresh on `kid` miss** — a token with an unknown `kid` triggers a synchronous JWKS fetch once before failing verification.
- **Lock-coordinated fetches** so concurrent verifications don't stampede the AS.

## 9. Error handling

Typical mapping for HTTP APIs:

| Exception | HTTP | Notes |
|---|---|---|
| `TokenMissingException` | 401 | No bearer token. |
| `TokenExpiredException` | 401 | Expired JWT. |
| `InvalidSignatureException` | 401 | Bad signature / unknown `kid`. |
| `InvalidClaimsException` | 401/403 | Claim validation failed. |
| `InsufficientScopeException` | 403 | Scope check failed (`RequireScope`). |
| `DPoPProofMissingException`, `InvalidDPoPProofException`, `DPoPBindingMismatchException`, `DPoPReplayDetectedException` | 401 | DPoP-bound token issues. |
| `JwksFetchException`, `MetadataFetchException` | 502/503 | JWKS or discovery fetch failed. |
| `AuthplaneTokenRequestException` | varies | Generic OAuth client-flow failure with `OAuthError` and `HttpStatus`. |
| `ConsentRequiredException` | 403 | AS requires consent / URL elicitation. Translate via `UrlElicitationSupport` (MCP adapter). |
| `CircuitOpenException` | 503 | Auth client circuit breaker is open. |

## 10. Lifecycle and disposal

- **`AuthplaneClient`:** `await using` / `DisposeAsync` — releases the underlying `HttpClient` and stops JWKS / metadata refresh tasks.
- **`AuthplaneResource`:** `IAsyncDisposable`. If created via `AuthplaneResource.CreateAsync` the underlying client is disposed with the resource. If created via `AuthplaneClient.CreateResourceAsync`, dispose the client after all resources are done — the shared client is not disposed by individual resources.
- **`AuthplaneAuthClient`:** `IAsyncDisposable` — closes its HTTP connections.

## 11. Conformance

The core test suite includes catalog-driven conformance cases under `tests/Authplane.Tests/`. The runner uses the `[Conformance("rfc-xxxx-...")]` attribute provided by `Authplane.Conformance.Shared` to bind tests to the cases defined in `oauth-sdk-conformance-catalog.yaml`. See [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) for how to run the suite locally and add new bindings.

## See also

- [`Authplane.Mcp` user guide](../../Authplane.Mcp/docs/user-guide.md) — the MCP / ASP.NET Core adapter that wraps the types described here.
