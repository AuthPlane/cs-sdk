# Authplane .NET SDK — User guide

This guide covers the `Authplane.Sdk` core library and how it relates to `Authplane.Mcp`. For package layout and build commands, see the [repository README](../README.md).

## Quickstart (resource server)

Use **`AuthplaneClient`** for shared HTTP, JWKS cache, and [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) / OIDC discovery. Create one **`AuthplaneResource`** per protected resource URI (audience).

```csharp
await using var client = await AuthplaneClient.CreateAsync(
    "https://auth.example.com",
    FetchSettings.FromDevMode(devMode: false));

await using var resource = await client.CreateResourceAsync(
    "https://api.example.com/mcp",
    new[] { "tools/echo" });

var claims = await resource.VerifyAsync(accessToken, dpopRequest: null);
claims.RequireScope("tools/echo");
```

Legacy entry point (creates an internal client; dispose the resource to release HTTP resources):

```csharp
await using var resource = await AuthplaneResource.CreateAsync(
    issuer: "https://auth.example.com",
    resource: "https://api.example.com/mcp",
    scopes: new[] { "tools/echo" });
```

## API overview

| Type | Role |
| --- | --- |
| **`AuthplaneClient`** | Issuer-scoped shared infrastructure: discovery, `HttpClient`, JWKS cache. |
| **`AuthplaneResource`** | Verify JWT access tokens for a fixed `resource` + `scopes` list; implements `IAsyncDisposable`. |
| **`AuthplaneAuthClient`** | OAuth **client** calls (client credentials, introspection, token exchange) with circuit breaker — separate from resource verification. |
| **`VerifiedClaims`** | Immutable claims after successful verification; `RequireScope` for enforcement. |
| **`ProtectedResourceMetadata`** | RFC 9728 PRM payload; `ToRfc9728Json()` for wire format. |
| **`OAuthProtectedResourceMetadata`** | `GetDocumentUrl(resourceUrl)` — PRM document URL (§3.1). |

## RFC 9728 — Protected Resource Metadata (PRM)

- **Document URL:** `OAuthProtectedResourceMetadata.GetDocumentUrl(resourceUri)` — template `/.well-known/oauth-protected-resource{path}{resource-query}`.
- **JSON:** `resource.GetProtectedResourceMetadata().ToRfc9728Json()` — includes `authorization_servers`, `bearer_methods_supported`, `resource_signing_alg_values_supported`, `scopes_supported`.

The **`Authplane.Mcp`** middleware serves this document **publicly** on `GET` before auth runs, and adds `resource_metadata` to `WWW-Authenticate` challenges (401/403) so MCP clients can discover the authorization server.

## DPoP (RFC 9449)

- **Inbound:** pass `DPoPRequestContext` to `VerifyAsync` with method, absolute request URL, optional `DPoP` proof string, and optional `IDPoPReplayStore` (register `InMemoryDPoPReplayStore` in DI for the MCP host).
- **Outbound:** configure `IDPoPSigner` (e.g. `ES256DpoPSigner`) on `AuthplaneAuthClient` for token endpoint calls that require DPoP.

## Error handling (verification)

Typical mapping for HTTP APIs:

| Exception | HTTP | Notes |
| --- | --- | --- |
| `TokenMissingException` | 401 | No bearer token. |
| `TokenExpiredException` | 401 | Expired JWT. |
| `InvalidSignatureException` | 401 | Bad signature / unknown `kid`. |
| `InvalidClaimsException` | 401/403 | Claim validation failed. |
| `InsufficientScopeException` | 403 | Scope check failed (`RequireScope`). |
| `DPoPProofMissingException`, `InvalidDPoPProofException`, `DPoPBindingMismatchException`, `DPoPReplayDetectedException` | 401 | DPoP-bound token issues. |
| `JwksFetchException` | 502/503 | JWKS or discovery fetch failed. |

OAuth **client** flows (`AuthplaneAuthClient`) use `AuthplaneTokenRequestException`, `ConsentRequiredException`, `CircuitOpenException`, etc.; circuit breaker records failures only for transport/server-class errors (see `CircuitPolicy`).

## Security notes

- **Algorithms:** RS256 and ES256 only; HMAC and `none` are rejected.
- **Audience / issuer:** JWT `iss` and `aud` must match the configured issuer and resource URI.
- **SSRF:** `FetchSettings` restricts outbound URLs for metadata and JWKS (allowlists, HTTP/HTTPS policy).
- **Dev mode:** relaxes TLS/localhost rules for local demos — do not enable in production.

## Lifecycle and disposal

- **`AuthplaneClient`:** `await using` / `DisposeAsync` — releases `HttpClient`.
- **`AuthplaneResource`:** If created via `AuthplaneResource.CreateAsync`, disposing the resource disposes the internal `AuthplaneClient`. If created via `AuthplaneClient.CreateResourceAsync`, dispose the **client** after all resources are done (resources do not dispose the shared client).
- **`AuthplaneAuthClient`:** `IAsyncDisposable` — dispose to close HTTP connections.

## OAuth token operations (`AuthplaneAuthClient`)

- `ClientCredentialsAsync` — client credentials grant.
- `IntrospectAsync` — RFC 7662 introspection.
- `TokenExchangeAsync` — RFC 8693 token exchange (including consent / URL elicitation errors surfaced as typed exceptions where applicable).

Circuit breaker: see `AuthplaneAuthResilienceOptions` and `CircuitBreakerState` for observability.

## Configuration reference

- **`FetchSettings`:** timeouts, SSRF policy, allowed hosts; use `FromDevMode(bool)` for defaults tuned to dev vs production.
- **`AuthplaneMcpAuth.Options`:** `issuer`, `resource`, `scopes`, `devMode` — passed to `CreateResourceAsync` for MCP integration.

## Conformance

The core test suite includes catalog-driven conformance cases under `tests/Authplane.Tests/`. Run the full solution tests (including conformance filters in CI) per repository instructions.

## MCP adapter (`Authplane.Mcp`)

- `AuthplaneMcpAuth.CreateResourceAsync` — builds an `AuthplaneResource` for the MCP host.
- `UseAuthplaneMcpAuth` — middleware: public PRM `GET`, bearer + optional DPoP verification, scope enforcement from tool calls or `x-authplane-required-scopes`.

See package README under `src/Authplane.Mcp/` for extension details.
