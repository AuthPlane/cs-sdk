# Authplane .NET SDK

[![CI](https://img.shields.io/github/actions/workflow/status/AuthPlane/cs-sdk/ci.yml?branch=develop&style=flat-square&label=CI)](https://github.com/AuthPlane/cs-sdk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)

OAuth 2.1 JWT validation and token operations for .NET resource servers, with a first-class adapter for [Model Context Protocol](https://modelcontextprotocol.io/) servers.

## Packages

| Package | Install | Purpose |
|---|---|---|
| [`Authplane.Sdk`](src/Authplane/README.md) | `dotnet add package Authplane.Sdk` | Framework-agnostic JWT validation, AS metadata discovery, and token operations |
| [`Authplane.Mcp`](src/Authplane.Mcp/README.md) | `dotnet add package Authplane.Mcp` | Adapter for the official [MCP .NET SDK](https://github.com/modelcontextprotocol/csharp-sdk) ASP.NET Core transport |

Requires .NET 8.0 or later.

## Capabilities

### Standards and RFCs

- OAuth 2.1 (draft-ietf-oauth-v2-1)
- RFC 8414 — Authorization Server Metadata discovery
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens (`typ=at+jwt`)
- RFC 7662 — Token Introspection
- RFC 7009 — Token Revocation
- RFC 8693 — Token Exchange
- RFC 9449 — DPoP (sender-constrained access tokens, inbound + outbound)
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 6750 — Bearer Token Usage
- RFC 7519 / 7517 — JWT and JWKS

### Security

- JWT signature, issuer, audience, `exp` / `nbf` / `iat`, and `typ` (`at+jwt`) validation; required claims enforced (`sub`, `client_id`, `exp`, `iat`, `jti`)
- Algorithm-confusion defenses: only `RS256` and `ES256`; `none` and HMAC rejected
- AS metadata hardening: discovered `issuer` must match configured issuer exactly; required endpoints must be present
- SSRF hardening on outbound HTTP: DNS pinning, private/loopback/link-local/cloud-metadata IP blocking, HTTPS-only, response size limits, no redirects
- HTTPS-only by default with a `devMode` toggle for `localhost` and private networks
- JWKS resilience: stale-cache fallback, background refresh at 80% TTL, force-refresh on `kid` miss, lock-coordinated fetches
- Inbound DPoP proof verification: binding, replay, `htm` / `htu` / `ath` checks
- Outbound DPoP proof generation with nonce retry and a pluggable nonce store
- Circuit breaker around authorization-server calls
- Token caching with TTL buffers

### Framework integrations

- Official [MCP .NET SDK](https://github.com/modelcontextprotocol/csharp-sdk) → [`Authplane.Mcp`](src/Authplane.Mcp/README.md)

### Observability

- Structured logging via `Microsoft.Extensions.Logging` across JWKS refresh, metadata discovery, circuit breaker transitions, token verification, and DPoP binding outcomes
- Strict nullable annotations and immutable `VerifiedClaims`

## Documentation

- Core SDK: [`src/Authplane/README.md`](src/Authplane/README.md) · [User Guide](src/Authplane/docs/user-guide.md)
- MCP adapter: [`src/Authplane.Mcp/README.md`](src/Authplane.Mcp/README.md) · [User Guide](src/Authplane.Mcp/docs/user-guide.md)
- Release history: [`CHANGELOG.md`](CHANGELOG.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Release policy: [`RELEASE_POLICY.md`](RELEASE_POLICY.md)
- Release runbook: [`RELEASE_SETUP.md`](RELEASE_SETUP.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
