# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-07

### Added

- Explicit RFC 9449 §4.3 #1 enforcement: the new
  `DPoPRequestContext.FromHeaderValues` factory rejects requests carrying
  more than one `DPoP` proof — as repeated header entries or as a single
  comma-folded value produced by a header-combining intermediary
  (RFC 9110 §5.3) — with the new `DPoPMultipleProofsException`, surfaced
  as a `DPoP`-scheme challenge with `error="invalid_dpop_proof"`
  (RFC 9449 §7.1) by both `AuthplaneErrors.WwwAuthenticate` and the MCP
  middleware. Only this rejection carries that code; the other DPoP
  failures keep `invalid_token`.
- Both packages now multi-target `net8.0;net10.0` and embed the Authplane
  package icon.

- `Authplane.Conformance.Shared` test library with `[Conformance]` attribute,
  `ConformanceTracker`, and `ConformanceCatalogAlignment` guard so
  conformance assertions are tagged and tracked against the shared catalog.
- `AuthplaneAuthClient.RevokeAsync` (RFC 7009 token revocation).
- `IDPoPNonceStore` / `InMemoryDPoPNonceStore` for outbound DPoP nonce handling.
- `JwksCache` with background refresh at 80% TTL, stale-cache fallback,
  force-refresh on `kid` miss, and lock-coordinated fetches.
- Proper SSRF hardening (`Net/IpValidation.cs`, `Net/Ssrf.cs`) with DNS pinning,
  anti-rebinding TOCTOU, cloud-metadata IP block, response-size limits, and
  no-redirects.
- `JwksFetchSettings` and `MetadataFetchSettings` for asymmetric outbound
  fetch policy.
- `IRevocationChecker` + `IntrospectionRevocation` + `failClosed` flag on
  `AuthplaneResource`.
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` (this file).
- Root README **Capabilities** section listing every implemented RFC, security
  feature, framework integration, and observability hook.
- Per-package `docs/user-guide.md` for `Authplane.Sdk` and `Authplane.Mcp`.
- `.editorconfig`, `Directory.Build.props`, `global.json`, `.pinact.yaml`.
- CI: `dotnet format --verify-no-changes` step, conformance catalog clone,
  upload of `conformance-report.{json,md}` as workflow artifact.
- Packaging: SourceLink + `.snupkg` symbol packages for downstream
  debugger step-through. Wired implicitly via `PublishRepositoryUrl=true`
  on the bundled .NET 10 SDK SourceLink — no explicit `Microsoft.SourceLink.GitHub`
  package reference required. `IncludeSymbols=true` +
  `SymbolPackageFormat=snupkg` produces a `.snupkg` next to each `.nupkg`;
  the publish workflow pushes both to nuget.org.

### Changed

- `OAuthProtectedResourceMetadata.GetDocumentUrl` now removes the trailing
  slash following the host component before inserting the well-known path
  suffix, per RFC 9728 §3.1. A resource configured as
  `https://api.example.com/mcp/` previously derived (and the MCP middleware
  served/advertised) `/.well-known/oauth-protected-resource/mcp/`; it now
  derives `/.well-known/oauth-protected-resource/mcp`. Only the document-URL
  derivation changed — the resource identifier itself is still stored,
  advertised, and compared exact-string everywhere else. A percent-encoded
  `%2F` in the final path segment is data, not a delimiter (RFC 3986 §3.3),
  and survives the trim.
- `src/Authplane/` reorganised into `OAuth/`, `Verifier/`, `Net/`, `DPoP/`,
  `Resilience/`, and `Metadata/` subfolders. The public namespace remains
  `Authplane`; no API breaking changes.
- `OAuthOperations.cs` (460 LOC) split into focused internals under
  `OAuth/Internal/` (`OAuthHttpClient`, `OAuthRequestBodies`,
  `OAuthResponseParser`, `OAuthErrorResponse`).
- All OAuth client exceptions (`AuthplaneTokenRequestException`,
  `ConsentRequiredException`, parsing exceptions, `ServerError`) consolidated
  in `Errors.cs`.
- `AuthplaneVerifier.cs` renamed to `AuthplaneResource.cs` (matches the class
  it contains).
- Root `README.md` rewritten as a user-facing intro per
  `sdk-documentation-conventions.md`. Build/test/coverage commands moved to
  `CONTRIBUTING.md`.
- Per-package READMEs rewritten as short hero pages with one quickstart and a
  link to the user guide; `dotnet restore/build/test` content moved to
  `CONTRIBUTING.md`.
- Coverage thresholds raised from 60/45 (line/branch) to 80/70.
- CI now runs both `Authplane.Tests` and `Authplane.Mcp.Tests`; the
  `--filter "FullyQualifiedName!~Conformance"` exclusion is removed.
- Smoke scripts moved from `demo/` to `scripts/`.
- `manual-e2e-smoke.sh` registers required scopes against the authserver
  before minting a token.
- `demo/Authplane.Mcp.Demo.csproj` now declares `IsPackable=false`, matching
  the hygiene flag the test and conformance projects already carry. The
  demo is `OutputType=Exe` so it was never producing a `.nupkg`; this just
  makes the intent explicit.
- **Breaking (verifier).** Inbound DPoP `htm` comparison is now byte-exact
  ordinal per RFC 9449 §4.3 step 11 / RFC 9110 §9.1 method-token semantics.
  A proof whose `htm` differs from the request method only in case (e.g.
  `htm:"post"` for a `POST` request) is now rejected with
  `InvalidDPoPProofException`. The previous behaviour case-folded both
  sides and silently accepted such proofs.
  Clients that emit lowercased `htm` must be updated.
- `AuthplaneMcpAuth.Options` accepts an `InboundDPoPOptions? inboundDpop`
  parameter and propagates it to the underlying `AuthplaneResource`. The
  MCP middleware's pre-token `WWW-Authenticate` challenge scheme now
  follows the configured DPoP mode: `Bearer`-only when DPoP is off,
  `DPoP`-only when `Required=true`, combined `Bearer+DPoP` otherwise.
  Previously the challenge always advertised both schemes regardless of
  whether the resource accepted DPoP.
- `ES256DpoPSigner` now implements `IDisposable` and releases the
  underlying `ECDsa` private key. Long-lived processes that rotate signers
  no longer leak native handles.
- `AuthplaneAuthClient.DisposeAsync` also clears the in-memory
  `TokenCache` so disposal releases the access tokens it was holding.
- Default `tokenTypeHint` parameters now reference
  `OAuthConstants.TokenTypeHintAccessToken` instead of the bare string
  literal; the values are unchanged.

### Deprecated

- `AuthplaneVerifier` legacy wrapper marked `[Obsolete]`; will be removed in
  v0.2.0. Migrate to `AuthplaneResource`.

### Removed

- The cosmetic `ConformanceTests.cs` runner (`() => Task.CompletedTask` per
  case) and the misleading `100 / 100 passed` report it produced. Replaced
  with a real `ConformanceCatalogAlignmentTests` guard.
- ~516 LOC of duplicated conformance plumbing across `Authplane.Tests` and
  `Authplane.Mcp.Tests`.

### Fixed

- Broken references to `Authplane.sln` (the file is `Authplane.slnx`).
- `demo/README.md` claimed `.NET 8 SDK` while `Authplane.csproj` targeted
  `net10.0`.
- `JwksCache` / `MetadataCache` background refresh used to get permanently
  stuck after a single call from a cancelled `CancellationToken`. The
  outer `Task.Run` received the caller's CT; when the CT was already
  cancelled at schedule time the task entered `Canceled` state and the
  `finally{}` that clears `_backgroundRefresh` never ran. From that
  point on `_backgroundRefresh` stayed pinned to a never-completing
  `Task` and no further background refresh was ever triggered for the
  lifetime of the cache — degrading silently to the 24h `_maxStaleAge`
  fallback. Task now schedules with `CancellationToken.None`.
- `AuthplaneClient.FetchMetadata` no longer swallows transport errors
  with a bare `catch { }`. When every discovery URL fails for
  transport reasons, the last transport exception is now attached as
  the `InnerException` on `MissingMetadataEndpointException`.
- `IntrospectionRevocation.IsRevokedAsync` no longer swallows
  `CircuitOpenException` when configured `failOpen: true`. A tripped
  circuit (AS observably unhealthy) now propagates so the
  resource-level `failClosed` / `failOpen` policy can decide.
  Previously the lenient I/O-error handling silently accepted any
  possibly-revoked token during an AS outage.
- Caller cancellation (`OperationCanceledException`) now propagates
  through the revocation check path instead of being translated to
  fail-open accepted.
- `AuthplaneResource.DecodeHeader` now uses
  `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes`
  instead of a hand-rolled `+`/`-` substitution + padding helper. No
  behavioural change.
- `WWW-Authenticate` challenges emitted from `AuthplaneMcpAuth` no
  longer over-advertise DPoP when the configured `AuthplaneResource`
  rejects DPoP-bound tokens. Previously a client that picked DPoP
  from the challenge negotiated a `cnf.jkt`-bound token and saw every
  request rejected as `DPoPNotSupportedException`.

### Added

- `Authplane.OAuthEndpoints` (internal) — single source of truth for the
  `/oauth/token`, `/oauth/introspect`, `/oauth/revoke` endpoint paths.
- `Authplane.OAuthRequestBodies.BuildTokenForm(token, hint?)` for the
  shared introspection / revocation parameter shape.
- `Authplane.JsonHelpers` (internal) — `GetStringOrNull`,
  `GetInt64OrNull`, `GetBoolOrNull`, `GetStringArrayOrEmpty` extension
  methods on `JsonElement`, replacing inline
  `TryGetProperty + ValueKind + Get*()` boilerplate.
- `Authplane.Base64Url`, `Authplane.DPoPHashes`,
  `Authplane.JwkThumbprint`, `Authplane.DPoPProofBuilder`,
  `Authplane.DPoPDefaults` (all internal) — single source of truth for
  base64url encoding, the DPoP `ath` digest, the RFC 7638 JWK
  thumbprint, the proof JWT shape, and the proof TTL / clock-skew
  defaults. Previously 3–4 near-identical copies of each lived across
  `DPoPKeyMaterial`, `DPoPProvider`, `ES256DpoPSigner`, and
  `AuthplaneResource`.
- `MissingMetadataEndpointException` overload accepting an
  `InnerException` for transport-failure causes.
- `OAuthConstants` expanded with nested static classes covering OAuth
  form-body parameters, RFC 6750 / 9449 error codes, HTTP header
  names, MIME types, auth scheme prefixes, RFC 8414 / 9728 well-known
  paths, JOSE algorithm identifiers, JWT claim names, DPoP-proof
  claim names, and JWK parameter names.

### Security

- SSRF hardening on outbound HTTP (DNS pinning, IP allow-list,
  cloud-metadata block, response size limit, no redirects).
- DPoP outbound nonce flow now resilient to AS nonce rotation.
- Bounded the `use_dpop_nonce` retry in `OAuthHttpClient` to a single
  attempt per RFC 9449 §8. A misbehaving or hostile AS that kept
  returning `400 use_dpop_nonce` with a fresh `DPoP-Nonce` header
  used to cause unbounded recursion in `DoTokenRequestAsync` /
  `DoPostFormAsync`, exhausting either the stack or the available
  sockets before any caller saw an error.
- `AuthplaneErrors.WwwAuthenticate` now strips CR / LF / control
  characters from `error_description` and `realm` quoted-string
  parameters before emitting the header (RFC 7230 / RFC 9110 forbid
  CTLs in field values). Previously the helper backslash-escaped `"`
  and `\` but passed every other byte through, so attacker-controlled
  fragments of `error.Message` containing CR/LF could inject
  continuation lines into the response and forge arbitrary headers.
  The MCP middleware's separate challenge builder already enforced
  this invariant; both copies of the builder now agree.
- DPoP `htm` proof claim is now compared byte-exact against the
  request method, restoring RFC 9449 §4.3 step 11 strictness. See
  Changed.

### Security

- SSRF hardening on outbound HTTP (DNS pinning, IP allow-list,
  cloud-metadata block, response size limit, no redirects).
- DPoP outbound nonce flow now resilient to AS nonce rotation.

[Unreleased]: https://github.com/AuthPlane/cs-sdk/compare/v0.1.0...HEAD
