# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `AccessDeniedException` (`access_denied`, 403) and `InvalidTargetException` (`invalid_target`, 400) typed by `MapOAuthError`; neither counts toward the circuit breaker.
- `AuthplaneMcpAuth.Options.ResourceMetadataUrl` points challenge `resource_metadata` at an AS-hosted PRM document instead of the derived resource-hosted URL; gated at construction under the resource identifier's shape rules (absolute `http(s)` URL with a host, and no fragment, userinfo, whitespace, backslash, malformed port, or out-of-grammar octet in the host, path or query), with no host policy and no `devMode` coupling, so `http://authserver:8080/...` boots.
- README **Compatibility** section: tested against authserver 0.2.0; introspection-based revocation requires authserver 0.1.2 or later.
- Resource-server-side DPoP nonce enforcement (RFC 9449 §9). The SDK handled nonces only outbound until now, so a resource server built on it could not adopt the mitigation at all. `InboundDPoPOptions` gains a `nonceIssuer` parameter as the opt-in switch; `null`, the default, leaves every existing deployment byte-identical, and non-null makes the nonce mandatory on every inbound proof — every client's first DPoP request then takes a 401 `use_dpop_nonce` round trip.
- Inbound DPoP nonces — new public API: `IDPoPNonceIssuer` and its built-in `HmacDPoPNonceIssuer`, `DPoPNonceRequiredException`, `AuthplaneErrors.ResponseHeaders` and `VerifiedClaims.NextDPoPNonce`. The HMAC key is a required constructor argument — the key is the deployment topology, and a per-process default behind a load balancer degenerates into a 401 loop; `HmacDPoPNonceIssuer.CreateEphemeral()` is the explicit single-process door.
- Inbound DPoP nonces — a missing, unknown or expired nonce answers 401 with a `DPoP`-scheme challenge carrying `error="use_dpop_nonce"` and a fresh nonce in a `DPoP-Nonce` response header. A framework-agnostic adapter must copy `AuthplaneErrors.ResponseHeaders` onto the response, or that challenge cannot be satisfied.
- Inbound DPoP nonces — a nonce accepted in the second half of its lifetime surfaces as `VerifiedClaims.NextDPoPNonce`, which the middleware advertises in the `DPoP-Nonce` header of the 200 and of the insufficient-scope 403. An adapter that copies only `ResponseHeaders` never sends the rotated nonce, so its clients take a 401 each time one expires — the round trip that rotating at half-life exists to avoid.
- Inbound DPoP nonces — nonce checks run only after every other proof check has passed, so an invalid proof still gets its own error, and the per-request `DPoPRequestContext.RequiredNonce` exact-echo check keeps precedence over the resource-level policy. Issuer output violating the RFC 9449 §8.1 `NQCHAR` syntax surfaces as `VerifierRuntimeException` (HTTP 500), not `invalid_token`.
- `AuthplaneErrors.ErrorResponseBody(...)`, `ErrorDescriptionFor(code)` and `ErrorCodeFor(error)`: the RFC 6750 §3 JSON error body and the fixed description, built from the code the challenge names. A null or empty code is the no-credentials case: both accept it without guarding, and the body then omits `error` entirely, as the challenge does (RFC 6750 §3.1 ties `invalid_request` to a 400, not to a 401 asking the caller to authenticate).
- `Authplane.Mcp` — the middleware logs the exception behind every failure under the `Authplane.Mcp` category before writing the response: `Error` for a 5xx, which is this server's own fault, and `Debug` for a rejection, since reaching one takes no credentials and a higher level would let an unauthenticated caller choose the host's log volume. Logging is optional — a host with no `ILoggerFactory` registered gets no lines and no error.

### Changed

- `TokenRevokedException` from an `active=false` introspection now names the other cause: the AS not recognising this resource server as the token's owner (authserver ≥ 0.1.2 runtime-client rule).
- User guides document `access_denied` vs `consent_required` on token exchange, the `allowed_client_ids` operator step, and the confidential + runtime-client requirement for introspection.
- `manual-e2e-setup.sh` no longer sets `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED` (on by default since authserver 0.2.0) and accepts `AUTHSERVER_REF` to check out an authserver ref before building.
- `manual-e2e-smoke.sh` no longer calls `POST /admin/scopes` (the route does not exist in authserver 0.2.0; the demo provisioner creates the scopes).
- `OAuthProtectedResourceMetadata.GetDocumentUrl` now derives the whole document URL — authority and path, not only the query — by slicing the original identifier string, so the result is the configured identifier with the well-known string inserted between the authority and the path. **Migration**: none for an identifier already written in the form clients are configured with; one carrying an uppercase scheme or host, a default port, or dot-segments now advertises a different, non-normalized `resource_metadata` URL, so update any hard-coded expectation of the old value.
- Derived PRM URL — reading the path off `Uri.AbsolutePath` re-rendered what the identifier did carry — a percent-escaped unreserved character unescaped, a dot-segment removed, an uppercase scheme or host lowercased, a default port dropped — while the PRM `resource` member emitted the configured bytes verbatim, which is the mismatch RFC 9728 §3.3 has a conformant client discard the document over.
- Derived PRM URL — the MCP middleware's PRM routing follows that derivation: it now compares the request's encoded target against the path sliced off the derived URL, keeping the decoded-path comparison as a fallback for hosts that do not expose a raw request target.
- **Breaking** A resource identifier must now be an absolute URL with a scheme and a host, enforced at construction with an `ArgumentException` — RFC 8707 §2 for the scheme, RFC 9728 §3 for the host. **Migration**: configure the full URL clients address.
- **Breaking** The identifier is also rejected at construction when it carries userinfo (RFC 9110 §4.2.4), whitespace, a backslash, a C0 control or DEL. Userinfo would publish a credential to unauthenticated callers; the other characters are silently rewritten by `Uri`, so the served document's `resource` member no longer matches the advertised URL and a conformant client discards it (RFC 9728 §3.3). **Migration**: remove credentials and surrounding whitespace from the configured identifier, and percent-encode an intentional interior space (`%20`) or backslash (`%5C`).
- Identifier gates — the same gates run in the `ProtectedResourceMetadata` constructor and `Build` — the type that emits the identifier as the PRM `resource` field — so a document cannot name an identifier this SDK refuses to derive a URL from. The query gate stays excluded there, since a query is carried into the derived URL and raises no mismatch.
- **Breaking** A port that is not RFC 3986 §3.2.3's `*DIGIT` in range — `:80O` with a letter O, `:99999` — is now rejected at construction on its own axis with its own message, ahead of the absoluteness gate that would otherwise report the wrong defect. A leading zero is rejected too: `:0080` is legal syntax, but stripping it is not an RFC 3986 §6.2 equivalence and a normalizing URL stack renders it `:80`, so a client re-derives a document URL that disagrees with the served document's verbatim `resource` member. **Migration**: write the port as in-range digits with no leading zero.
- `OAuthProtectedResourceMetadata.GetDocumentUrl` now preserves the resource identifier's query in the derived document URL — RFC 9728 §3 inserts the well-known string ahead of the path and query. **Migration**: update any hard-coded expectation of the old query-less URL. A bare `?` derives a URL with no query, an identifier without a query is unaffected, and serving a different document per query value is not supported.
- **Breaking** The identifier's query is now validated at construction against the RFC 3986 §3.4 production, because it flows verbatim into the derived document URL, where an out-of-grammar octet yields an advertised `resource_metadata` no client can fetch. **Migration**: percent-encode the offending octets. Rejected: a literal `"`, a space, and a malformed `%zz`. Unreserved characters, sub-delims, `:`, `@`, `/`, `?` and well-formed `%XX` are accepted unchanged.
- **Breaking** The identifier's path is validated at construction against the RFC 3986 §3.3 production, for the same reason as the query: the byte-exact derivation carries it verbatim into the advertised URL. **Migration**: percent-encode the offending octets. Rejected: a non-ASCII segment such as `/café` (percent-encode it as UTF-8), a zero-width space (U+200B), the delimiter set `"<>[]^{|}` and the backtick, a malformed `%zz` and a truncated `%2`. For a rejected identifier the previously derived URL was already the percent-encoded form, so re-encoding it advertises the same URL as before — but the identifier string now spells it explicitly, and the PRM `resource` member the document serves changes with it.
- **Breaking** A resource identifier carrying a URI fragment is now rejected at construction with an `ArgumentException` instead of being silently accepted (RFC 8707 §2; RFC 9728 §1.2). It was previously stored verbatim and echoed into the PRM document. **Migration**: drop the fragment. A percent-encoded `%23` is still accepted as path data.

- CI and release runs now check out the shared conformance catalog at the SHA pinned in `.conformance-catalog-ref` instead of the catalog's default branch, so a catalog change can no longer break a build on its own. The alignment guard is asserted in both directions, and a weekly drift workflow reports divergence from the catalog tip.

- Conformance catalog pin bumped to `583a6d9`, with markers for its three new resource-identifier cases.
- **BREAKING** `AuthplaneErrors.WwwAuthenticate(...)` now emits a fixed `error_description` chosen by the `error=` code instead of the exception message. **Migration**: log `error.Message` server-side, or pass `verboseDescription: true`.
- **BREAKING** `Authplane.Mcp` — the middleware now answers every failure with an RFC 6750 §3 JSON body (`application/json; charset=utf-8`) instead of prose such as `Missing Authorization header.` or `invalid_token: dpop_proof_missing`. **Migration**: parse `error` and `error_description` from the object; the status is unchanged, but the challenge is not — see the next entry.
- **BREAKING** `Authplane.Mcp` — the challenge and the body no longer carry the exception message, and the middleware's seven hardcoded descriptions give way to a fixed description per `error` code. `use_dpop_nonce` has no fixed description and takes the contentless fallback.
- **BREAKING** `Authplane.Mcp` — a 503 (`JwksFetchException`, `MetadataFetchException`) now answers `temporarily_unavailable` (RFC 6749 §5.2) instead of `server_error`, which read as a defect in this resource server rather than the authorization server being unreachable and retryable; a 500 still answers `server_error`, `CircuitOpenException` included. **Migration**: match `temporarily_unavailable` wherever a client tells a transient outage from a fault.

### Deprecated

- `VerifiedClaims.MayAct` marked `[Obsolete]`: authserver 0.2.0 no longer issues `may_act`; removed in the next minor.

### Fixed

- The MCP middleware's decoded-path fallback held `%5C` back from decoding while Kestrel decodes it, so a `%5C`-bearing resource identifier answered 401 at its own advertised metadata URL on hosts without a raw request target.
- `AuthplaneResource.CreateAsync` no longer abandons the `AuthplaneClient` it builds when the resource constructor rejects its arguments; `DisposeAsync` is now idempotent.
- The conformance drift marker is no longer duplicated between `ConformanceCatalogAlignment.DriftMarker` and the drift workflow with nothing tying them together; a test now fails if either copy changes without the other.
- The authority now has an RFC 3986 §3.2.2 character-production gate, so an internationalized host is rejected at construction instead of reaching a `WWW-Authenticate` challenge as a non-URI.
- The host production gate no longer throws `IndexOutOfRangeException` on an authority that is userinfo and nothing else (`https://user@`); the missing host is reported by the absoluteness gate as an `ArgumentException`, as it was before the gate was added.
- `AuthplaneClient.CreateAsync` no longer abandons the client it built when the priming metadata fetch fails or the caller's token is cancelled.
- An opaque resource identifier such as `mailto:ops@example.com` is no longer reported as carrying userinfo; it is still refused, now because an opaque URI has no host to derive a metadata document URL from.
- The MCP middleware's generic error arm hardcoded 401 for every `AuthplaneException`, so a JWKS or metadata outage surfaced as 401 `invalid_token` — prompting a pointless re-authentication against a healthy AS — instead of 503. The arm now takes its status from `AuthplaneErrors.HttpStatus` and emits `WWW-Authenticate` only on a 401, so a 5xx no longer carries a challenge, and a verifier runtime fault maps to 500. The 403 `insufficient_scope` challenge is unchanged.
- The conformance-catalog parser in `Authplane.Conformance.Shared` silently dropped cases it could not parse: one with an `id` but no `title` in any non-final position, and one whose title contains an apostrophe in any position. A dropped case never reaches `ConformanceCatalogAlignment`, so coverage it should have demanded went unasserted. The parser now keeps a title-less case with its id as the title, parses quoted titles properly, and no longer lets a full-line comment end the `cases:` block. Anything it still cannot parse — a case, a scalar, a block scalar indicator, an unknown escape — now throws, so a shape it does not understand breaks the build instead of vanishing.

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
