# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-07

### Added

- Resource-server-side DPoP nonce enforcement (RFC 9449 §9). Until now the
  SDK handled nonces only outbound — `IDPoPNonceStore` remembers what an AS
  issued to us as a client — so a resource server built on it could not
  adopt the server-provided-nonce mitigation at all. `InboundDPoPOptions`
  gains a `nonceIssuer` parameter as the opt-in switch: `null` (the default)
  leaves every existing deployment byte-identical, including proofs that
  happen to carry an AS-issued nonce; non-null makes the nonce mandatory on
  every inbound proof. The new `IDPoPNonceIssuer` mints and recognises the
  nonces, with `HmacDPoPNonceIssuer` as the built-in implementation —
  stateless HMAC-sealed timestamps rather than a lookup store, because §9
  nonces bound proof *lifetime* while single-use is already the `jti` replay
  store's job, and a shared HMAC key makes any instance accept any
  sibling's nonce without shared infrastructure (default lifetime 300s,
  matching the max proof age). The HMAC key is a required constructor
  argument: the key IS the deployment topology, and a defaulted per-process
  key behind a load balancer would degenerate every request into a hard
  401 loop that only shows up under multi-replica load. The explicit
  single-process door is `HmacDPoPNonceIssuer.CreateEphemeral()`. A
  missing, unknown, or expired nonce raises the new
  `DPoPNonceRequiredException` carrying a fresh nonce; both
  `AuthplaneErrors.WwwAuthenticate` and the MCP middleware surface it as
  HTTP 401 with a `DPoP`-scheme challenge carrying
  `error="use_dpop_nonce"` plus the fresh nonce in a `DPoP-Nonce` response
  header — deliberately distinct from `invalid_dpop_proof`, which tells the
  client its proof is broken when only the nonce needs refreshing. The new
  `AuthplaneErrors.ResponseHeaders` completes the framework-agnostic
  adapter contract (status from `HttpStatus`, challenge from
  `WwwAuthenticate`, extra headers from `ResponseHeaders`) by mapping
  `DPoPNonceRequiredException` to its `DPoP-Nonce` header — a
  `use_dpop_nonce` challenge without it is unsatisfiable — and the MCP
  middleware consumes the same mapping for status, challenge and headers
  alike. Issuer output is gated on the RFC 9449 §8.1 `NQCHAR` syntax at
  `DPoPNonceRequiredException` and `VerifiedClaims`, so a misbehaving
  custom issuer is rejected before its output can reach a response
  header — and the rejection surfaces as `VerifierRuntimeException`
  (HTTP 500): the server's plugin broke a contract, and reporting it as
  `invalid_token` would send a conformant client into a re-authenticate
  loop against a healthy AS. Nonce checks run only after every
  other proof check has passed, so a genuinely invalid proof still gets
  its proof error and never burns a nonce on a doomed retry. On the
  success side, a nonce accepted in the second half of its lifetime is
  surfaced as `VerifiedClaims.NextDPoPNonce` and advertised by the
  middleware in the `DPoP-Nonce` header of the 200 — and of the
  insufficient-scope 403, whose proof was accepted before the scope check
  failed (RFC 9449 §8.2 — the RFC leaves *when* to supply a new nonce to
  the server; rotating at half-life means a steadily active client never
  takes the 401 round trip). The per-request
  `DPoPRequestContext.RequiredNonce` exact-echo check is unchanged and
  takes precedence over the resource-level policy, following the replay
  store's per-request-override rule.

### Changed

- **Breaking for a deployment configured with a non-absolute resource
  identifier.** A resource identifier must now be an absolute URL with a
  scheme and a host, enforced at construction with an `ArgumentException`.
  RFC 8707 §2 requires the resource parameter to be "an absolute URI, as
  specified by Section 4.3 of [RFC3986]" (the scheme), and RFC 9728 §3 inserts
  the well-known suffix after the host component (the host). Previously a
  relative or opaque identifier was accepted and produced a malformed metadata
  URL: `urn:example:api` derived
  `/.well-known/oauth-protected-resourceexample:api`, and the relative `/mcp`
  and scheme-relative `//api.example.com/mcp` slipped through via the
  runtime's implicit `file` scheme — the latter is also how
  `UseAuthplaneMcpAuth` could anchor the DPoP `htu` origin on `file://`. The
  gate therefore runs at one site more than the fragment gate needed: the
  `AuthplaneMcpAuth.Options` constructor — the single operator-facing entry
  for the MCP adapter, so `CreateResourceAsync`, `SetupAsync`, and
  `UseAuthplaneMcpAuth` (including the lazy-DI wiring the user guide shows)
  all fail at startup — plus `AuthplaneResource.CreateAsync`,
  `AuthplaneClient.CreateResourceAsync`, and
  `OAuthProtectedResourceMetadata.GetDocumentUrl`.
  *Migration:* configure the full URL of the protected resource — for example
  `/mcp` becomes `https://api.example.com/mcp`. `http` hosts are still
  accepted for local development; no scheme allowlist is imposed.
- **Breaking for a deployment configured with userinfo, whitespace, or a
  backslash in the resource identifier.** Alongside the absolute-URL gate,
  the identifier is now rejected at construction when it carries a userinfo
  component (`https://svc:s3cr3t@api.example.com/mcp`, or `mailto:`-style
  identifiers whose syntax fills the userinfo slot — RFC 9110 §4.2.4 forbids
  generating userinfo in http(s) URIs), whitespace anywhere in the string, or
  a backslash. Neither whitespace nor a backslash can appear unescaped in an
  RFC 3986 URI, and `Uri` silently rewrites both instead of rejecting them —
  surrounding whitespace is trimmed, an interior space is escaped to `%20`,
  and a backslash becomes `/` — while the published PRM `resource` field
  echoes the identifier verbatim, so the identifier and the derived document
  URL diverged and a conformant client discards the document (RFC 9728 §3.3).
  Userinfo previously passed construction and then failed on every request
  inside `GetDocumentUrl`; a trailing space — typically from a `.env` value —
  and a backslash were silently accepted. Those three now fail at startup with
  an `ArgumentException` naming the actual defect. Whitespace and the backslash
  are two of the three rewrite shapes this closes; C0 controls and DEL are the
  third, rejected by the same gate with a message of their own, since telling an
  operator to look for a space they cannot see is worse than saying nothing.
  `Uri` canonicalizes the path in other ways that still construct — a non-ASCII
  segment, a zero-width space (a format character above `0x20`, so neither
  whitespace nor a control), a malformed percent-escape — which
  `OAuthProtectedResourceMetadata` documents at its derivation as a known
  limitation. This is not a claim that the divergence class is closed.
  A port that is not RFC 3986 §3.2.3's `*DIGIT` in range — `:80O` with a letter
  O, `:99999` — is now its own axis with its own message, rather than inheriting
  the absoluteness one: all three are absolute URLs with a scheme and a host,
  and what they have is a bad port. It runs ahead of the absoluteness gate,
  because `Uri.TryCreate` fails on them and the parse failure would otherwise
  report the wrong defect first. A leading zero is rejected as well: `:0080` is legal
  RFC 3986 §3.2.3 syntax, but the derivation renders it `:80` while the emitted identifier
  keeps it — the same emit-versus-derive divergence the axis exists to prevent, and not one
  of the RFC 3986 §6.2 equivalences (host case, dot-segments, default-port removal) the
  derivation is documented to apply. Only an all-digit port is echoed back; a port
  carrying non-digits has the same shape as a userinfo whose `@` was forgotten
  (`https://user:pass/x`), so it renders as `(malformed port)`.

  The gates also run in the `ProtectedResourceMetadata` constructor and `Build`
  — the type that *emits* the identifier as the PRM `resource` field. Gating
  only the derivation half would have left an operator able to construct and
  serve a document naming an identifier the same SDK refuses to derive a URL
  from. The query gate stays excluded there, and only there: a query is carried
  into the derived URL, so emitting one raises no mismatch for that type to
  prevent.

  *Migration:* remove credentials and surrounding whitespace from the
  configured identifier, and percent-encode an intentional interior space
  (`%20`) or backslash (`%5C`); none of these ever reached the served
  metadata correctly.
- `OAuthProtectedResourceMetadata.GetDocumentUrl` now preserves the resource
  identifier's query component in the derived Protected Resource Metadata
  document URL. RFC 9728 §3 inserts the well-known string "between the host
  component and the path and/or query components, if any"; a query is legal on
  a resource identifier (RFC 8707 §2 states the SHOULD NOT and its exception
  in the same sentence, carried forward by RFC 9728 §1.2). Previously the
  derivation used only the authority and `Uri.AbsolutePath`, silently dropping
  the query: `https://api.example.com/mcp?tenant=a` derived
  `…/.well-known/oauth-protected-resource/mcp`; it now derives
  `…/.well-known/oauth-protected-resource/mcp?tenant=a`. When no terminating
  slash follows the host (`https://api.example.com?x=1`) the suffix lands
  directly after the host and the query follows
  (`…/.well-known/oauth-protected-resource?x=1`); a terminating slash before
  the query is removed per RFC 9728 §3.1, deriving the same URL. The query is
  carried over verbatim from the original identifier string, so its
  percent-encoding is preserved byte-for-byte (`Uri.Query` is not used: `Uri`
  canonicalizes on construction and unescapes percent-encodings of unreserved
  characters, turning `%7E` into `~`). The *path* portion of the derived URL is
  still taken from `Uri.AbsolutePath` and so is still canonicalized; that is
  unchanged by this release.
  A bare `?` is an empty query and derives a query-less URL:
  `https://api.example.com/mcp?` derives
  `…/.well-known/oauth-protected-resource/mcp`, with no dangling `?`.
  *Migration:* if your resource identifier contains a non-empty query component, the PRM
  document URL advertised in `WWW-Authenticate: … resource_metadata=` now
  includes that query. Update any hard-coded expectation of the old query-less
  URL. Your existing PRM route continues to serve the document — routing is
  unchanged. Serving distinct documents per query value is not supported.
  Identifiers without a query derive exactly the same URL as before.
- **Breaking for a deployment configured with a query outside the RFC 3986
  §3.4 `query` production.** Because the query now flows verbatim from the
  configured identifier into the derived document URL, a query outside the
  production produces an advertised `resource_metadata` value that is not a
  URI and that no client can fetch. The identifier's query is therefore
  validated at construction: characters outside the production (for example
  `"` or a space) and malformed percent-escapes (`%zz`) are rejected with an
  `ArgumentException`, so the misconfiguration surfaces at startup instead of
  at request time. The gate applies to the same sites as the fragment gate, except
  the `ProtectedResourceMetadata` constructor / `Build`: a query, unlike a fragment,
  is carried into the derived URL, so emitting one raises no RFC 9728 §3.3 mismatch
  for that type to prevent.
  This is not a fix for a header-injection issue and there was none: the MCP
  middleware has always escaped `"`, `\` and control characters in every
  `WWW-Authenticate` parameter it emits, both before and after this change.
  *Migration:* percent-encode the offending characters in the configured
  identifier; every legal query character — unreserved, sub-delims, `:`, `@`,
  `/`, `?`, and well-formed `%XX` escapes — is accepted unchanged.
- **Breaking for a deployment configured with a fragment.** A resource
  identifier carrying a URI fragment is now rejected at construction with an
  `ArgumentException`, instead of being silently accepted. RFC 8707 §2 states
  "The URI MUST NOT include a fragment component", and RFC 9728 §1.2 defines
  the resource identifier as a URL with no fragment component. Previously
  `https://api.example.com/mcp#frag` was stored verbatim and echoed as the PRM
  `resource` field, while `GetDocumentUrl` derived the well-known URL from the
  authority plus `Uri.AbsolutePath` and so dropped the fragment. The served
  document then named a resource that disagreed with the URL it was fetched
  from, which RFC 9728 §3.3 requires a conformant client to discard — an
  interop failure with no error raised anywhere on the server side.
  The gate applies to `AuthplaneResource.CreateAsync`,
  `AuthplaneClient.CreateResourceAsync`, `AuthplaneMcpAuth.CreateResourceAsync`
  / `SetupAsync`, `OAuthProtectedResourceMetadata.GetDocumentUrl`, and the
  `ProtectedResourceMetadata` constructor / `ProtectedResourceMetadata.Build` —
  the last of these being the type that *emits* the identifier as the PRM
  `resource` field, so gating only the derivation half would have left the
  mismatch constructible through public API.
  The exception message names the offending identifier, with the fragment and
  any userinfo elided.
  *Migration:* drop the fragment from the configured resource identifier — for
  example `https://api.example.com/mcp#frag` becomes
  `https://api.example.com/mcp`. Because the fragment never reached the served
  metadata document or the well-known URL, removing it changes no
  externally-visible value; deployments without a fragment are unaffected. The
  check looks for the literal `#` fragment delimiter (RFC 3986 §3.5), so a
  percent-encoded `%23` remains ordinary path data and is still accepted.
  Whether a resource identifier must additionally be an absolute URL is a
  separate axis, addressed by the absolute-URL entry above.

- CI and release runs now check out the shared conformance catalog at the SHA
  pinned in the tracked `.conformance-catalog-ref` instead of the catalog's
  default branch, so a catalog change can no longer break a build on its own.
  The catalog-alignment guard is asserted in both directions — every catalog
  case carries a `[Conformance]` marker, and every marked id exists in the
  catalog — and a weekly `conformance-catalog-drift` workflow runs the same
  assertion against the catalog's unpinned tip as an early warning.

### Fixed

- The MCP middleware's generic error arm hardcoded 401 for every
  `AuthplaneException`, contradicting the `AuthplaneErrors.HttpStatus`
  mapping it now shares with framework-agnostic adapters: a JWKS or
  metadata outage surfaced to the client as 401 `invalid_token` —
  prompting a pointless re-authentication against a healthy AS — instead
  of 503, and a verifier-side runtime fault as anything but 500. The arm
  now takes its status from `HttpStatus` and emits a `WWW-Authenticate`
  challenge only on 401: a 5xx is the server's fault, and a challenge
  would direct the client to fix credentials that are not the problem.
- The conformance-catalog parser in `Authplane.Conformance.Shared` used
  to drop cases silently in shapes it did not understand: a case with an
  `id` but no `title` was dropped in every non-final position (the final
  case already fell back to its id), and a case whose title contains an
  apostrophe was dropped in any position (the title regex could not match
  past the `'`). A dropped case never reaches
  `ConformanceCatalogAlignment`, which treats an absent case as
  nothing-to-check — so the alignment guard stayed green while
  under-checking. The parser now keeps a title-less case with its id as
  the title, parses quoted titles properly (apostrophes, escaped quotes,
  and long scalars wrapped across lines the way the catalog emitter
  writes them), and throws on any case list item or quoted scalar it
  cannot parse instead of skipping it. The same fail-loudly rule now
  covers the block boundary and the scalar grammar: a full-line comment
  no longer ends the `cases:` block (only a top-level key or the
  document-end marker does, anything else at column 0 throws), a quoted
  scalar whose continuation leaves the case item throws instead of
  swallowing the cases in between, the double-quoted escape set is
  decoded properly (`\n`, `\t`, `\r`, `\0`, `\/`, `\"`, `\\`, `\ `,
  `\uXXXX`) with unknown escapes throwing instead of being mangled,
  block scalar indicators throw instead of being returned as the value,
  ids parse through the same scalar grammar as titles, and the case
  field indentation is derived from the file instead of hardcoded. The
  catalog drift guard is a contract shared with the other AuthPlane
  SDKs; failing loudly on unparseable catalog shapes is now this SDK's
  side of it.

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
