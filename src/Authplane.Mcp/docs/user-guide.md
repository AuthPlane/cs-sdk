# Authplane.Mcp — User Guide

Reference for the Authplane adapter that wires the core SDK into the official [MCP .NET SDK](https://github.com/modelcontextprotocol/csharp-sdk)'s ASP.NET Core HTTP transport. Use this package when you have an MCP server hosted as ASP.NET Core (e.g. via `WebApplication`, `MapMcp`) and you want Authplane-issued JWT access tokens to be validated automatically — including PRM publication, scope enforcement, DPoP, and consent-required URL elicitation.

## 1. Install

```sh
dotnet add package Authplane.Mcp
```

Brings `Authplane.Sdk` along as a transitive dependency. Requires .NET 10.

## 2. Quickstart

```csharp
using Authplane;
using Authplane.Mcp;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

var options = new AuthplaneMcpAuth.Options(
    issuer: "https://auth.company.com",
    resource: "https://mcp.company.com/mcp",
    scopes: new[] { "tools/query", "tools/write" },
    devMode: false);

builder.Services.AddSingleton<AuthplaneResource>(_ =>
    AuthplaneMcpAuth.CreateResourceAsync(options).GetAwaiter().GetResult());
builder.Services.AddSingleton<IDPoPReplayStore, InMemoryDPoPReplayStore>();

builder.Services.AddMcpServer().WithHttpTransport().WithToolsFromAssembly();

var app = builder.Build();
app.UseAuthplaneMcpAuth(options);
app.MapMcp(pattern: "/mcp");
await app.RunAsync();
```

## 3. Core concepts

| Type | Role |
|---|---|
| `AuthplaneMcpAuth` | Static helpers: builds the `AuthplaneResource` from `Options`, wires the middleware. |
| `AuthplaneMcpAuthExtensions.UseAuthplaneMcpAuth` | ASP.NET Core middleware. Serves the public RFC 9728 PRM document, runs token + DPoP verification, enforces scopes for the resolved tool. |
| `UrlElicitationSupport` | Translates `ConsentRequiredException` (raised by `AuthplaneAuthClient.TokenExchangeAsync`) into the MCP `UrlElicitationRequired` (`-32042`) error envelope. |

## 4. Basic usage

### Resolve scopes per tool

The middleware enforces a scope per request, derived from one of:

1. The MCP tool name (mapped via `Options.ScopeForTool`, optional).
2. An explicit `x-authplane-required-scopes` header on the inbound request.
3. The default `Options.scopes` list.

```csharp
var options = new AuthplaneMcpAuth.Options(
    issuer: "https://auth.company.com",
    resource: "https://mcp.company.com/mcp",
    scopes: new[] { "tools/query" },
    devMode: false)
{
    ScopeForTool = toolName => $"tools/{toolName}",
};
```

### Surface the PRM document

The middleware automatically responds to `GET /.well-known/oauth-protected-resource{...}` before auth runs. No additional wiring needed.

If you need the JSON yourself:

```csharp
var resource = serviceProvider.GetRequiredService<AuthplaneResource>();
var prmJson = resource.GetProtectedResourceMetadata().ToRfc9728Json();
```

### Where the PRM document lives

A `WWW-Authenticate` challenge names the PRM document through its `resource_metadata` parameter (RFC 9728 §5.1). Two topologies serve that document:

- **Resource-hosted — the default.** The middleware serves the document itself at `/.well-known/oauth-protected-resource{path}`, derived from `resource`, and advertises that URL. Nothing to configure.
- **AS-hosted.** authserver 0.2.0 and later serves a document for every registered Resource at `{issuer}/.well-known/oauth-protected-resource/{ref}`, where `{ref}` is the RFC 9728 §3.1 path suffix of the Resource URI (or its slug). Set `resourceMetadataUrl` to point challenges there — useful when the resource server cannot host well-known paths, for instance behind a gateway that owns `/.well-known`.

```csharp
var options = new AuthplaneMcpAuth.Options(
    issuer: "https://auth.company.com",
    resource: "https://mcp.company.com/mcp",
    scopes: new[] { "tools/query" },
    devMode: false,
    resourceMetadataUrl: "https://auth.company.com/.well-known/oauth-protected-resource/mcp");
```

The override is validated at construction under the same shape rules as the resource identifier — absolute http(s) URL with a host, and no fragment, userinfo, whitespace, backslash, malformed port, or out-of-grammar octet in the host, path or query — and changes the advertised URL only: the middleware keeps serving the resource-hosted document at its derived path either way. There is no host policy and no `devMode` dependency on this value: it is advertised to clients, never fetched by the SDK, so `http://authserver:8080/...` and a private-network address are both accepted, which is what the in-cluster and docker-compose topologies need.

Whichever topology you choose, RFC 9728 §3.3 requires the `resource` value **inside** the document to equal the URL clients call, byte for byte. The Resource URI registered at the authorization server, the `resource` configured here, and the public URL of the server must match exactly — a trailing slash or a different case in the host is enough for a conformant client to discard the document.

### Translate consent errors

Wrap a tool that calls `AuthplaneAuthClient.TokenExchangeAsync` so consent failures surface as MCP URL-elicitation errors:

```csharp
var result = await UrlElicitationSupport.TryWithUrlElicitationAsync(async () =>
{
    var token = await authClient.TokenExchangeAsync(new TokenExchangeOptions(
        subjectToken: incomingToken,
        audience: "https://downstream.example.com"));
    return await CallDownstream(token.AccessToken);
});
```

If `AuthplaneAuthClient` throws `ConsentRequiredException`, `UrlElicitationSupport` returns a structured `-32042` envelope the MCP client can render.

Two rejections look similar but are not consent problems, and neither counts toward the circuit breaker:

- `AccessDeniedException` (`access_denied`, HTTP 403) — the operator has not allow-listed this MCP server's client on the target Resource. Re-prompting the user will not fix it.
- `InvalidTargetException` (`invalid_target`, HTTP 400) — the `resource` value does not match a granted resource exactly, byte for byte (a trailing slash counts).

**Operator step.** For each MCP server that exchanges for a downstream resource it does not itself act as, allow-list its client id on that Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, fronted exchanges and Broker resources need nothing.

## 5. Main API reference

### `AuthplaneMcpAuth.Options`

```csharp
public sealed record Options(
    string Issuer,
    string Resource,
    IReadOnlyList<string> Scopes,
    bool DevMode = false)
{
    public Func<string, string?>? ScopeForTool { get; init; }
}
```

### `AuthplaneMcpAuthExtensions`

```csharp
public static IApplicationBuilder UseAuthplaneMcpAuth(
    this IApplicationBuilder app,
    AuthplaneMcpAuth.Options options);
```

### `UrlElicitationSupport`

```csharp
public static Task<T> TryWithUrlElicitationAsync<T>(Func<Task<T>> body);
```

## 6. Configuration

`AuthplaneMcpAuth.Options` covers the issuer, resource URI, scopes, the `devMode` toggle, the challenge `realm`, inbound DPoP, and `resourceMetadataUrl` (see [Where the PRM document lives](#where-the-prm-document-lives)). For finer-grained control of outbound HTTP (timeouts, SSRF policy), construct an `AuthplaneClient` yourself with explicit `FetchSettings` and pass the resulting `AuthplaneResource` to the DI container — the middleware uses whichever resource is registered.

## 7. Intermediate features

### DPoP inbound

The middleware passes the request method and absolute URL to `AuthplaneResource.VerifyAsync` whenever the token is DPoP-bound. Make sure to register `IDPoPReplayStore` (the default `InMemoryDPoPReplayStore` is sufficient for single-instance hosts; use a distributed store across replicas).

### Auth error mapping

The middleware translates the SDK exception hierarchy into HTTP responses, including `WWW-Authenticate` challenges with `resource_metadata` per RFC 9728:

| Exception | HTTP |
|---|---|
| `TokenMissingException`, `TokenExpiredException`, `InvalidSignatureException`, `InvalidClaimsException` | 401 |
| `InsufficientScopeException` | 403 |
| `DPoPProofMissingException`, `InvalidDPoPProofException`, `DPoPBindingMismatchException`, `DPoPReplayDetectedException` | 401 |
| `JwksFetchException`, `MetadataFetchException` | 503 |
| `CircuitOpenException`, `ProtocolException`, `VerifierRuntimeException` | 500 |

Every 401 and 403 also carries an RFC 6750 §3 JSON body
(`application/json; charset=utf-8`) whose `error` and `error_description` are
the same pair the `WWW-Authenticate` challenge names, so a client reading
either half sees the same answer:

```json
{"error":"invalid_token","error_description":"The access token is missing or not valid for this resource"}
```

A 5xx carries a body of the same shape but no challenge: telling a client to
fix credentials that are not the problem sends it round a loop it cannot exit.
Its `error` is `temporarily_unavailable` on a 503, where the authorization
server is unreachable from here and the condition is worth retrying, and
`server_error` on a 500, where this resource server is at fault:

```json
{"error":"temporarily_unavailable","error_description":"The authorization server cannot be reached from this resource server"}
```

A request that carried no credentials at all — no `Authorization` header, an
unrecognized scheme, or an empty token — is the one case with no `error` on
either side. RFC 6750 §3 has the challenge omit it, because the error codes
describe a request that did authenticate and failed, and the body omits it for
the same reason:

```json
{"error_description":"The request did not carry a usable access token"}
```

A client should read that absence the way the challenge already reads: begin
discovery and authenticate.

The description is a fixed sentence chosen by the `error` code, never the
exception's own message — the SDK's messages name the unknown `kid`, the claim
that did not validate, or the `aud` the resource expects, and the caller here
has by definition not authenticated.

The detail is not lost. Before writing any of these responses the middleware
logs the exception under the `Authplane.Mcp` category: at `Error` for a 5xx,
which is this server's own fault and which you want to see without having been
told to look, and at `Debug` for a rejection, since reaching a rejection takes
no credentials and logging every one higher would let an unauthenticated caller
choose your log volume. Raise the category while diagnosing:

```json
{ "Logging": { "LogLevel": { "Authplane.Mcp": "Debug" } } }
```

Logging is optional: a host with no `ILoggerFactory` registered gets no log
lines and no error.

## 8. Advanced features

### Manual setup (custom DI / non-WebApplication hosts)

```csharp
var resource = await AuthplaneMcpAuth.CreateResourceAsync(options);
services.AddSingleton<AuthplaneResource>(resource);
services.AddSingleton<IDPoPReplayStore, InMemoryDPoPReplayStore>();
```

Then plug the middleware in wherever in your pipeline:

```csharp
app.UseAuthplaneMcpAuth(options);
```

## 9. Error handling

The middleware never throws on the request path — every SDK exception lands as an HTTP response. If you wrap downstream calls (e.g. `AuthplaneAuthClient.TokenExchangeAsync`) inside your tool, surface their typed exceptions through `UrlElicitationSupport` so the MCP client gets a structured error rather than a generic 500.

## 10. Lifecycle

- The singleton `AuthplaneResource` registered at startup keeps background JWKS / metadata refresh tasks alive.
- On shutdown, dispose it (or its parent `AuthplaneClient`) to stop those tasks.
- The middleware itself holds no state.

## See also

- [`Authplane.Sdk` user guide](../../Authplane/docs/user-guide.md) — the framework-agnostic types this adapter wraps.
