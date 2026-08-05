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

`AuthplaneMcpAuth.Options` covers the issuer, resource URI, scopes, and the `devMode` toggle. For finer-grained control of outbound HTTP (timeouts, SSRF policy), construct an `AuthplaneClient` yourself with explicit `FetchSettings` and pass the resulting `AuthplaneResource` to the DI container — the middleware uses whichever resource is registered.

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
| `JwksFetchException`, `MetadataFetchException` | 502 |
| `CircuitOpenException` | 503 |

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
