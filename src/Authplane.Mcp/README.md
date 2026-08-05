# Authplane.Mcp

[![NuGet](https://img.shields.io/nuget/v/Authplane.Mcp?style=flat-square&label=Authplane.Mcp)](https://www.nuget.org/packages/Authplane.Mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

Authplane JWT validation for servers built on the [official MCP .NET SDK](https://github.com/modelcontextprotocol/csharp-sdk) ASP.NET Core transport.

## Install

```sh
dotnet add package Authplane.Mcp
```

## Quickstart

```csharp
using Authplane;
using Authplane.Mcp;
using Microsoft.AspNetCore.Builder;

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

Dispose the singleton `AuthplaneResource` (or its parent `AuthplaneClient`) on shutdown to stop background JWKS / metadata refresh.

## Documentation

PRM behaviour, dev mode, revocation checking, manual setup, the full `AuthplaneMcpAuth` / `UseAuthplaneMcpAuth` / `UrlElicitationSupport` API, and error mapping: **[User Guide](docs/user-guide.md)**.
