# Authplane.Sdk

[![NuGet](https://img.shields.io/nuget/v/Authplane.Sdk?style=flat-square&label=Authplane.Sdk)](https://www.nuget.org/packages/Authplane.Sdk)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](https://opensource.org/licenses/Apache-2.0)

Framework-agnostic OAuth 2.1 JWT validation and token operations for .NET resource servers.

## Install

```sh
dotnet add package Authplane.Sdk
```

## Quickstart

```csharp
using Authplane;

await using var client = await AuthplaneClient.CreateAsync(
    issuer: "https://auth.example.com",
    fetchSettings: FetchSettings.FromDevMode(devMode: false));

await using var resource = await client.CreateResourceAsync(
    resource: "https://api.example.com/mcp",
    scopes: new[] { "tools/query" });

var claims = await resource.VerifyAsync(incomingJwt);
claims.RequireScope("tools/query");
Console.WriteLine($"{claims.Sub} {string.Join(',', claims.Scopes)}");
```

Call `await client.DisposeAsync()` on shutdown to stop background JWKS and metadata refresh.

## Documentation

Full API reference, configuration options, error hierarchy, DPoP, token operations, introspection, token exchange, revocation, and advanced usage: **[User Guide](docs/user-guide.md)**.
