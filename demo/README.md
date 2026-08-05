# Calculator Service Example

A minimal MCP server demonstrating Authplane JWT authentication wired up the
way a real deployment would be: inbound JWT + DPoP verification, RFC 7662
introspection-based revocation, and RFC 8693 token exchange that surfaces
MCP URL elicitation (`-32042`) when the upstream resource requires consent.

The server exposes three tools:

| Tool           | Required scope         | What it shows                                                      |
|----------------|------------------------|--------------------------------------------------------------------|
| `add`          | `tools/add`            | Per-tool scope enforcement on a trivial mint-backed resource.      |
| `multiply`     | `tools/multiply`       | Same as `add`, different scope.                                    |
| `consent_demo` | `tools/consent_demo`   | RFC 8693 exchange to a Broker resource that returns `consent_required`; the SDK translates it to MCP URL elicitation. |

## Prerequisites

- .NET 10 SDK
- **authserver** running locally (`http://localhost:9000`) with the demo
  provisioned via `mcp-demo-server-start.sh`, the demo provisioning script
  shipped with authserver.
  That script registers the `calculator-mcp-demo` resource, the
  `google-calendar` Broker (for URL elicitation), an OAuth client, and
  writes the client credentials to `/tmp/authserver-demo.client-id` and
  `/tmp/authserver-demo.key` — `run.sh` reads them automatically.

## Configuration

Override via environment variables (or copy `.env.example` to `.env`):

| Variable        | Default                          | Description                                  |
|-----------------|----------------------------------|----------------------------------------------|
| `ISSUER_URL`    | `http://localhost:9000`          | Authplane authserver issuer URL              |
| `RESOURCE_URL`  | `http://localhost:8080/mcp`      | This MCP server's resource (audience)        |
| `DEV_MODE`      | `true` (via `run.sh`)            | Relaxes SSRF / allows HTTP+localhost         |
| `CLIENT_ID`     | `/tmp/authserver-demo.client-id` | OAuth client used for introspection + exchange |
| `CLIENT_SECRET` | `/tmp/authserver-demo.key`       | Required; the demo refuses to start without it |

## Run

```bash
# 1. Start the authserver (in the authserver repo)
./demo/mcp-demo-server-start.sh

# 2. Start the calculator MCP server (here)
./demo/run.sh
```

The server listens on port **8080**. MCP endpoint: `http://localhost:8080/mcp`.

## How it works

```
MCP Client ──Authorization: Bearer <jwt>──► Demo server (port 8080)
   │                                            │
   │                                            ├─ AuthplaneMcpAuth middleware
   │                                            │    • Validates token signature + claims
   │                                            │    • Validates DPoP proof when cnf.jkt present
   │                                            │    • Enforces per-tool scope via body or x-authplane-required-scopes
   │                                            │    • IntrospectionRevocation rejects revoked tokens
   │                                            │
   │                                            └─ consent_demo tool ──► AuthplaneAuthClient
   ◄── -32042 URL elicitation ──── translated by ─── TokenExchangeAsync (RFC 8693)
       (consent_url to AS connect endpoint)         to google-calendar Broker
                                                    └─ AS returns consent_required + consent_url
```

The cs-sdk's `UrlElicitationSupport.WrapToolWithUrlElicitation<T>` catches
the `ConsentRequiredException` thrown by `AuthplaneAuthClient.TokenExchangeAsync`
and translates it into an `McpProtocolException` with error code
`UrlElicitationRequired` (-32042). The MCP client sees the error, reads the
`elicitations[0].url`, and prompts the user to visit it.

## Manual smoke

```bash
# 1. Get a client-credentials token (note: scopes need to be granted to the
#    client out-of-band; this token has no scopes, so tool calls return 403).
TOKEN=$(curl -s -X POST http://localhost:9000/oauth/token \
  -u "$(cat /tmp/authserver-demo.client-id):$(cat /tmp/authserver-demo.key)" \
  -d "grant_type=client_credentials&resource=http://localhost:8080/mcp" \
  | jq -r .access_token)

# 2. PRM document — public, advertises the three scopes + DPoP capability
curl -s http://localhost:8080/.well-known/oauth-protected-resource/mcp | jq .

# 3. Initialize MCP session
SESSION=$(curl -s -D - -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | awk '/Mcp-Session-Id:/ {print $2}' | tr -d '\r')

curl -s -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESSION" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 4. List tools — expect [add, multiply, consent_demo]
curl -s -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" -H "Mcp-Session-Id: $SESSION" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

For the full happy path including `consent_demo`'s URL elicitation surface,
drive the server from an MCP client (Claude Code, Inspector) so the user
flow grants the demo scopes.

## Related

- [Authplane.Mcp adapter](../src/Authplane.Mcp/) — `AuthplaneMcpAuth.CreateResourceAsync()` and `UrlElicitationSupport`
- [Authplane C# SDK](https://github.com/AuthPlane/cs-sdk) — core JWT verification, `AuthplaneAuthClient`, `TokenExchangeOptions`
- authserver demo provisioner (`mcp-demo-server-start.sh`, shipped with authserver) — the matching authorization-server side
