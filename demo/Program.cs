// Calculator Service demo — Authplane JWT auth with DPoP inbound + per-tool scopes
// + RFC 7662 introspection-based revocation + RFC 8693 token exchange that
// surfaces URL elicitation when the upstream resource requires user consent.
//
// Expects an authserver provisioned by its bundled demo script with:
//   • calculator-mcp-demo (Mint resource) — scopes tools/add, tools/multiply, tools/consent_demo
//   • google-calendar (Broker resource)   — fake upstream, triggers consent_required
//
// Run from repo root: ./demo/run.sh   or   dotnet run --project demo

using Authplane;
using Authplane.Mcp;
using ModelContextProtocol.Server;

var builder = WebApplication.CreateBuilder(args);

// ────────────────────────────────────────────────────────────────────────────
// Configuration — env first, then files written by authserver/demo/mcp-demo-server-start.sh
// ────────────────────────────────────────────────────────────────────────────
var issuer = Environment.GetEnvironmentVariable("ISSUER_URL") ?? "http://localhost:9000";
var resource = Environment.GetEnvironmentVariable("RESOURCE_URL") ?? "http://localhost:8080/mcp";
var devMode = string.Equals(Environment.GetEnvironmentVariable("DEV_MODE"), "true", StringComparison.OrdinalIgnoreCase);

var clientId = Environment.GetEnvironmentVariable("CLIENT_ID")
    ?? ReadIfExists("/tmp/authserver-demo.client-id")
    ?? resource;
var clientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET")
    ?? ReadIfExists("/tmp/authserver-demo.key");

if (string.IsNullOrWhiteSpace(clientSecret))
{
    Console.Error.WriteLine(
        "CLIENT_SECRET is required. Start the demo authserver first:\n" +
        "  ./demo/mcp-demo-server-start.sh   (in the authserver repo)\n" +
        "or set CLIENT_SECRET in demo/.env.");
    return 1;
}

// ────────────────────────────────────────────────────────────────────────────
// Outbound DPoP — proof-of-possession on introspection + token-exchange calls
// ────────────────────────────────────────────────────────────────────────────
var dpopProvider = new DPoPProvider(DPoPKeyMaterial.CreateES256());

var fetchSettings = FetchSettings.FromDevMode(devMode);

// ────────────────────────────────────────────────────────────────────────────
// Auth client — used by IntrospectionRevocation (revocation) and the
// consent_demo tool (token exchange). Wraps Basic client auth + outbound DPoP.
// ────────────────────────────────────────────────────────────────────────────
var authClient = new AuthplaneAuthClient(
    issuerUrl: issuer,
    clientId: clientId,
    clientSecret: clientSecret,
    dpopProvider: dpopProvider,
    fetchSettings: fetchSettings);

// ────────────────────────────────────────────────────────────────────────────
// Resource verifier — RFC 9449 inbound DPoP + RFC 7662 revocation via the
// auth client. Resource is registered as singleton so the middleware and
// the consent_demo tool both share it.
// ────────────────────────────────────────────────────────────────────────────
var inboundDpop = new InboundDPoPOptions(required: false);
var revocationChecker = new IntrospectionRevocation(authClient);
var verifierResource = await AuthplaneResource.CreateAsync(
    issuer: issuer,
    resource: resource,
    scopes: new[] { "tools/add", "tools/multiply", "tools/consent_demo" },
    fetchSettings: fetchSettings,
    revocationChecker: revocationChecker,
    inboundDpop: inboundDpop);

var mcpAuthOptions = new AuthplaneMcpAuth.Options(
    issuer: issuer,
    resource: resource,
    scopes: new[] { "tools/add", "tools/multiply", "tools/consent_demo" },
    devMode: devMode);

builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton(verifierResource);
builder.Services.AddSingleton(authClient);
builder.Services.AddSingleton<IDPoPReplayStore, InMemoryDPoPReplayStore>();

builder.Services
    .AddMcpServer()
    .WithHttpTransport()
    .WithToolsFromAssembly();

var app = builder.Build();

app.Lifetime.ApplicationStopping.Register(() =>
{
    verifierResource.DisposeAsync().AsTask().GetAwaiter().GetResult();
    authClient.DisposeAsync().AsTask().GetAwaiter().GetResult();
});

app.UseAuthplaneMcpAuth(mcpAuthOptions);
app.MapMcp(pattern: "/mcp");

await app.RunAsync();
return 0;

static string? ReadIfExists(string path)
{
    if (!File.Exists(path))
    {
        return null;
    }
    var content = File.ReadAllText(path).Trim();
    return string.IsNullOrEmpty(content) ? null : content;
}

// ────────────────────────────────────────────────────────────────────────────
// Tools — discovered by WithToolsFromAssembly. Tool handlers receive
// IHttpContextAccessor (registered above) so they can read the inbound
// access token for outbound token exchange.
// ────────────────────────────────────────────────────────────────────────────
[McpServerToolType]
public static class CalculatorTools
{
    [McpServerTool(Name = "add")]
    public static double Add(double a, double b, IHttpContextAccessor _) => a + b;

    [McpServerTool(Name = "multiply")]
    public static double Multiply(double a, double b, IHttpContextAccessor _) => a * b;

    private const string GoogleCalendarResourceUri = "https://www.googleapis.com/calendar/v3";
    private const string GoogleCalendarScope = "https://www.googleapis.com/auth/calendar";

    /// <summary>
    /// Exchange the inbound user token for a Google Calendar token via RFC 8693.
    /// The demo authserver registers <c>google-calendar</c> as a Broker resource
    /// with fake upstream credentials; until the user has connected Google Calendar
    /// (which they cannot, in the demo) the AS responds to this exchange with
    /// <c>consent_required</c> and a <c>consent_url</c>. <c>UrlElicitationSupport</c>
    /// translates that into an MCP <c>-32042</c> URL-elicitation error so the
    /// client can prompt the user to visit the connect URL.
    /// </summary>
    [McpServerTool(Name = "consent_demo")]
    public static Task<object> ConsentDemo(IHttpContextAccessor httpContextAccessor, AuthplaneAuthClient client)
    {
        return UrlElicitationSupport.WrapToolWithUrlElicitation<object>(async () =>
        {
            var ctx = httpContextAccessor.HttpContext
                ?? throw new InvalidOperationException("No HttpContext available.");
            var subjectToken = ExtractBearerOrDPoPToken(ctx)
                ?? throw new TokenMissingException("Access token missing from request.");

            var downstream = await client.TokenExchangeAsync(
                new TokenExchangeOptions(
                    subjectToken: subjectToken,
                    resources: new[] { GoogleCalendarResourceUri },
                    audiences: null,
                    scope: GoogleCalendarScope));

            return new
            {
                token_type = downstream.TokenType,
                scope = downstream.Scope ?? string.Empty,
            };
        });
    }

    private static string? ExtractBearerOrDPoPToken(HttpContext ctx)
    {
        var header = ctx.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return header["Bearer ".Length..].Trim();
        }
        if (header.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
        {
            return header["DPoP ".Length..].Trim();
        }
        return null;
    }
}
