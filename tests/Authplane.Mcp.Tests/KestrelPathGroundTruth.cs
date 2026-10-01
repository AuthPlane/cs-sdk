using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Authplane.Mcp.Tests;

/// <summary>
/// Observed ground truth for how Kestrel decodes a request target into
/// <c>HttpContext.Request.Path</c>: a real Kestrel server on a loopback port,
/// driven by the literal bytes of a request line written to a socket, echoing
/// back the <c>Request.Path</c> it produced.
/// </summary>
/// <remarks>
/// <para>
/// The middleware's decoded-path fallback compares <c>Request.Path</c> against
/// an expected path put through the SDK's own model of that decoder. Shaping
/// the request with a second, hand-written copy of the same model makes the
/// assertion <c>PathsMatch(f(p), f(p))</c> — true for any <c>f</c>, so a model
/// that is wrong about Kestrel still passes green. Measuring the decoded path
/// instead of modelling it is what lets the test fail when the model is wrong.
/// </para>
/// <para>
/// The request goes out over a raw socket rather than <c>HttpClient</c>
/// because the input under measurement is the request target exactly as a
/// client puts it on the wire, and <see cref="Uri"/> normalises some escapes
/// on the way out — which would silently measure the decoder against an input
/// other than the one asked for. <c>Connection: close</c> plus an explicit
/// <c>Content-Length</c> on the echo keeps the read a plain read-to-EOF with
/// no chunked framing to unpick.
/// </para>
/// </remarks>
public sealed class KestrelPathGroundTruth : IDisposable
{
    private static readonly TimeSpan ExchangeTimeout = TimeSpan.FromSeconds(30);

    private readonly IHost _host;
    private readonly int _port;

    public KestrelPathGroundTruth()
    {
        // Port 0 lets Kestrel bind a free port itself, so there is no
        // allocate-then-bind TOCTOU to retry around (the reason
        // LoopbackHttpListener exists for HttpListener, which cannot).
        _host = new HostBuilder()
            .ConfigureLogging(logging => logging.ClearProviders())
            .ConfigureWebHost(webHost => webHost
                .UseKestrel(options => options.Listen(IPAddress.Loopback, 0))
                .Configure(app => app.Run(async context =>
                {
                    var payload = Encoding.UTF8.GetBytes(context.Request.Path.Value ?? string.Empty);
                    context.Response.ContentType = "text/plain; charset=utf-8";
                    context.Response.ContentLength = payload.Length;
                    await context.Response.Body.WriteAsync(payload).ConfigureAwait(false);
                })))
            .Build();

        _host.Start();

        var address = _host.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First();
        _port = new Uri(address, UriKind.Absolute).Port;
    }

    /// <summary>
    /// Sends <paramref name="requestTarget"/> as the request target of a real
    /// HTTP/1.1 request line and returns the <c>Request.Path</c> Kestrel
    /// produced from it.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Kestrel did not answer 200 — it rejected the target outright, which is
    /// itself ground truth worth surfacing rather than swallowing.
    /// </exception>
    public async Task<string> DecodePathAsync(string requestTarget)
    {
        using var timeout = new CancellationTokenSource(ExchangeTimeout);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, _port, timeout.Token).ConfigureAwait(false);

        // Refuse what cannot be transmitted verbatim. `Encoding.ASCII` maps any
        // non-ASCII char to '?' without error, so `DecodePathAsync("/café")` would
        // put `/caf?` on the wire and hand back a query-stripped `Request.Path`
        // as if it were the answer — the exact failure this class's remark
        // gives as its reason for bypassing `HttpClient`/`Uri`: silently
        // measuring the decoder against an input other than the one asked for.
        if (!Ascii.IsValid(requestTarget))
        {
            throw new ArgumentException(
                $"Request target '{requestTarget}' is not ASCII, so it cannot be put on the "
                    + "wire byte-for-byte. Percent-encode the non-ASCII octets first — this "
                    + "fixture measures what it transmits, and transmitting a substitute would "
                    + "measure the wrong input.",
                nameof(requestTarget));
        }

        var stream = client.GetStream();
        var requestLine = Encoding.ASCII.GetBytes(
            $"GET {requestTarget} HTTP/1.1\r\nHost: localhost:{_port}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(requestLine, timeout.Token).ConfigureAwait(false);
        await stream.FlushAsync(timeout.Token).ConfigureAwait(false);

        using var received = new MemoryStream();
        await stream.CopyToAsync(received, timeout.Token).ConfigureAwait(false);
        var response = Encoding.UTF8.GetString(received.ToArray());

        var headerEnd = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerEnd < 0)
        {
            throw new InvalidOperationException(
                $"Kestrel returned no complete response for request target '{requestTarget}'.");
        }

        var statusLine = response[..response.IndexOf("\r\n", StringComparison.Ordinal)];
        if (!statusLine.StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Kestrel did not serve request target '{requestTarget}': {statusLine}");
        }

        return response[(headerEnd + 4)..];
    }

    public void Dispose()
    {
        _host.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
        _host.Dispose();
    }
}
