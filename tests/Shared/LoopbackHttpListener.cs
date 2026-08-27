global using Authplane.TestSupport;

using System.Net;
using System.Net.Sockets;

namespace Authplane.TestSupport;

/// <summary>
/// Binds an <see cref="HttpListener"/> on a free loopback port, retrying the
/// whole allocate-and-bind sequence.
/// </summary>
/// <remarks>
/// Asking the OS for a free port and then binding it in a second call is a
/// TOCTOU: nothing holds the port between <c>TcpListener.Stop</c> and
/// <c>HttpListener.Start</c>. CI runs both target frameworks in parallel, and
/// xUnit runs collections within a framework in parallel too, so two servers
/// can be handed the same ephemeral port and the loser throws
/// <see cref="HttpListenerException"/> — "Address already in use" on Linux,
/// "Failed to listen on prefix … because it conflicts with an existing
/// registration" on Windows — failing a run for no reason of its own.
///
/// The retry covers the whole sequence, not just the bind: once the port is
/// taken, retrying the bind on it is futile. Every fixture in both test
/// projects goes through here so that no copy of the race is left behind.
/// </remarks>
internal static class LoopbackHttpListener
{
    private const int MaxAttempts = 10;

    /// <param name="host">
    /// Host for the prefix and the returned origin. Defaults to
    /// <c>localhost</c>; pass <c>127.0.0.1</c> where a fixture asserts against
    /// the literal address rather than the name.
    /// </param>
    /// <returns>The origin the listener is bound to, and the started listener.</returns>
    internal static (string Origin, HttpListener Listener) Start(string host = "localhost")
    {
        for (var attempt = 1; ; attempt++)
        {
            var tcp = new TcpListener(IPAddress.Loopback, 0);
            tcp.Start();
            var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            tcp.Stop();

            var origin = $"http://{host}:{port}";
            var listener = new HttpListener();
            listener.Prefixes.Add($"{origin}/");

            try
            {
                listener.Start();
                return (origin, listener);
            }
            catch (HttpListenerException) when (attempt < MaxAttempts)
            {
                listener.Close();
            }
        }
    }
}
