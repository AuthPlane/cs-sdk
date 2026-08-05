namespace Authplane;

/// <summary>
/// <see cref="FetchSettings"/> with defaults tuned for the JWKS endpoint: shorter timeout,
/// HTTPS only (even in dev mode you usually want HTTPS for JWKS), small response cap.
/// </summary>
public sealed class JwksFetchSettings : FetchSettings
{
    public JwksFetchSettings(
        bool ssrfProtection = true,
        bool allowHttp = false,
        bool allowLocalhost = false,
        bool allowPrivateNetworks = false,
        double timeoutSeconds = 5.0)
        : base(ssrfProtection, allowHttp, allowLocalhost, allowPrivateNetworks, timeoutSeconds)
    {
    }

    public static JwksFetchSettings CreateForDevMode(bool devMode) =>
        devMode
            ? new JwksFetchSettings(
                ssrfProtection: false,
                allowHttp: true,
                allowLocalhost: true,
                allowPrivateNetworks: true,
                timeoutSeconds: 5.0)
            : new JwksFetchSettings();
}
