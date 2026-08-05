namespace Authplane;

/// <summary>
/// <see cref="FetchSettings"/> with defaults tuned for the AS metadata discovery
/// endpoint: longer timeout (the document is rarely refreshed), small response cap.
/// </summary>
public sealed class MetadataFetchSettings : FetchSettings
{
    public MetadataFetchSettings(
        bool ssrfProtection = true,
        bool allowHttp = false,
        bool allowLocalhost = false,
        bool allowPrivateNetworks = false,
        double timeoutSeconds = 10.0)
        : base(ssrfProtection, allowHttp, allowLocalhost, allowPrivateNetworks, timeoutSeconds)
    {
    }

    public static MetadataFetchSettings CreateForDevMode(bool devMode) =>
        devMode
            ? new MetadataFetchSettings(
                ssrfProtection: false,
                allowHttp: true,
                allowLocalhost: true,
                allowPrivateNetworks: true,
                timeoutSeconds: 10.0)
            : new MetadataFetchSettings();
}
