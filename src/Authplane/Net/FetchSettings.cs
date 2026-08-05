namespace Authplane;

public class FetchSettings
{
    public bool SsrfProtection { get; }
    public bool AllowHttp { get; }
    public bool AllowLocalhost { get; }
    public bool AllowPrivateNetworks { get; }
    public double TimeoutSeconds { get; }

    public FetchSettings(
        bool ssrfProtection,
        bool allowHttp,
        bool allowLocalhost,
        bool allowPrivateNetworks,
        double timeoutSeconds)
    {
        SsrfProtection = ssrfProtection;
        AllowHttp = allowHttp;
        AllowLocalhost = allowLocalhost;
        AllowPrivateNetworks = allowPrivateNetworks;
        TimeoutSeconds = timeoutSeconds;
    }

    public static FetchSettings FromDevMode(bool devMode)
    {
        if (devMode)
        {
            return new FetchSettings(
                ssrfProtection: false,
                allowHttp: true,
                allowLocalhost: true,
                allowPrivateNetworks: true,
                timeoutSeconds: 10.0);
        }

        return new FetchSettings(
            ssrfProtection: true,
            allowHttp: false,
            allowLocalhost: false,
            allowPrivateNetworks: false,
            timeoutSeconds: 10.0);
    }
}

