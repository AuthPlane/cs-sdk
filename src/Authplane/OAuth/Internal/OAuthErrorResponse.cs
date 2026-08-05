using System.Text.Json;

namespace Authplane;

/// <summary>
/// Parsed view of an OAuth 2.x error JSON body. Fields are tolerant of missing values —
/// callers should default-handle every property.
/// </summary>
internal sealed record OAuthErrorResponse(
    string? Error,
    string? ErrorDescription,
    string? ErrorUri,
    string? ServiceId,
    string? Cause,
    string? ConsentUrl)
{
    public static OAuthErrorResponse Empty { get; } = new(null, null, null, null, null, null);

    /// <summary>
    /// Best-effort parse of an error response body. Returns <see cref="Empty"/> on any
    /// parse failure or non-object root.
    /// </summary>
    public static OAuthErrorResponse TryParse(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return Empty;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return Empty;
            }

            var root = doc.RootElement;
            return new OAuthErrorResponse(
                Error: root.GetStringOrNull("error"),
                ErrorDescription: root.GetStringOrNull("error_description"),
                ErrorUri: root.GetStringOrNull("error_uri"),
                ServiceId: root.GetStringOrNull("service_id")
                    ?? root.GetStringOrNull("service")
                    ?? root.GetStringOrNull(OAuthConstants.Params.Resource),
                Cause: root.GetStringOrNull("cause"),
                ConsentUrl: root.GetStringOrNull("consent_url"));
        }
        catch
        {
            return Empty;
        }
    }
}
