using ModelContextProtocol;

namespace Authplane.Mcp;

public static class UrlElicitationSupport
{
    private const string DefaultConsentMessage = "Consent is required to proceed";

    public static Exception ToUrlElicitationRequiredError(Exception error)
    {
        var consent = AsConsentRequired(error);
        if (consent is null || string.IsNullOrWhiteSpace(consent.ConsentUrl))
        {
            return error;
        }

        var message = string.IsNullOrWhiteSpace(consent.Message) ? DefaultConsentMessage : consent.Message;
        var serviceId = string.IsNullOrWhiteSpace(consent.ServiceId) ? "unknown_service" : consent.ServiceId;
        var causeDetail = string.IsNullOrWhiteSpace(consent.CauseDetail) ? message : consent.CauseDetail;

        var protocolError = new McpProtocolException(message, McpErrorCode.UrlElicitationRequired);
        protocolError.Data["elicitations"] = new[]
        {
            new Dictionary<string, object?>
            {
                ["mode"] = "url",
                ["url"] = consent.ConsentUrl,
                ["elicitationId"] = Guid.NewGuid().ToString(),
                ["message"] = $"{message} ({serviceId}: {causeDetail})"
            }
        };
        return protocolError;
    }

    public static async Task<T> WrapToolWithUrlElicitation<T>(Func<Task<T>> handler)
    {
        try
        {
            return await handler().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw ToUrlElicitationRequiredError(ex);
        }
    }

    private static ConsentRequiredLike? AsConsentRequired(Exception error)
    {
        if (error is ConsentRequiredException cre)
        {
            return new ConsentRequiredLike(
                Message: cre.Message,
                ServiceId: cre.ServiceId,
                CauseDetail: cre.CauseDetail,
                ConsentUrl: cre.ConsentUrl);
        }

        if (error is AuthplaneTokenRequestException tre &&
            (string.Equals(tre.OAuthError, "consent_required", StringComparison.Ordinal) ||
             string.Equals(tre.OAuthError, "interaction_required", StringComparison.Ordinal)))
        {
            return new ConsentRequiredLike(
                Message: tre.Message,
                ServiceId: "unknown_service",
                CauseDetail: tre.Message,
                ConsentUrl: null);
        }

        if (error is AggregateException ae && ae.InnerException is not null)
        {
            return AsConsentRequired(ae.InnerException);
        }

        return null;
    }

    private sealed record ConsentRequiredLike(
        string Message,
        string ServiceId,
        string CauseDetail,
        string? ConsentUrl);
}
