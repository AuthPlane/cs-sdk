namespace Authplane;

/// <summary>
/// Classifies OAuth / HTTP failures for a future AS circuit breaker.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AuthplaneAuthClient"/> does not yet implement a circuit breaker; call
/// <see cref="ShouldRecordFailure"/> when recording failures so business OAuth errors
/// (e.g. <c>consent_required</c>, <c>invalid_grant</c>) do not open the circuit.
/// </para>
/// </remarks>
public static class CircuitPolicy
{
    private static readonly HashSet<string> OAuthErrorsNoCircuit = new(StringComparer.Ordinal)
    {
        OAuthConstants.ErrorCodes.ConsentRequired,
        OAuthConstants.ErrorCodes.InteractionRequired,
        OAuthConstants.ErrorCodes.InvalidGrant,
        OAuthConstants.ErrorCodes.InvalidScope,
        OAuthConstants.ErrorCodes.InvalidDPoPProof,
        OAuthConstants.ErrorCodes.InvalidRequest,
        OAuthConstants.ErrorCodes.UnsupportedGrantType,
    };

    /// <summary>
    /// Returns whether this exception should increment an AS outage circuit breaker.
    /// </summary>
    public static bool ShouldRecordFailure(Exception ex)
    {
        switch (ex)
        {
            case CircuitOpenException:
                return false;
            case ServerError:
                return true;
            case AuthplaneTokenRequestException tre:
                return ShouldRecordTokenRequestFailure(tre);
            default:
                return true;
        }
    }

    private static bool ShouldRecordTokenRequestFailure(AuthplaneTokenRequestException tre)
    {
        var code = tre.OAuthError;
        var status = tre.HttpStatus;

        if (status is >= 500)
        {
            return true;
        }

        if (string.Equals(code, OAuthConstants.ErrorCodes.InvalidClient, StringComparison.Ordinal) ||
            string.Equals(code, OAuthConstants.ErrorCodes.UnauthorizedClient, StringComparison.Ordinal))
        {
            return true;
        }

        if (string.Equals(code, OAuthConstants.ErrorCodes.ServerError, StringComparison.Ordinal))
        {
            return true;
        }

        if (!string.IsNullOrEmpty(code) && OAuthErrorsNoCircuit.Contains(code))
        {
            return false;
        }

        // Introspection/token HTTP errors without a parsed OAuth code: 401/403 usually mean client auth.
        if (status is 401 or 403)
        {
            if (string.IsNullOrEmpty(code))
            {
                return true;
            }

            if (OAuthErrorsNoCircuit.Contains(code))
            {
                return false;
            }

            return true;
        }

        if (status is >= 400)
        {
            return false;
        }

        return true;
    }
}
