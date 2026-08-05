using System.Globalization;
using System.Net.Http.Headers;

namespace Authplane;

/// <summary>
/// RFC 7234 cache header parsing.
/// </summary>
internal static class CacheHeaders
{
    /// <summary>
    /// Extract an absolute expiry timestamp from HTTP response cache headers.
    /// Precedence per RFC 7234 §4.2.2:
    /// 1. Cache-Control: no-store / no-cache → 0 (already expired)
    /// 2. Cache-Control: max-age=N → now + N
    /// 3. Expires header → parsed to Unix timestamp
    /// 4. null if no usable cache header is present
    /// </summary>
    internal static DateTimeOffset? ParseExpiresAt(HttpResponseHeaders headers)
    {
        if (headers.CacheControl is { } cc)
        {
            if (cc.NoStore || cc.NoCache)
            {
                return DateTimeOffset.UtcNow;
            }

            if (cc.MaxAge is { } maxAge && maxAge.TotalSeconds >= 0)
            {
                return DateTimeOffset.UtcNow + maxAge;
            }
        }

        if (headers.TryGetValues("Expires", out var expiresValues))
        {
            foreach (var val in expiresValues)
            {
                if (TryParseExpires(val, out var expires))
                {
                    return expires;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Parse an HTTP <c>Expires</c> header. RFC 7231 §7.1.1.1 requires
    /// recipients to accept three obsolete forms beyond the preferred
    /// IMF-fixdate (RFC 1123):
    ///   1. <c>r</c>          — IMF-fixdate / RFC 1123 (the preferred form).
    ///   2. RFC 850           — "Sunday, 06-Nov-94 08:49:37 GMT".
    ///   3. ANSI C asctime    — "Sun Nov  6 08:49:37 1994".
    /// Previously we only accepted form 1, so a legacy proxy emitting an
    /// asctime / RFC 850 Expires fell through to the default refresh
    /// interval.
    /// </summary>
    private static readonly string[] ExpiresFormats =
    {
        "r",                       // RFC 1123 / IMF-fixdate (preferred)
        "dddd, dd-MMM-yy HH:mm:ss 'GMT'",  // RFC 850
        "ddd MMM  d HH:mm:ss yyyy",        // asctime, day < 10 (two-space pad)
        "ddd MMM d HH:mm:ss yyyy",         // asctime, day >= 10
    };

    internal static bool TryParseExpires(string value, out DateTimeOffset expires)
    {
        return DateTimeOffset.TryParseExact(
            value,
            ExpiresFormats,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal,
            out expires);
    }
}
