using System.Text.Json;

namespace Authplane;

/// <summary>
/// Extension methods that collapse the
/// <c>TryGetProperty(...) + ValueKind == JsonValueKind.X + Get*()</c> idiom
/// used throughout the SDK's response parsers. Previously inlined in 15+
/// sites across OAuthResponseParser, OAuthErrorResponse, and
/// AuthplaneClient.FetchMetadata; each copy decided independently whether
/// to filter blank strings, whether to accept Numbers as longs vs Doubles,
/// and how to treat <c>null</c>-valued props. Promoting the pattern here
/// gives a single behaviour for the SDK and shortens the parsers by half.
/// </summary>
internal static class JsonHelpers
{
    /// <summary>
    /// Return the string value of <paramref name="propertyName"/> on
    /// <paramref name="element"/>, or <c>null</c> if the property is
    /// missing or not a string. Blank strings are returned as-is — callers
    /// that treat blank as missing should follow with
    /// <see cref="string.IsNullOrWhiteSpace"/>.
    /// </summary>
    public static string? GetStringOrNull(this JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!element.TryGetProperty(propertyName, out var prop))
        {
            return null;
        }

        return prop.ValueKind == JsonValueKind.String ? prop.GetString() : null;
    }

    /// <summary>
    /// Return the 64-bit integer value of <paramref name="propertyName"/>,
    /// or <c>null</c> if the property is missing or not a JSON number.
    /// </summary>
    public static long? GetInt64OrNull(this JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!element.TryGetProperty(propertyName, out var prop))
        {
            return null;
        }

        if (prop.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        return prop.TryGetInt64(out var n) ? n : null;
    }

    /// <summary>
    /// Return the boolean value of <paramref name="propertyName"/>, or
    /// <c>null</c> if the property is missing or not a JSON boolean.
    /// </summary>
    public static bool? GetBoolOrNull(this JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!element.TryGetProperty(propertyName, out var prop))
        {
            return null;
        }

        return prop.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null,
        };
    }

    /// <summary>
    /// Return the array-of-strings value of <paramref name="propertyName"/>,
    /// or an empty list if the property is missing / not an array / not all
    /// strings. Non-string elements are skipped silently. Useful for the
    /// <c>aud</c> / <c>agent_chain</c> shape that may be a string or an
    /// array — pair with <see cref="GetStringOrNull"/> to handle both.
    /// </summary>
    public static IReadOnlyList<string> GetStringArrayOrEmpty(this JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<string>();
        }

        if (!element.TryGetProperty(propertyName, out var prop))
        {
            return Array.Empty<string>();
        }

        if (prop.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        var list = new List<string>();
        foreach (var el in prop.EnumerateArray())
        {
            if (el.ValueKind == JsonValueKind.String)
            {
                var s = el.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                {
                    list.Add(s!);
                }
            }
        }
        return list;
    }
}
