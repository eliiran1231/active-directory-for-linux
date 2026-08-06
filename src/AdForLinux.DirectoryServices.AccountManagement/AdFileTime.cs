namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Converts AD time values. AD stores times as a FILETIME: the number of
/// 100-nanosecond ticks since 1 January 1601 (UTC), written as a string.
///
/// Two values mean "no time set": 0 and long.MaxValue. Microsoft turns both
/// into null, and so do we.
/// </summary>
internal static class AdFileTime
{
    /// <summary>Reads a FILETIME attribute, or null when it means "never".</summary>
    public static DateTime? ToDateTime(string? raw)
    {
        if (raw is null || !long.TryParse(raw, out var ticks))
        {
            return null;
        }

        if (ticks == 0 || ticks == long.MaxValue)
        {
            return null;
        }

        // FromFileTimeUtc gives a DateTime with Kind = Utc, matching Microsoft.
        return DateTime.FromFileTimeUtc(ticks);
    }

    /// <summary>Writes a DateTime as a FILETIME string, or "never" for null.</summary>
    public static string FromDateTime(DateTime? value)
    {
        if (value is null)
        {
            // What AD tools write for "never expires".
            return long.MaxValue.ToString();
        }

        return value.Value.ToUniversalTime().ToFileTimeUtc().ToString();
    }

    /// <summary>
    /// Reads a duration attribute like <c>lockoutDuration</c>. AD stores these
    /// as a negative number of 100-ns ticks. Returns null when it means
    /// "forever" (0 or long.MinValue).
    /// </summary>
    public static TimeSpan? ToDuration(string? raw)
    {
        if (raw is null || !long.TryParse(raw, out var ticks) || ticks == 0 || ticks == long.MinValue)
        {
            return null;
        }

        // Stored negative; the length is its absolute value.
        return TimeSpan.FromTicks(Math.Abs(ticks));
    }
}
