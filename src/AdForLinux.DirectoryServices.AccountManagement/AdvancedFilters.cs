using System.Globalization;
using System.ComponentModel;

namespace AdForLinux.DirectoryServices.AccountManagement;

/// <summary>
/// Sets comparisons for read-only account properties on a query-by-example
/// principal used by <see cref="PrincipalSearcher"/>.
/// </summary>
public class AdvancedFilters
{
    private readonly Principal _principal;

    protected internal AdvancedFilters(Principal p)
    {
        ArgumentNullException.ThrowIfNull(p);
        _principal = p;
    }

    public void LastBadPasswordAttempt(DateTime lastAttempt, MatchType match) =>
        AdvancedDateFilterSet("badPasswordTime", lastAttempt, match);

    public void AccountExpirationDate(DateTime expirationTime, MatchType match) =>
        AdvancedDateFilterSet("accountExpires", expirationTime, match);

    public void AccountLockoutTime(DateTime lockoutTime, MatchType match) =>
        AdvancedDateFilterSet("lockoutTime", lockoutTime, match);

    public void BadLogonCount(int badLogonCount, MatchType match) =>
        AdvancedFilterSet("badPwdCount", badLogonCount, typeof(int), match);

    public void LastLogonTime(DateTime logonTime, MatchType match)
    {
        ValidateMatchType(match);
        _principal.SetAdvancedFilter(
            "lastLogon",
            $"(|{ToLdapDateCondition("lastLogon", logonTime, match)}" +
            $"{ToLdapDateCondition("lastLogonTimestamp", logonTime, match, requirePresenceForNotEquals: true)})");
    }

    public void LastPasswordSetTime(DateTime passwordSetTime, MatchType match) =>
        AdvancedDateFilterSet("pwdLastSet", passwordSetTime, match);

    private void AdvancedDateFilterSet(
        string attribute,
        DateTime value,
        MatchType match,
        bool excludeDefaultValue = false)
    {
        ValidateMatchType(match);
        _principal.SetAdvancedFilter(attribute, ToLdapDateCondition(attribute, value, match, excludeDefaultValue));
    }

    protected void AdvancedFilterSet(string attribute, object value, Type objectType, MatchType mt)
    {
        ArgumentException.ThrowIfNullOrEmpty(attribute);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(objectType);
        ValidateMatchType(mt);

        var text = objectType == typeof(DateTime) && value is DateTime date
            ? date.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture)
            : Convert.ToString(value, CultureInfo.InvariantCulture)
                ?? throw new ArgumentException("The filter value cannot be converted to text.", nameof(value));

        _principal.SetAdvancedFilter(attribute, text, mt);
    }

    private static void ValidateMatchType(MatchType match)
    {
        if (!Enum.IsDefined(match))
        {
            throw new InvalidEnumArgumentException(nameof(match), (int)match, typeof(MatchType));
        }
    }

    internal static string ToLdapDateCondition(
        string attribute,
        DateTime value,
        MatchType match,
        bool excludeDefaultValue = false,
        bool requirePresenceForNotEquals = false)
    {
        var fileTime = value.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);
        var condition = ToLdapCondition(attribute, fileTime, match, requirePresenceForNotEquals);
        return excludeDefaultValue && match is not MatchType.Equals and not MatchType.NotEquals
            ? $"(&{condition}(!({attribute}=0)))"
            : condition;
    }

    internal static string ToLdapCondition(
        string attribute,
        string value,
        MatchType match,
        bool requirePresenceForNotEquals = false)
    {
        var escaped = LdapFilter.EscapeValue(value);
        return match switch
        {
            MatchType.Equals => $"({attribute}={escaped})",
            MatchType.NotEquals when requirePresenceForNotEquals =>
                $"(&(!({attribute}={escaped}))({attribute}=*))",
            MatchType.NotEquals => $"(!({attribute}={escaped}))",
            MatchType.GreaterThan =>
                $"(&({attribute}>={escaped})(!({attribute}={escaped}))({attribute}=*))",
            MatchType.GreaterThanOrEquals => $"({attribute}>={escaped})",
            MatchType.LessThan =>
                $"(&({attribute}<={escaped})(!({attribute}={escaped}))({attribute}=*))",
            MatchType.LessThanOrEquals => $"({attribute}<={escaped})",
            _ => throw new InvalidEnumArgumentException(nameof(match), (int)match, typeof(MatchType)),
        };
    }
}
