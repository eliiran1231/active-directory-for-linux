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
    private readonly Dictionary<string, Func<string>> _criteria = new(StringComparer.OrdinalIgnoreCase);

    // Built-in criteria belong to this instance, including detached and ownerless
    // filters. Defer conversion until query construction so values can be replaced.
    internal IEnumerable<string> FilterConditions => _criteria.Values.Select(condition => condition());

    private void SetAdvancedFilter(string key, Func<string> condition) => _criteria[key] = condition;

    protected internal AdvancedFilters(Principal p)
    {
        _principal = p;
    }

    public void LastBadPasswordAttempt(DateTime lastAttempt, MatchType match) =>
        AdvancedDateFilterSet("badPasswordTime", lastAttempt, match, excludeDefaultValue: true);

    public void AccountExpirationDate(DateTime expirationTime, MatchType match) =>
        AdvancedDateFilterSet("accountExpires", expirationTime, match);

    public void AccountLockoutTime(DateTime lockoutTime, MatchType match) =>
        AdvancedDateFilterSet("lockoutTime", lockoutTime, match);

    public void BadLogonCount(int badLogonCount, MatchType match) =>
        SetAdvancedFilter("badPwdCount", () =>
            ToLdapCondition("badPwdCount", badLogonCount.ToString(CultureInfo.InvariantCulture), match));

    public void LastLogonTime(DateTime logonTime, MatchType match)
    {
        SetAdvancedFilter(
            "lastLogon",
            () => $"(|{ToLdapDateCondition("lastLogon", logonTime, match, excludeDefaultValue: true)}" +
            $"{ToLdapDateCondition("lastLogonTimestamp", logonTime, match, excludeDefaultValue: true, requirePresenceForNotEquals: true)})");
    }

    public void LastPasswordSetTime(DateTime passwordSetTime, MatchType match) =>
        AdvancedDateFilterSet("pwdLastSet", passwordSetTime, match, excludeDefaultValue: true);

    private void AdvancedDateFilterSet(
        string attribute,
        DateTime value,
        MatchType match,
        bool excludeDefaultValue = false)
    {
        SetAdvancedFilter(attribute, () => ToLdapDateCondition(attribute, value, match, excludeDefaultValue));
    }

    protected void AdvancedFilterSet(string attribute, object value, Type objectType, MatchType mt)
    {
        _principal.SetAdvancedExtensionFilter(attribute, value, () => ConvertExtension(attribute, value, mt));
    }

    private static string ConvertExtension(string attribute, object value, MatchType match)
    {
        // Only object[] supplies multiple criteria. Other collections are a
        // single value, and elements are converted without recursive expansion.
        var values = value as object[] ?? new[] { value };
        return string.Concat(values.Select(item => ConvertExtensionValue(attribute, item, match)));
    }

    private static string ConvertExtensionValue(string attribute, object value, MatchType match)
    {
        var text = value switch
        {
            DateTime date => date.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
            bool boolean => boolean ? "TRUE" : "FALSE",
            _ => value.ToString()!,
        };
        return ToLdapCondition(attribute, text, match, papiQuoting: true);
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
            ? $"(&{condition}(!{attribute}=0))"
            : condition;
    }

    internal static string ToLdapCondition(
        string attribute,
        string value,
        MatchType match,
        bool requirePresenceForNotEquals = false,
        bool papiQuoting = false)
    {
        var escaped = papiQuoting
            ? PrincipalQueryFilterTranslator.EscapeKeepingWildcards(value)
            : LdapFilter.EscapeValue(value);
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
