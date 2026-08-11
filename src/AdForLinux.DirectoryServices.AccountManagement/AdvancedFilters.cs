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
        AdvancedFilterSet("badPasswordTime", lastAttempt, typeof(DateTime), match);

    public void AccountExpirationDate(DateTime expirationTime, MatchType match) =>
        AdvancedFilterSet("accountExpires", expirationTime, typeof(DateTime), match);

    public void AccountLockoutTime(DateTime lockoutTime, MatchType match) =>
        AdvancedFilterSet("lockoutTime", lockoutTime, typeof(DateTime), match);

    public void BadLogonCount(int badLogonCount, MatchType match) =>
        AdvancedFilterSet("badPwdCount", badLogonCount, typeof(int), match);

    public void LastLogonTime(DateTime logonTime, MatchType match) =>
        AdvancedFilterSet("lastLogonTimestamp", logonTime, typeof(DateTime), match);

    public void LastPasswordSetTime(DateTime passwordSetTime, MatchType match) =>
        AdvancedFilterSet("pwdLastSet", passwordSetTime, typeof(DateTime), match);

    protected void AdvancedFilterSet(string attribute, object value, Type objectType, MatchType mt)
    {
        ArgumentException.ThrowIfNullOrEmpty(attribute);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(objectType);
        if (!Enum.IsDefined(mt))
        {
            throw new InvalidEnumArgumentException(nameof(mt), (int)mt, typeof(MatchType));
        }

        var text = objectType == typeof(DateTime) && value is DateTime date
            ? date.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture)
            : Convert.ToString(value, CultureInfo.InvariantCulture)
                ?? throw new ArgumentException("The filter value cannot be converted to text.", nameof(value));

        _principal.SetAdvancedFilter(attribute, text, mt);
    }

    internal static string ToLdapCondition(string attribute, string value, MatchType match)
    {
        var escaped = LdapFilter.EscapeValue(value);
        return match switch
        {
            MatchType.Equals => $"({attribute}={escaped})",
            MatchType.NotEquals => $"(!({attribute}={escaped}))",
            MatchType.GreaterThan => $"(&({attribute}>={escaped})(!({attribute}={escaped})))",
            MatchType.GreaterThanOrEquals => $"({attribute}>={escaped})",
            MatchType.LessThan => $"(&({attribute}<={escaped})(!({attribute}={escaped})))",
            MatchType.LessThanOrEquals => $"({attribute}<={escaped})",
            _ => throw new InvalidEnumArgumentException(nameof(match), (int)match, typeof(MatchType)),
        };
    }
}
