using System.DirectoryServices.Protocols;
using System.Globalization;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Turns a raw <see cref="SearchResultEntry"/> into name/value pairs using the
/// CLR representation implied by each attribute's Active Directory syntax.
/// </summary>
internal static class SearchEntryReader
{
    public static IEnumerable<(string Name, object Value)> Read(
        SearchResultEntry entry,
        LdapConnection connection)
    {
        var names = entry.Attributes.AttributeNames.Cast<string>().ToArray();
        var kinds = LdapAttributeSchema.Resolve(connection, names);

        foreach (var name in names)
        {
            var attribute = entry.Attributes[name];
            var canonicalName = name.Split(';', 2)[0];
            var kind = kinds[canonicalName];
            var wanted = kind == LdapValueKind.Binary ? typeof(byte[]) : typeof(string);

            foreach (var value in attribute.GetValues(wanted))
            {
                yield return (name, ConvertValue(value, kind));
            }
        }
    }

    internal static object ConvertValue(object value, LdapValueKind kind) => kind switch
    {
        LdapValueKind.Boolean => bool.Parse((string)value),
        LdapValueKind.Int32 => int.Parse((string)value, NumberStyles.Integer, CultureInfo.InvariantCulture),
        LdapValueKind.Int64 => long.Parse((string)value, NumberStyles.Integer, CultureInfo.InvariantCulture),
        LdapValueKind.DateTime => ParseDirectoryTime((string)value),
        _ => value,
    };

    private static DateTime ParseDirectoryTime(string value)
    {
        var normalized = value;
        if (value.Length >= 5 && (value[^5] == '+' || value[^5] == '-'))
        {
            normalized = string.Concat(value.AsSpan(0, value.Length - 2), ":", value.AsSpan(value.Length - 2));
        }

        string[] formats =
        {
            "yyyyMMddHHmmss.FFFFFFF'Z'", "yyyyMMddHHmmss'Z'",
            "yyyyMMddHHmmss.FFFFFFFzzz", "yyyyMMddHHmmsszzz",
            "yyMMddHHmmss'Z'", "yyMMddHHmmsszzz",
        };
        if (!DateTimeOffset.TryParseExact(
                normalized,
                formats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new FormatException($"LDAP returned invalid directory time '{value}'.");
        }

        return DateTime.SpecifyKind(parsed.UtcDateTime, DateTimeKind.Unspecified);
    }
}
