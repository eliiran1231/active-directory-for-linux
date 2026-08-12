using System.Collections;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace AdForLinux.DirectoryServices.AccountManagement;

internal enum PrincipalQueryFilterKind
{
    Attribute,
    UserAccountControlBit,
    GroupTypeBit,
    Unsupported,
}

internal sealed record PrincipalQueryFilter(
    string Key,
    PrincipalQueryFilterKind Kind,
    string Attribute,
    object? Value,
    uint Bit = 0);

/// <summary>
/// Converts property-oriented query-by-example state into LDAP assertions.
/// Save-state staging remains separate because several public properties share
/// one directory bit field but must remain independent query predicates.
/// </summary>
internal static class PrincipalQueryFilterTranslator
{
    private const string BitwiseAndMatchingRule = "1.2.840.113556.1.4.803";

    public static string Translate(IEnumerable<PrincipalQueryFilter> filters) =>
        string.Concat(filters.Select(Translate));

    private static string Translate(PrincipalQueryFilter filter) => filter.Kind switch
    {
        PrincipalQueryFilterKind.Attribute => AttributeAssertions(filter.Attribute, filter.Value),
        PrincipalQueryFilterKind.UserAccountControlBit or PrincipalQueryFilterKind.GroupTypeBit =>
            BitAssertion(filter.Attribute, filter.Bit, (bool)filter.Value!),
        PrincipalQueryFilterKind.Unsupported => throw new InvalidOperationException(
            $"The property '{filter.Key}' cannot be used in a query-by-example filter."),
        _ => throw new InvalidOperationException($"Unsupported query filter kind '{filter.Kind}'."),
    };

    private static string BitAssertion(string attribute, uint bit, bool mustBeSet)
    {
        var assertion = $"({attribute}:{BitwiseAndMatchingRule}:={bit.ToString(CultureInfo.InvariantCulture)})";
        return mustBeSet ? assertion : $"(!{assertion})";
    }

    private static string AttributeAssertions(string attribute, object? value)
    {
        if (value is null)
        {
            return $"(!({attribute}=*))";
        }

        if (value is byte[] bytes)
        {
            return $"({attribute}={LdapFilter.EscapeBytes(bytes)})";
        }

        if (value is X509Certificate2 certificate)
        {
            return $"({attribute}={LdapFilter.EscapeBytes(certificate.RawData)})";
        }

        if (value is IEnumerable values and not string)
        {
            var assertions = values.Cast<object?>()
                .Select(item => AttributeAssertions(attribute, item))
                .ToArray();
            return assertions.Length == 0
                ? $"(!({attribute}=*))"
                : string.Concat(assertions);
        }

        var text = value switch
        {
            DateTime date => date.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
            bool boolean => boolean ? "TRUE" : "FALSE",
            IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString(),
        } ?? throw new InvalidOperationException(
            $"The value for '{attribute}' cannot be converted to an LDAP assertion.");

        return $"({attribute}={EscapeKeepingWildcards(text)})";
    }

    private static string EscapeKeepingWildcards(string value) => value
        .Replace("\\", "\\5c")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}
