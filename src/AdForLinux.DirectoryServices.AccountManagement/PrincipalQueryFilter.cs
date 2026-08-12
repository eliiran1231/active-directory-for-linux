using System.Collections;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace AdForLinux.DirectoryServices.AccountManagement;

internal enum PrincipalQueryFilterKind
{
    String,
    StringCollection,
    Binary,
    CertificateCollection,
    AccountExpiration,
    Workstations,
    Extension,
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
        PrincipalQueryFilterKind.String => StringAssertion(filter.Attribute, filter.Value),
        PrincipalQueryFilterKind.StringCollection => CollectionAssertions(
            filter.Attribute, filter.Value, StringAssertion),
        PrincipalQueryFilterKind.Binary => BinaryAssertion(filter.Attribute, filter.Value),
        PrincipalQueryFilterKind.CertificateCollection => CollectionAssertions(
            filter.Attribute, filter.Value, CertificateAssertion),
        PrincipalQueryFilterKind.AccountExpiration => AccountExpirationAssertion(filter.Value),
        PrincipalQueryFilterKind.Workstations => WorkstationsAssertion(filter.Attribute, filter.Value),
        PrincipalQueryFilterKind.Extension => ExtensionAssertions(filter.Attribute, filter.Value),
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

    private static string StringAssertion(string attribute, object? value)
    {
        if (value is null)
        {
            return $"(!({attribute}=*))";
        }

        if (value is not string text)
        {
            throw new InvalidOperationException(
                $"The value for '{attribute}' is not a string query value.");
        }

        return $"({attribute}={EscapeKeepingWildcards(text)})";
    }

    private static string BinaryAssertion(string attribute, object? value)
    {
        if (value is null)
        {
            // Microsoft BinaryConverter includes this extra closing parenthesis.
            // It is observable through GetUnderlyingSearcher().Filter and can
            // make a null binary QBE fail when executed, so preserve it.
            return $"(!({attribute}=*)))";
        }

        if (value is not byte[] bytes)
        {
            throw new InvalidOperationException(
                $"The value for '{attribute}' is not a binary query value.");
        }

        return $"({attribute}={LdapFilter.EscapeBytes(bytes)})";
    }

    private static string CertificateAssertion(string attribute, object? value)
    {
        if (value is not X509Certificate2 certificate)
        {
            throw new InvalidOperationException(
                $"The value for '{attribute}' is not a certificate query value.");
        }

        return $"({attribute}={LdapFilter.EscapeBytes(certificate.RawData)})";
    }

    private static string AccountExpirationAssertion(object? value) => value switch
    {
        null => "(|(accountExpires=9223372036854775807)(accountExpires=0))",
        DateTime date => $"(accountExpires={date.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture)})",
        _ => throw new InvalidOperationException(
            "AccountExpirationDate is not a DateTime query value."),
    };

    private static string WorkstationsAssertion(string attribute, object? value)
    {
        if (value is null)
        {
            return $"(!({attribute}=*))";
        }

        if (value is not string workstations)
        {
            throw new InvalidOperationException(
                "PermittedWorkstations is not a string query value.");
        }

        return $"({attribute}=*{EscapeKeepingWildcards(workstations)}*)";
    }

    private static string CollectionAssertions(
        string attribute,
        object? value,
        Func<string, object?, string> converter)
    {
        if (value is not IEnumerable values || value is string)
        {
            throw new InvalidOperationException(
                $"The value for '{attribute}' is not a collection query value.");
        }

        return string.Concat(values.Cast<object?>().Select(item => converter(attribute, item)));
    }

    private static string ExtensionAssertions(string attribute, object? value)
    {
        if (value is IEnumerable values and not string)
        {
            return string.Concat(values.Cast<object?>().Select(item => ExtensionAssertions(attribute, item)));
        }

        if (value is null)
        {
            // Microsoft's extension-cache converter dereferences each
            // collection element to obtain its runtime type. A null extension
            // value therefore fails while the QBE filter is being built.
            throw new NullReferenceException();
        }

        var text = value switch
        {
            DateTime date => date.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
            bool boolean => boolean ? "TRUE" : "FALSE",
            IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString(),
        } ?? throw new InvalidOperationException(
            $"The extension value for '{attribute}' cannot be converted to an LDAP assertion.");

        return $"({attribute}={EscapeKeepingWildcards(text)})";
    }

    private static string EscapeKeepingWildcards(string value) => value
        .Replace("\\", "\\5c")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}
