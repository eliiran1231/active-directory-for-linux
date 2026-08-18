using System.DirectoryServices.Protocols;
using System.Globalization;
using ProtocolScope = System.DirectoryServices.Protocols.SearchScope;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Reads every value of an LDAP attribute whose values may be split across
/// Active Directory range responses.
/// </summary>
internal static class RangedAttributeReader
{
    public static IReadOnlyList<object> Read(DirectoryEntry entry, string attributeName)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentException.ThrowIfNullOrWhiteSpace(attributeName);

        var values = new List<object>();
        var nextStart = 0;

        while (true)
        {
            var requestedName = $"{attributeName};range={nextStart}-*";
            var request = new SearchRequest(
                entry.DistinguishedName,
                "(objectClass=*)",
                ProtocolScope.Base,
                requestedName);
            var response = (SearchResponse)entry.GetConnection().SendRequest(request);
            if (response.Entries.Count == 0)
            {
                return values;
            }

            var returned = FindReturnedAttribute(
                response.Entries[0].Attributes,
                attributeName,
                nextStart);
            if (returned is null)
            {
                return values;
            }

            AddValues(entry.GetSchemaConnection(), returned.Value.Attribute, attributeName, values);
            if (returned.Value.IsTerminal)
            {
                return values;
            }

            if (returned.Value.End < nextStart)
            {
                throw new InvalidOperationException(
                    $"The server returned an invalid range for attribute '{attributeName}'.");
            }

            nextStart = checked(returned.Value.End + 1);
        }
    }

    internal static bool TryParseReturnedName(
        string returnedName,
        string attributeName,
        out int start,
        out int? end)
    {
        start = 0;
        end = null;

        var prefix = $"{attributeName};range=";
        if (!returnedName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var range = returnedName.AsSpan(prefix.Length);
        var separator = range.IndexOf('-');
        if (separator <= 0
            || !int.TryParse(
                range[..separator],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out start))
        {
            return false;
        }

        var high = range[(separator + 1)..];
        if (high.SequenceEqual("*"))
        {
            return true;
        }

        if (!int.TryParse(
                high,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsedEnd)
            || parsedEnd < start)
        {
            return false;
        }

        end = parsedEnd;
        return true;
    }

    private static ReturnedAttribute? FindReturnedAttribute(
        SearchResultAttributeCollection attributes,
        string attributeName,
        int expectedStart)
    {
        DirectoryAttribute? plain = null;
        ReturnedAttribute? emptyRange = null;
        var sawUnexpectedRange = false;

        foreach (string returnedName in attributes.AttributeNames)
        {
            var attribute = attributes[returnedName];
            if (returnedName.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
            {
                plain = attribute;
                continue;
            }

            if (!TryParseReturnedName(returnedName, attributeName, out var start, out var end))
            {
                continue;
            }

            if (start != expectedStart)
            {
                sawUnexpectedRange = true;
                continue;
            }

            var candidate = new ReturnedAttribute(attribute, end is null, end ?? expectedStart);
            if (attribute.Count > 0)
            {
                return candidate;
            }

            emptyRange ??= candidate;
        }

        if (plain is { Count: > 0 })
        {
            return new ReturnedAttribute(plain, IsTerminal: true, End: expectedStart);
        }

        if (sawUnexpectedRange)
        {
            throw new InvalidOperationException(
                $"The server returned a non-contiguous range for attribute '{attributeName}'.");
        }

        // AD can include an empty copy of the requested range name alongside
        // the populated, server-sized range. If no populated value exists,
        // either the attribute is empty or the final range has been reached.
        return emptyRange ?? (plain is null
            ? null
            : new ReturnedAttribute(plain, IsTerminal: true, End: expectedStart));
    }

    private static void AddValues(
        LdapConnection connection,
        DirectoryAttribute attribute,
        string attributeName,
        List<object> values)
    {
        var kind = LdapAttributeSchema.Resolve(connection, new[] { attributeName })[attributeName];
        var wanted = kind == LdapValueKind.Binary ? typeof(byte[]) : typeof(string);
        values.AddRange(attribute.GetValues(wanted).Select(value => SearchEntryReader.ConvertValue(value, kind)));
    }

    private readonly record struct ReturnedAttribute(
        DirectoryAttribute Attribute,
        bool IsTerminal,
        int End);
}
