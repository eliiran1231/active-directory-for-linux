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

        var generation = entry.IdentityLifetime.Capture(entry.ThrowIfDisposed);
        void Validate() => entry.IdentityLifetime.Checked(generation, entry.ThrowIfDisposed, () => true);
        var distinguishedName = entry.IdentityLifetime.Checked(generation, entry.ThrowIfDisposed, () => entry.DistinguishedName);
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        using var lease = entry.AcquireConnection(Validate);
        var profile = lease.ExecuteTransport(transport => (transport.Timeout, IsProtocols: (transport.Capabilities & LdapTransportCapabilities.ProtocolsConnection) != 0));
        var timeout = profile.Timeout;
        TimeSpan Remaining()
        {
            Validate();
            if (profile.IsProtocols) return timeout;
            var value = timeout - System.Diagnostics.Stopwatch.GetElapsedTime(started);
            return value > TimeSpan.Zero ? value : throw new TimeoutException("Ranged LDAP read deadline expired.");
        }
        var values = new List<object>();
        var nextStart = 0;

        while (true)
        {
            var requestedName = $"{attributeName};range={nextStart}-*";
            var request = new SearchRequest(
                distinguishedName,
                "(objectClass=*)",
                ProtocolScope.Base,
                requestedName);
            Validate();
            var response = lease.Search(request, Remaining);
            Validate();
            if (response.Entries.Length == 0)
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

            values.AddRange(lease.ReadValues(entry, attributeName, returned.Value.Attribute, response.OriginalAttribute(returned.Value.Name), Remaining));
            Validate();
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
        Dictionary<string, byte[][]> attributes,
        string attributeName,
        int expectedStart)
    {
        byte[][]? plain = null;
        string? plainName = null;
        ReturnedAttribute? emptyRange = null;
        var sawUnexpectedRange = false;

        foreach (string returnedName in attributes.Keys)
        {
            var attribute = attributes[returnedName];
            if (returnedName.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
            {
                plain = attribute; plainName = returnedName;
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

            var candidate = new ReturnedAttribute(returnedName, attribute, end is null, end ?? expectedStart);
            if (attribute.Length > 0)
            {
                return candidate;
            }

            emptyRange ??= candidate;
        }

        if (plain is { Length: > 0 })
        {
            return new ReturnedAttribute(plainName!, plain, IsTerminal: true, End: expectedStart);
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
            : new ReturnedAttribute(plainName!, plain, IsTerminal: true, End: expectedStart));
    }

    private readonly record struct ReturnedAttribute(
        string Name, byte[][] Attribute,
        bool IsTerminal,
        int End);
}
