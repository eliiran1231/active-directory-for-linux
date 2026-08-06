using System.DirectoryServices.Protocols;

namespace AdForLinux.DirectoryServices.Ldap;

/// <summary>
/// Turns a raw <see cref="SearchResultEntry"/> into name/value pairs, decoding
/// text attributes to strings and leaving binary ones as byte[]. Shared by
/// DirectoryEntry and search-result property collections so they read alike.
/// </summary>
internal static class SearchEntryReader
{
    public static IEnumerable<(string Name, object Value)> Read(SearchResultEntry entry)
    {
        foreach (string name in entry.Attributes.AttributeNames)
        {
            var attribute = entry.Attributes[name];
            var wanted = LdapAttributeSchema.IsBinary(name) ? typeof(byte[]) : typeof(string);

            foreach (var value in attribute.GetValues(wanted))
            {
                yield return (name, value);
            }
        }
    }
}
