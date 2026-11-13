using System.Collections;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Existing-entry loading is excluded; these normal draft entries preserve owner
// callbacks while exercising only cursor validity and local wrapper identity.
internal static class DictionaryCursorMirrors
{
    private sealed class Draft : IDisposable
    {
        private readonly DS.DirectoryEntry parent=new("LDAP://unused.example.test/DC=example,DC=test");
        internal DS.DirectoryEntry Entry { get; }
        internal Draft()
        {
            Entry=parent.Children.Add("CN=dictionary-cursor","user");
            if (!Entry.UsePropertyCache) throw new InvalidOperationException("Only cached drafts are admitted");
            Entry.Properties["description"].Value="differential test user";
        }
        public void Dispose() { Entry.Dispose(); parent.Dispose(); }
    }

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("PropertyDictionaryEnumeratorComparisonTests.Unpositioned_dictionary_enumerator_read_matches_microsoft", Unpositioned());
        verify("PropertyDictionaryEnumeratorComparisonTests.Positioned_reads_return_property_wrappers_with_matching_identity", Positioned());
        verify("PropertyDictionaryEnumeratorComparisonTests.Pending_attribute_addition_does_not_change_an_existing_enumeration", Addition());
    }

    private static object? Read(IDictionaryEnumerator cursor,string accessor) => accessor switch
    {
        "Current" => cursor.Current,
        "Entry" => cursor.Entry.Value,
        "Key" => cursor.Key,
        "Value" => cursor.Value,
        _ => throw new ArgumentOutOfRangeException(nameof(accessor)),
    };

    private static List<Sequence> Unpositioned()
    {
        var rows=new List<Sequence>();
        // Exact finite cross-product declared by the source MemberData member.
        foreach (var position in new[] { "before-start","after-end","after-reset" })
        foreach (var accessor in new[] { "Current","Entry","Key","Value" })
        {
            using var draft=new Draft();
            var cursor=draft.Entry.Properties.GetEnumerator();
            try
            {
                if (position=="after-end") while (cursor.MoveNext()) { }
                else if (position=="after-reset")
                {
                    if (!cursor.MoveNext()) throw new InvalidOperationException("Empty draft fixture");
                    cursor.Reset();
                }
                var error=OfflineTheoryMirrors.Capture(() => Read(cursor,accessor));
                var row=new Sequence();
                row.Observe(36,error?.GetType().FullName,exceptionType:true);
                rows.Add(row);
            }
            finally { (cursor as IDisposable)?.Dispose(); }
        }
        return rows;
    }

    private static List<Sequence> Positioned()
    {
        var rows=new List<Sequence>();
        foreach (var accessor in new[] { "Current","Entry","Value" })
        {
            using var draft=new Draft();
            var properties=draft.Entry.Properties;
            var cursor=properties.GetEnumerator();
            try
            {
                var found=false;
                while (cursor.MoveNext())
                    if (string.Equals((string)cursor.Key,"description",StringComparison.OrdinalIgnoreCase))
                    { found=true; break; }
                if (!found) throw new InvalidOperationException("Description not enumerated by draft fixture");
                var first=(DS.PropertyValueCollection)Read(cursor,accessor)!;
                var second=(DS.PropertyValueCollection)Read(cursor,accessor)!;
                var row=new Sequence();
                row.Observe(72,ReferenceEquals(first,second));
                row.Observe(74,ReferenceEquals(first,properties["description"]));
                rows.Add(row);
            }
            finally { (cursor as IDisposable)?.Dispose(); }
        }
        return rows;
    }

    private static List<Sequence> Addition()
    {
        using var draft=new Draft();
        var properties=draft.Entry.Properties;
        var cursor=properties.GetEnumerator();
        try
        {
            properties["info"].Value="pending enumeration comparison";
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                while (cursor.MoveNext()) _=(string)cursor.Key;
            });
            var row=new Sequence();
            row.Observe(111,error?.GetType().FullName,exceptionType:true);
            return [row]; // The enumerated-name set was redacted and is excluded.
        }
        finally { (cursor as IDisposable)?.Dispose(); }
    }
}
