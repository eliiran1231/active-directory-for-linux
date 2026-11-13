using System.Collections;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// The source's Base query proves exactly one result, or explicitly requests none.
// These controlled producers exercise the normal collection modes, not LDAP or ADSI.
internal static class ControlledResultCursorMirrors
{
    private const string Dn="CN=cursor-user,DC=example,DC=test";

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("CompatibilitySearchResultBinaryOwnershipComparisonTests.Repeated_enumeration_isolates_binary_value_buffers_like_microsoft", BinaryOwnership());
        verify("CompatibilitySearchResultLifecycleComparisonTests.Enumeration_and_materialized_lookup_identity_match_microsoft", Identity());
        verify("CompatibilityDirectoryResultCursorComparisonTests.Current_validates_cursor_position", Current());
        verify("CompatibilityDirectoryResultCursorComparisonTests.Reset_rewinds_cached_results_after_optional_materialization", Reset());
    }

    private static List<Sequence> BinaryOwnership()
    {
        var rows=new List<Sequence>();
        foreach (var mutate in new[] { false,true })
        {
            var seed=Enumerable.Range(0,16).Select(i => (byte)i).ToArray();
            using var root=new DS.DirectoryEntry("LDAP://unused.example.test/"+Dn);
            DS.SearchResult Item()
            {
                var properties=new DS.ResultPropertyCollection();
                properties.Set("distinguishedName",new object[] { Dn });
                properties.Set("objectGUID",new object[] { seed.ToArray() });
                return new DS.SearchResult(root,properties);
            }
            using var results=new DS.SearchResultCollection(Produce(Item(),empty:false),cacheResults:true,new[] { "objectGUID","distinguishedName" });
            byte[] Only(DS.SearchResultCollection collection)
            {
                var cursor=collection.GetEnumerator();
                try
                {
                    if (!cursor.MoveNext()) throw new InvalidOperationException("Binary producer was empty");
                    var item=(DS.SearchResult)cursor.Current;
                    if ((string)item.Properties["distinguishedName"][0]!=Dn) throw new InvalidOperationException("Binary producer role control failed");
                    var bytes=(byte[])item.Properties["objectGUID"][0];
                    if (cursor.MoveNext()) throw new InvalidOperationException("Binary producer returned extra rows");
                    return bytes;
                }
                finally { (cursor as IDisposable)?.Dispose(); }
            }
            using var baselineResults=new DS.SearchResultCollection(Produce(Item(),empty:false),cacheResults:true,new[] { "objectGUID","distinguishedName" });
            var baseline=Only(baselineResults).ToArray();
            var row=new Sequence();
            row.Observe(26,baseline.Length);
            var first=Only(results);
            row.Observe(44,first.Length);
            if (!first.SequenceEqual(baseline)) throw new InvalidOperationException("Binary producer content control failed");
            if (mutate) first[0]^=0xff;
            var later=Only(results);
            row.Observe(63,later.Length);
            // Local controlled-content check, not a Microsoft GUID comparison.
            if (!later.SequenceEqual(baseline)) throw new InvalidOperationException("Binary snapshot mutation escaped into a later enumeration");
            if (mutate) row.Observe(76,ReferenceEquals(first,later));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Identity()
    {
        var rows=new List<Sequence>();
        foreach (var materialize in new[] { false,true })
        foreach (var operation in new[] { "repeated-enumeration","enumeration-vs-indexer","contains-enumerated",
            "contains-indexed","index-of-enumerated","index-of-indexed" })
        {
            using var root=new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test");
            IEnumerable<DS.SearchResult> ProduceRows()
            {
                foreach (var role in new[] { "first","second" })
                {
                    var properties=new DS.ResultPropertyCollection();
                    properties.Set("distinguishedName",new object[] { "CN="+role+",DC=example,DC=test" });
                    yield return new DS.SearchResult(root,properties);
                }
            }
            using var results=new DS.SearchResultCollection(ProduceRows(),cacheResults:true,new[] { "distinguishedName" });
            string Key(DS.SearchResult item) => ((string)item.Properties["distinguishedName"][0]!).ToUpperInvariant();
            var row=new Sequence();
            if (materialize) row.Observe(35,results.Count);
            var first=results.Cast<DS.SearchResult>().ToDictionary(Key,StringComparer.OrdinalIgnoreCase);
            var second=results.Cast<DS.SearchResult>().ToDictionary(Key,StringComparer.OrdinalIgnoreCase);
            row.Observe(42,results.Count);
            var indexed=Enumerable.Range(0,results.Count).Select(i => results[i]).ToDictionary(Key,StringComparer.OrdinalIgnoreCase);
            var keys=indexed.Keys.Order(StringComparer.OrdinalIgnoreCase).ToArray();
            var expectedRoles=new[] { "CN=FIRST,DC=EXAMPLE,DC=TEST","CN=SECOND,DC=EXAMPLE,DC=TEST" };
            if (!keys.SequenceEqual(expectedRoles,StringComparer.OrdinalIgnoreCase)
                || !keys.SequenceEqual(first.Keys.Order(StringComparer.OrdinalIgnoreCase),StringComparer.OrdinalIgnoreCase)
                || !keys.SequenceEqual(second.Keys.Order(StringComparer.OrdinalIgnoreCase),StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException("Two-row producer/key control failed");
            foreach (var key in keys)
            {
                var actual=operation switch
                {
                    "repeated-enumeration" => ReferenceEquals(first[key],second[key]),
                    "enumeration-vs-indexer" => ReferenceEquals(first[key],indexed[key]),
                    "contains-enumerated" => results.Contains(first[key]),
                    "contains-indexed" => results.Contains(indexed[key]),
                    "index-of-enumerated" => results.IndexOf(first[key])>=0,
                    _ => results.IndexOf(indexed[key]) is var i && i>=0 && ReferenceEquals(indexed[key],results[i]),
                };
                row.Observe(79,actual);
            }
            rows.Add(row);
        }
        return rows;
    }

    private static DS.SearchResultCollection Results(DS.DirectoryEntry root,bool cache,bool empty)
    {
        var properties=new DS.ResultPropertyCollection();
        properties.Set("distinguishedName",new object[] { Dn });
        var item=new DS.SearchResult(root,properties);
        return new DS.SearchResultCollection(Produce(item,empty),cache,new[] { "distinguishedName" });
    }

    private static IEnumerable<DS.SearchResult> Produce(DS.SearchResult item,bool empty)
    {
        if (!empty) yield return item;
    }

    private static void Position(IEnumerator cursor,string position)
    {
        if (position=="before-first") return;
        if (position=="empty-after-last")
        {
            if (cursor.MoveNext()) throw new InvalidOperationException("Empty producer control failed");
            return;
        }
        if (!cursor.MoveNext()) throw new InvalidOperationException("One-result producer control failed");
        if (position=="after-last" && cursor.MoveNext())
            throw new InvalidOperationException("One-result producer returned extra rows");
    }

    private static (Exception? Error,string? Dn) Read(IEnumerator cursor)
    {
        string? dn=null;
        var error=OfflineTheoryMirrors.Capture(() =>
        {
            var item=(DS.SearchResult?)cursor.Current;
            dn=item is null ? null : (string)item.Properties["distinguishedName"][0]!;
        });
        return (error,dn);
    }

    private static List<Sequence> Current()
    {
        var rows=new List<Sequence>();
        foreach (var cache in new[] { true,false })
        foreach (var position in new[] { "before-first","positioned","after-last","empty-after-last" })
        {
            using var root=new DS.DirectoryEntry("LDAP://unused.example.test/"+Dn);
            using var results=Results(root,cache,position=="empty-after-last");
            var cursor=results.GetEnumerator();
            try
            {
                Position(cursor,position);
                var row=new Sequence();
                for (var attempt=0;attempt<2;attempt++)
                {
                    var state=Read(cursor);
                    if (position=="positioned" && (state.Error is not null || state.Dn!=Dn))
                        throw new InvalidOperationException("Positioned producer control failed");
                    row.Observe(45,state.Error?.GetType().FullName,exceptionType:true);
                    row.Observe(46,state.Dn?.ToUpperInvariant());
                }
                rows.Add(row);
            }
            finally { (cursor as IDisposable)?.Dispose(); }
        }
        return rows;
    }

    private static List<Sequence> Reset()
    {
        var rows=new List<Sequence>();
        foreach (var materialize in new[] { false,true })
        foreach (var position in new[] { "before-first","positioned","after-last" })
        {
            using var root=new DS.DirectoryEntry("LDAP://unused.example.test/"+Dn);
            using var results=Results(root,cache:true,empty:false);
            if (materialize && results.Count!=1) throw new InvalidOperationException("Materialized producer control failed");
            var cursor=results.GetEnumerator();
            try
            {
                Position(cursor,position);
                var error=OfflineTheoryMirrors.Capture(cursor.Reset);
                var row=new Sequence();
                row.Observe(84,error?.GetType().FullName,exceptionType:true);
                if (error is null)
                {
                    // Original source prerequisites, not literal-valued oracle
                    // sites 96/98/105. Those comparisons are never admitted.
                    if (Read(cursor).Error is not InvalidOperationException)
                        throw new InvalidOperationException("Reset cursor position control failed");
                    if (!cursor.MoveNext()) throw new InvalidOperationException("Reset replay control failed");
                    var replay=Read(cursor);
                    row.Observe(102,replay.Error?.GetType().FullName,exceptionType:true);
                    if (replay.Error is null && replay.Dn!=Dn)
                        throw new InvalidOperationException("Reset producer value control failed");
                    if (cursor.MoveNext()) throw new InvalidOperationException("Reset replay returned extra rows");
                }
                rows.Add(row);
            }
            finally { (cursor as IDisposable)?.Dispose(); }
        }
        return rows;
    }
}
