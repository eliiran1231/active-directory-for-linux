using System.Collections;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

internal static class DetachedControlMirrors
{
    private sealed class Principal : AM.Principal { }

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("PropertyCollectionBindingComparisonTests.Collection_access_defers_binding_like_microsoft", WrapperAccess());
        verify("PrincipalValueCollectionComparisonTests.Non_generic_Add_return_value_matches_microsoft", AddReturns());
        verify("PrincipalEqualityDisposalComparisonTests.Equality_of_distinct_unsaved_principals_matches_after_disposal", PrincipalEquality());
        verify("DirectoryEntryDisposedWrapperComparisonTests.Close_replaces_property_wrapper_without_disposing_entry_as_a_control", CloseWrapper());
        verify("ResultPropertyLookupComparisonTests.Removed_property_returns_empty_collection_like_microsoft", RemovedProperty());
        verify("SchemaNameCollectionComparisonTests.Removing_a_missing_value_throws_the_same_exception", MissingSchemaValue());
        verify("LifecycleComparisonTests.Search_result_and_enumerator_disposal_match_for_empty_results", EmptyResultLifetime());
    }

    private static List<Sequence> WrapperAccess()
    {
        var rows=new List<Sequence>();
        foreach (var operation in new[] { "collection","names","values","read-only","null-key" })
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test",null,null,DS.AuthenticationTypes.Signing);
            object? value=null;
            var error=OfflineTheoryMirrors.Capture(() => value=operation switch
            {
                "collection" => entry.Properties is not null,
                "names" => entry.Properties.PropertyNames is not null,
                "values" => entry.Properties.Values is not null,
                "read-only" => ((IDictionary)entry.Properties).IsReadOnly,
                _ => entry.Properties[null!],
            });
            var row=new Sequence();
            row.Observe(37,error?.GetType().FullName,exceptionType:true);
            row.Observe(38,(error as ArgumentException)?.ParamName);
            row.Observe(40,value);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> AddReturns()
    {
        var rows=new List<Sequence>();
        foreach (var initial in new[] { 0,1,3 })
        {
            var values=new AM.PrincipalValueCollection<string>();
            for (var i=0;i<initial;i++) values.Add($"HOST/{i}");
            var returned=((IList)values).Add("HOST/new");
            var row=new Sequence();
            row.Observe(33,returned);
            row.Observe(34,values.Count);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> PrincipalEquality()
    {
        var rows=new List<Sequence>();
        foreach (var disposeLeft in new[] { false,true })
        foreach (var disposeRight in new[] { false,true })
        {
            using var left=new Principal();
            using var right=new Principal();
            if (disposeLeft) left.Dispose();
            if (disposeRight) right.Dispose();
            var row=new Sequence();
            row.Observe(36,left.Equals(left));
            bool? value=null;
            var error=OfflineTheoryMirrors.Capture(() => value=left.Equals(right));
            row.Observe(42,error?.GetType().FullName,exceptionType:true);
            row.Observe(43,value);
            row.Observe(44,left.Equals(null));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> CloseWrapper()
    {
        using var entry=new DS.DirectoryEntry();
        var before=entry.Properties;
        entry.Close();
        if (ReferenceEquals(before,entry.Properties)) throw new InvalidOperationException("Close retained the source-forbidden property wrapper");
        var row=new Sequence();
        row.Observe(63,((IDictionary)entry.Properties).IsReadOnly);
        return [row];
    }

    private static List<Sequence> RemovedProperty()
    {
        var values=new DS.ResultPropertyCollection();
        ((IDictionary)values)["description"]="temporary";
        ((IDictionary)values).Remove("description");
        var row=new Sequence();
        row.Observe(98,values.Contains("description"));
        _=values["description"];
        row.Observe(101,values.Count);
        return [row];
    }

    private static List<Sequence> MissingSchemaValue()
    {
        using var entry=new DS.DirectoryEntry();
        var values=entry.Children.SchemaFilter;
        var error=OfflineTheoryMirrors.Capture(() => values.Remove("missing"));
        var row=new Sequence();
        row.Observe(394,error?.GetType().FullName,exceptionType:true);
        return [row];
    }

    private static List<Sequence> EmptyResultLifetime()
    {
        using var result=new AM.PrincipalSearchResult<AM.Principal>(Array.Empty<AM.Principal>());
        using var enumerator=result.GetEnumerator();
        result.Dispose();
        var collectionError=OfflineTheoryMirrors.Capture(() => { using var unexpected=result.GetEnumerator(); });
        if (collectionError is not ObjectDisposedException) throw new InvalidOperationException("Disposed result did not enforce the source-required guard");
        var row=new Sequence();
        row.Observe(93,enumerator.MoveNext());
        enumerator.Dispose();
        var cursorError=OfflineTheoryMirrors.Capture(() => enumerator.MoveNext());
        if (cursorError is not ObjectDisposedException) throw new InvalidOperationException("Disposed cursor did not enforce the source-required guard");
        // Disposed ObjectName strings were redacted and are not inferred.
        return [row];
    }
}
