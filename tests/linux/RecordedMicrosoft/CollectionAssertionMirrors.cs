using System.Collections;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

internal static class CollectionAssertionMirrors
{
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("SchemaNameCollectionComparisonTests.Invalid_indexer_access_matches_exception_and_preserves_contents", SchemaIndexes(paired:false));
        verify("PrincipalSearcherDisposalComparisonTests.QueryFilter_getter_matches_microsoft_after_disposal", Searchers(setter:false));
        verify("PrincipalSearcherDisposalComparisonTests.Null_QueryFilter_validation_precedence_matches_microsoft", Searchers(setter:true));
        verify("PrincipalValueCollectionOfflineComparisonTests.Non_generic_add_return_value_matches_microsoft", AddReturns());
        verify("PrincipalValueCollectionOfflineComparisonTests.Generic_enumerator_current_matches_microsoft", EnumeratorPositions());
        verify("PrincipalValueCollectionOfflineComparisonTests.Disposed_enumerator_operations_match_microsoft", DisposedEnumerators());
        verify("PropertyCollectionValidationComparisonTests.Invalid_lookup_key_matches_microsoft", InvalidKeys());
        verify("PropertyCollectionValidationComparisonTests.CopyTo_validation_before_binding_matches_microsoft", InvalidCopies());
    }

    internal static List<Sequence> SchemaIndexes(bool paired)
    {
        var rows = new List<Sequence>();
        foreach (var index in new[] { -1,1 })
        foreach (var write in new[] { false,true })
        {
            using var entry = new DS.DirectoryEntry();
            var values=entry.Children.SchemaFilter;
            values.Add("user");
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                if (write) values[index]=paired ? "group" : "computer";
                else _=values[index];
            });
            var row=new Sequence();
            row.Observe(paired ? 274 : 174,error?.GetType().FullName,exceptionType:true);
            if (paired) row.Observe(275,(error as ArgumentException)?.ParamName);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Searchers(bool setter)
    {
        var rows = new List<Sequence>();
        foreach (var dispose in new[] { false,true })
        {
            using var searcher = new AM.PrincipalSearcher();
            if (dispose) searcher.Dispose();
            var error = OfflineTheoryMirrors.Capture(() =>
            {
                if (setter) searcher.QueryFilter=null!;
                else _=searcher.QueryFilter;
            });
            var row = new Sequence();
            row.Observe(setter ? 48 : 28,error?.GetType().FullName,exceptionType:true);
            // Setter ParamName at line 49 was redacted in every captured row.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> AddReturns()
    {
        var rows = new List<Sequence>();
        foreach (var initialCount in new[] { 0,1,3 })
        {
            var values = new AM.PrincipalValueCollection<string>();
            for (var i=0;i<initialCount;i++) values.Add($"HOST/existing-{i}");
            var actual = ((IList)values).Add("HOST/new");
            var row = new Sequence();
            row.Observe(29,actual);
            // Collection contents were opaque and are not compared here.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> EnumeratorPositions()
    {
        var rows = new List<Sequence>();
        foreach (var position in new[] { "before-first","after-last","after-reset","positioned" })
        {
            var values = new AM.PrincipalValueCollection<string>();
            values.Add("HOST/first");
            using var enumerator = values.GetEnumerator();
            switch (position)
            {
                case "positioned": enumerator.MoveNext(); break;
                case "after-last": enumerator.MoveNext(); enumerator.MoveNext(); break;
                case "after-reset": enumerator.MoveNext(); enumerator.Reset(); break;
            }
            string? value = null;
            var error = OfflineTheoryMirrors.Capture(() => value=enumerator.Current);
            var row = new Sequence();
            row.Observe(53,error?.GetType().FullName,exceptionType:true);
            row.Observe(54,value); // Only null values survived the public capture.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> DisposedEnumerators()
    {
        var rows = new List<Sequence>();
        foreach (var operation in new[] { "Current","MoveNext","Reset" })
        {
            var values = new AM.PrincipalValueCollection<string>();
            values.Add("HOST/first");
            using var enumerator = values.GetEnumerator();
            enumerator.MoveNext();
            enumerator.Dispose();
            var error = OfflineTheoryMirrors.Capture(() =>
            {
                if (operation=="Current") _=enumerator.Current;
                else if (operation=="MoveNext") enumerator.MoveNext();
                else enumerator.Reset();
            });
            var row = new Sequence();
            row.Observe(78,error?.GetType().FullName,exceptionType:true);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> InvalidKeys()
    {
        var rows = new List<Sequence>();
        foreach (var operation in new[] { "typed-null","dictionary-null","dictionary-integer","dictionary-object","contains-integer","contains-object" })
        {
            var values = new DS.PropertyCollection();
            var error = OfflineTheoryMirrors.Capture(() =>
            {
                if (operation=="typed-null") { _=values[null!]; return; }
                IDictionary dictionary=values;
                object? key=operation switch
                {
                    "dictionary-null" => null,
                    "dictionary-integer" or "contains-integer" => 42,
                    _ => new object(),
                };
                if (operation.StartsWith("contains-",StringComparison.Ordinal)) _=dictionary.Contains(key!);
                else _=dictionary[key!];
            });
            var row = new Sequence();
            row.Observe(31,error?.GetType().FullName,exceptionType:true);
            row.Observe(32,(error as ArgumentException)?.ParamName);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> InvalidCopies()
    {
        var rows = new List<Sequence>();
        foreach (var operation in new[] { "negative-index","null-array","multidimensional-array" })
        {
            ICollection values = new DS.PropertyCollection();
            Array? destination=operation switch
            {
                "negative-index" => new object[1],
                "null-array" => null,
                _ => new object[1,1],
            };
            var error = OfflineTheoryMirrors.Capture(() => values.CopyTo(destination!,operation=="negative-index" ? -1 : 0));
            var row = new Sequence();
            row.Observe(58,error?.GetType().FullName,exceptionType:true);
            // All ParamName values at line 59 were redacted.
            rows.Add(row);
        }
        return rows;
    }
}
