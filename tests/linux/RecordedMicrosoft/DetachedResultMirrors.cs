using System.Collections;
using System.Runtime.InteropServices;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

internal static class DetachedResultMirrors
{
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("SynchronizationCookieIdentityComparisonTests.Repeated_cookie_reads_have_the_same_identity_semantics_as_microsoft", CookieIdentity());
        verify("PrincipalMissingContextComparisonTests.ContextType_without_context_matches_microsoft", MissingContexts());
        verify("ResultPropertyLookupComparisonTests.Typed_lookup_after_dictionary_assignment_matches_microsoft", TypedLookups());
        verify("ResultPropertyLookupComparisonTests.Missing_property_collection_identity_matches_microsoft", MissingProperties());
        verify("ResultPropertyDeferredErrorComparisonTests.Indexer_rethrows_deferred_value_error_like_microsoft", DeferredErrors());
        verify("AdvancedFilterExtensionComparisonTests.Custom_filter_replaces_extension_cache_state_like_microsoft", ExtensionFilters());
        verify("PrincipalSearchResultPositionComparisonTests.Empty_result_Current_matches_position_validation", EmptyResultPositions());
    }

    private static List<Sequence> CookieIdentity()
    {
        var rows=new List<Sequence>();
        foreach (var scenario in new[] { "Default","EmptyInput","NullInput","Reset","ResetNull","ResetEmpty","Nonempty" })
        {
            var sync=new DS.DirectorySynchronization(new byte[] { 1,2,3 });
            switch (scenario)
            {
                case "Default": sync=new DS.DirectorySynchronization(); break;
                case "EmptyInput": sync=new DS.DirectorySynchronization(Array.Empty<byte>()); break;
                case "NullInput": sync=new DS.DirectorySynchronization((byte[]?)null); break;
                case "Reset": sync.ResetDirectorySynchronizationCookie(); break;
                case "ResetNull": sync.ResetDirectorySynchronizationCookie(null); break;
                case "ResetEmpty": sync.ResetDirectorySynchronizationCookie(Array.Empty<byte>()); break;
            }
            var first=sync.GetDirectorySynchronizationCookie();
            var second=sync.GetDirectorySynchronizationCookie();
            var row=new Sequence();
            row.Observe(55,ReferenceEquals(first,second));
            rows.Add(row);
        }
        return rows;
    }

    private sealed class Principal : AM.Principal
    {
        internal object?[]? Read(string name) => ExtensionGet(name);
        internal void Write(string name,object value) => ExtensionSet(name,value);
    }
    private sealed class Filters(AM.Principal owner) : AM.AdvancedFilters(owner)
    {
        internal void Set() => AdvancedFilterSet("description","criterion",typeof(string),AM.MatchType.Equals);
    }

    private static List<Sequence> MissingContexts()
    {
        var rows=new List<Sequence>();
        foreach (var disposed in new[] { false,true })
        {
            using var principal=new Principal();
            if (disposed) principal.Dispose();
            var error=OfflineTheoryMirrors.Capture(() => _=principal.ContextType);
            var row=new Sequence();
            row.Observe(79,error?.GetType().FullName,exceptionType:true);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> TypedLookups()
    {
        var rows=new List<Sequence>();
        foreach (var payload in new[] { "null","string","integer","collection" })
        {
            var values=new DS.ResultPropertyCollection();
            object? input=payload switch
            {
                "null" => null,
                "string" => "unexpected value",
                "integer" => 42,
                _ => values["missing"],
            };
            ((IDictionary)values)["description"]=input;
            var row=new Sequence();
            row.Observe(35,values.Contains("DESCRIPTION"));
            row.Observe(36,values.Count);
            DS.ResultPropertyValueCollection? result=null;
            var error=OfflineTheoryMirrors.Capture(() => result=values["DESCRIPTION"]);
            row.Observe(45,error?.GetType().FullName,exceptionType:true);
            row.Observe(46,result is null);
            if (result is not null) row.Observe(51,result.Count);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> MissingProperties()
    {
        var rows=new List<Sequence>();
        foreach (var lookup in new[] { "same-key","different-key","different-result" })
        {
            var values=new DS.ResultPropertyCollection();
            var other=lookup=="different-result" ? new DS.ResultPropertyCollection() : values;
            var key=lookup=="different-key" ? "another-missing" : "missing";
            var first=values["missing"];
            var second=other[key];
            var row=new Sequence();
            row.Observe(79,values.Count);
            row.Observe(82,ReferenceEquals(first,second));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> DeferredErrors()
    {
        var rows=new List<Sequence>();
        foreach (var comError in new[] { false,true })
        {
            Exception deferred=comError
                ? new COMException("Attribute conversion failed",unchecked((int)0x8000500c))
                : new NotSupportedException("Unsupported ADSI value type");
            var values=new DS.ResultPropertyValueCollection(new object[] { "readable-before",deferred,"readable-after" });
            _=values[0]; _=values[2];
            var row=new Sequence();
            row.Observe(27,values.Contains(deferred));
            row.Observe(28,values.IndexOf(deferred));
            values.CopyTo(new object[3],0);
            var error=OfflineTheoryMirrors.Capture(() => _=values[1]);
            row.Observe(39,error?.GetType().FullName,exceptionType:true);
            if (!ReferenceEquals(deferred,error)) throw new InvalidOperationException("Deferred result error lost source-required identity");
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> ExtensionFilters()
    {
        var rows=new List<Sequence>();
        foreach (var existing in new[] { false,true })
        {
            using var principal=new Principal();
            if (existing) principal.Write("description","original");
            new Filters(principal).Set();
            var row=new Sequence();
            row.Observe(85,principal.Read("description"));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> EmptyResultPositions()
    {
        var rows=new List<Sequence>();
        foreach (var position in new[] { "before-start","after-end","after-reset" })
        foreach (var nonGeneric in new[] { false,true })
        foreach (var arrayBacked in new[] { false,true })
        {
            using var result=new AM.PrincipalSearchResult<AM.Principal>(arrayBacked
                ? Array.Empty<AM.Principal>() : new List<AM.Principal>());
            using var enumerator=result.GetEnumerator();
            if (position!="before-start")
            {
                enumerator.MoveNext();
                if (position=="after-reset") enumerator.Reset();
            }
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                object? current=nonGeneric ? ((IEnumerator)enumerator).Current : enumerator.Current;
            });
            var row=new Sequence();
            // The ORIGINAL assertion's actual operand is a Microsoft Error read;
            // its expected operand is a literal and is deliberately not admitted.
            row.Observe(41,error?.GetType().FullName,exceptionType:true);
            rows.Add(row);
        }
        return rows;
    }
}
