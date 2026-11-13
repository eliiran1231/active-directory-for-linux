using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

internal static class RetainedCollectionMirrors
{
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("CompatibilityRetainedValueReplacementComparisonTests.Whole_value_replacement_preserves_matching_local_state_after_owner_disposal", WrapperReplacement());
        verify("CompatibilityRetainedPrincipalValuesAfterDisposeComparisonTests.Retained_service_names_mutation_after_owner_disposal_matches_microsoft", ServiceNames());
        verify("PropertyValueCollectionComparisonTests.Case_varied_strings_and_equal_byte_arrays_use_object_equality", PropertyEquality());
    }

    private static List<Sequence> WrapperReplacement()
    {
        var rows=new List<Sequence>();
        foreach (var kind in new[] { "scalar","array","null" })
        foreach (var dispose in new[] { false,true })
        {
            // Public draft-entry construction preserves normal owner callbacks.
            // No server object is created: CommitChanges is never called.
            using var parent=new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test");
            using var entry=parent.Children.Add("CN=retained-wrapper","user");
            if (!entry.UsePropertyCache) throw new InvalidOperationException("Only cached draft entries are admitted");
            var values=entry.Properties["description"];
            values.Value="differential test user"; // Public source-fixture constant.
            if (dispose) entry.Dispose();
            object? replacement=kind switch
            {
                "scalar" => "pending-scalar",
                "array" => new object[] { "pending-first","pending-second" },
                _ => null,
            };
            var error=OfflineTheoryMirrors.Capture(() => values.Value=replacement);
            var row=new Sequence();
            row.Observe(46,error?.GetType().FullName,exceptionType:true);
            row.Observe(47,(error as ObjectDisposedException)?.ObjectName);
            row.Observe(49,values.Count);
            row.Observe(54,values.Value is null);
            row.Observe(55,values.Value is object[]);
            // Non-null ObjectName and content strings were redacted.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> ServiceNames()
    {
        const string seed="HOST/compat-retained-seed";
        const string added="HOST/compat-retained-added";
        var rows=new List<Sequence>();
        foreach (var operation in new[] { "Add","RemoveAt","Clear" })
        foreach (var dispose in new[] { false,true })
        {
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,
                "unused.example.test","DC=example,DC=test",
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            using var owner=new AM.ComputerPrincipal(context);
            if (owner.IsPersisted) throw new InvalidOperationException("Only unsaved collection owners are admitted");
            var values=owner.ServicePrincipalNames;
            values.Add(seed);
            if (dispose) owner.Dispose();
            _=values.ToArray();
            _=values.Contains(seed);
            _=values.Contains(added);
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                switch (operation)
                {
                    case "Add": values.Add(added); break;
                    case "RemoveAt": values.RemoveAt(0); break;
                    case "Clear": values.Clear(); break;
                }
            });
            _=values.ToArray(); // Retained local reads only; no owner reacquisition.
            var row=new Sequence();
            row.Observe(74,error?.GetType().FullName,exceptionType:true);
            row.Observe(75,(error as ArgumentException)?.ParamName);
            row.Observe(77,values.Count);
            row.Observe(79,values.Contains(seed));
            row.Observe(80,values.Contains(added));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> PropertyEquality()
    {
        // Normal detached fixtures. They carry no live entry or owner callbacks;
        // these observations cover collection equality, not provider binding.
        var properties=new DS.PropertyCollection();
        var strings=properties["description"];
        var binary=properties["audio"];
        strings.Value="CaseSensitive";
        var containsString=strings.Contains("casesensitive");
        var stringIndex=strings.IndexOf("casesensitive");
        strings.Remove("casesensitive");
        var stringCount=strings.Count;
        binary.Value=new byte[] { 1,2,3 };
        var equalBytes=new byte[] { 1,2,3 };
        var containsBytes=binary.Contains(equalBytes);
        var byteIndex=binary.IndexOf(equalBytes);
        binary.Remove(equalBytes);
        var row=new Sequence();
        row.Observe(39,containsString);
        row.Observe(40,stringIndex);
        row.Observe(41,stringCount);
        row.Observe(42,containsBytes);
        row.Observe(43,byteIndex);
        row.Observe(44,binary.Count);
        return [row];
    }
}
