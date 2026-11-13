using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

internal static class DetachedEntryMirrors
{
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("DirectoryEntryCredentialCacheComparisonTests.Credential_assignment_invalidates_property_wrapper_like_microsoft", Credentials());
        verify("DirectoryEntryCredentialCacheComparisonTests.Authentication_assignment_invalidates_property_wrapper_like_microsoft", Authentication());
        verify("DirectoryEntryPathEquivalenceComparisonTests.Equivalent_path_assignment_preserves_text_and_property_wrapper_like_microsoft", Paths());
        verify("DirectoryEntryUnboundCommitComparisonTests.Unbound_commit_and_cache_mode_transition_match_microsoft", UnboundCommits());
        verify("DirectoryEntryComparisonTests.Disposed_entry_lifecycle_matches_for_cached_and_uncached_entries", DisposedLifecycle());
    }

    private static List<Sequence> DisposedLifecycle()
    {
        var rows=new List<Sequence>();
        foreach (var cache in new[] { true,false })
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/CN=user,DC=example,DC=test");
            entry.UsePropertyCache=cache;
            entry.Dispose();
            var refresh=OfflineTheoryMirrors.Capture(entry.RefreshCache);
            var property=OfflineTheoryMirrors.Capture(() => _=entry.Properties["displayName"].Value);
            var commit=OfflineTheoryMirrors.Capture(entry.CommitChanges);
            var name=OfflineTheoryMirrors.Capture(() => _=entry.Name);
            var parent=OfflineTheoryMirrors.Capture(() => { using var value=entry.Parent; });
            var row=new Sequence();
            row.Observe(85,refresh?.GetType().Name,exceptionType:true);
            row.Observe(87,property?.GetType().Name,exceptionType:true);
            row.Observe(89,commit?.GetType().Name,exceptionType:true);
            row.Observe(90,(commit as ObjectDisposedException)?.ObjectName);
            row.Observe(94,name?.GetType().Name,exceptionType:true);
            row.Observe(96,parent?.GetType().Name,exceptionType:true);
            // Searching a disposed root can rebind. The live search is excluded.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Credentials()
    {
        var rows=new List<Sequence>();
        foreach (var property in new[] { "Username","Password" })
        foreach (var replacement in new string?[] { "replacement","",null,"original" })
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test","original","original");
            var before=entry.Properties;
            if (property=="Username") entry.Username=replacement;
            else entry.Password=replacement;
            var row=new Sequence();
            row.Observe(42,entry.Username); // Only the null username was exported.
            row.Observe(44,ReferenceEquals(before,entry.Properties));
            row.Observe(46,ReferenceEquals(entry.Properties,entry.Properties));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Authentication()
    {
        var rows=new List<Sequence>();
        foreach (var replacement in new[] { DS.AuthenticationTypes.None,DS.AuthenticationTypes.Anonymous,
            DS.AuthenticationTypes.Secure | DS.AuthenticationTypes.Signing,DS.AuthenticationTypes.Secure })
        {
            using var entry=new DS.DirectoryEntry();
            var before=entry.Properties;
            entry.AuthenticationType=replacement;
            var row=new Sequence();
            row.Observe(67,(int)entry.AuthenticationType);
            row.Observe(68,ReferenceEquals(before,entry.Properties));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Paths()
    {
        var rows=new List<Sequence>();
        foreach (var input in new (string Initial,string Replacement)[]
        {
            ("Alice","ALICE"),("Alice","Bob"),("Alice","Al\u00adice"),
            ("Jos\u00e9","Jose\u0301"),("Alice","\uff21lice"),("\u3042","\u30a2"),
        })
        {
            const string prefix="LDAP://unused.example.test/CN=";
            const string suffix=",DC=example,DC=test";
            using var entry=new DS.DirectoryEntry(prefix+input.Initial+suffix);
            var before=entry.Properties;
            entry.Path=prefix+input.Replacement+suffix;
            var row=new Sequence();
            row.Observe(33,ReferenceEquals(before,entry.Properties));
            // Path text was redacted and is not compared to an inferred string.
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> UnboundCommits()
    {
        var rows=new List<Sequence>();
        foreach (var state in new[] { "fresh","wrapper","closed","disposed" })
        foreach (var disableCache in new[] { false,true })
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test",null,null,DS.AuthenticationTypes.Signing);
            if (state!="fresh") _=entry.Properties;
            if (state=="closed") entry.Close();
            if (state=="disposed") entry.Dispose();
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                if (disableCache) entry.UsePropertyCache=false;
                else entry.CommitChanges();
            });
            var row=new Sequence();
            row.Observe(62,error?.GetType().FullName,exceptionType:true);
            row.Observe(63,entry.UsePropertyCache);
            rows.Add(row);
        }
        return rows;
    }
}
