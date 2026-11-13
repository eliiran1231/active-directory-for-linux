using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Configure managed, unbound searchers only. Never execute a search or save.
internal static class NativeSearcherMirrors
{
    private static AM.PrincipalContext Context() => new(AM.ContextType.Domain,
        "unused.example.test", "DC=example,DC=test",
        AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer, null, null);

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("PrincipalSearcherComparisonTests.Replacing_query_filter_updates_context_like_microsoft", ContextReplacement());
        verify("CompatibilityNativeSearcherReplacementComparisonTests.Replacing_filter_retains_native_searcher_configuration_like_microsoft", Replacement());
        verify("CompatibilitySearcherConstructionPagingComparisonTests.Deferred_filter_assignment_preserves_constructor_paging_state", Paging());
    }

    private static List<Sequence> ContextReplacement()
    {
        using var first=Context();
        using var second=Context();
        using var filter=new AM.UserPrincipal(first) { SamAccountName="context-replacement" };
        using var replacement=new AM.UserPrincipal(second) { SamAccountName="context-replacement" };
        using var searcher=new AM.PrincipalSearcher(filter);
        searcher.QueryFilter=replacement;
        var row=new Sequence();
        row.Observe(208,ReferenceEquals(second,searcher.Context));
        row.Observe(211,ReferenceEquals(first,searcher.Context));
        return [row];
    }

    private static List<Sequence> Replacement()
    {
        var rows = new List<Sequence>();
        foreach (var distinct in new[] { false, true })
        {
            using var first = Context();
            using var second = Context();
            using var filter = new AM.UserPrincipal(first) { SamAccountName = "native-first" };
            var replacementContext = distinct ? second : first;
            using var replacement = new AM.UserPrincipal(replacementContext) { SamAccountName = "native-replacement" };
            using var searcher = new AM.PrincipalSearcher(filter);
            var native = (DS.DirectorySearcher)searcher.GetUnderlyingSearcher();
            native.PageSize = 17;
            native.SizeLimit = 3;
            searcher.QueryFilter = replacement;
            var row = new Sequence();
            row.Observe(55, ReferenceEquals(replacement, searcher.QueryFilter));
            row.Observe(57, ReferenceEquals(replacementContext, searcher.Context));
            var after = (DS.DirectorySearcher)searcher.GetUnderlyingSearcher();
            row.Observe(63, ReferenceEquals(native, after));
            row.Observe(64, after.PageSize);
            row.Observe(65, after.SizeLimit);
            row.Observe(67, ReferenceEquals(after, searcher.GetUnderlyingSearcher()));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Paging()
    {
        var rows = new List<Sequence>();
        foreach (var constructorFilter in new[] { false, true })
        {
            using var context = Context();
            using var filter = new AM.UserPrincipal(context);
            using var searcher = constructorFilter ? new AM.PrincipalSearcher(filter) : new AM.PrincipalSearcher();
            if (!constructorFilter) searcher.QueryFilter = filter;
            var native = (DS.DirectorySearcher)searcher.GetUnderlyingSearcher();
            var row = new Sequence();
            row.Observe(47, native.PageSize);
            native.PageSize = 37;
            if (!ReferenceEquals(native, searcher.GetUnderlyingSearcher()))
                throw new InvalidOperationException("Native searcher control identity changed");
            // The source's line 54 expected operand is literal true. It is only
            // a local control above, never counted as a Microsoft observation.
            row.Observe(55, native.PageSize);
            rows.Add(row);
        }
        return rows;
    }
}
