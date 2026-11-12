using System.Reflection;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

internal static class ReviewedAssertionMirrors
{
    internal static void Run(Action<string, List<Sequence>> verify)
    {
        verify("SearcherValidationContractComparisonTests.Detached_enum_rejection_preserves_previous_value", Enums());
        verify("SearcherValidationContractComparisonTests.Detached_time_limits_match_fractional_and_overflow_boundaries", TimeLimits());
        verify("SearcherValidationContractComparisonTests.Detached_paging_and_sync_conflicts_preserve_state_and_allow_recovery", Paging());
        verify("SearcherValidationContractComparisonTests.Detached_virtual_list_conflicts_preserve_explicit_cache_intent", CacheIntent());
        verify("SearcherValidationContractComparisonTests.Detached_virtual_list_rejected_setter_preserves_coupled_state", VlvSetters());
        verify("SearcherValidationContractComparisonTests.Rejected_setter_matches_exception_parameter_and_preserves_state", RejectedSetters());
    }

    private static void Failure(Sequence row, Action action)
    {
        var error = OfflineTheoryMirrors.Capture(action);
        if (error is TargetInvocationException invocation) error = invocation.InnerException;
        row.Observe(217, error?.GetType().FullName, exceptionType: true);
        if (error is ArgumentException argument) row.Observe(219, argument.ParamName);
    }

    private static List<Sequence> Enums()
    {
        var rows = new List<Sequence>();
        foreach (var input in new (string Property, int Invalid)[]
        {
            ("DerefAlias",-1),("DerefAlias",4),("ExtendedDN",-2),("ExtendedDN",2),
            ("ReferralChasing",1),("ReferralChasing",int.MaxValue),("SearchScope",-1),
            ("SearchScope",3),("SecurityMasks",16),("SecurityMasks",int.MaxValue),
        })
        {
            using var searcher = new DS.DirectorySearcher();
            var property = typeof(DS.DirectorySearcher).GetProperty(input.Property)!;
            var row = new Sequence();
            row.Observe(30, Convert.ToInt32(property.GetValue(searcher)));
            Failure(row, () => property.SetValue(searcher, Enum.ToObject(property.PropertyType, input.Invalid)));
            row.Observe(37, Convert.ToInt32(property.GetValue(searcher)));
            row.Observe(38, Convert.ToInt32(property.GetValue(searcher)));
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> TimeLimits()
    {
        var rows = new List<Sequence>();
        foreach (var name in new[] { "ClientTimeout", "ServerTimeLimit", "ServerPageTimeLimit" })
        {
            using var searcher = new DS.DirectorySearcher();
            var property = typeof(DS.DirectorySearcher).GetProperty(name)!;
            var row = new Sequence();
            foreach (var value in new[] { TimeSpan.FromSeconds(-2), TimeSpan.FromSeconds(-1),
                TimeSpan.Zero, TimeSpan.FromTicks(1), TimeSpan.FromMilliseconds(1500),
                TimeSpan.FromSeconds(int.MaxValue), TimeSpan.FromSeconds((long)int.MaxValue+1), TimeSpan.MaxValue })
            {
                Failure(row, () => property.SetValue(searcher, value));
                // TimeSpan state was redacted at source line 60, so only the
                // exception sequence is compared in this partial adaptation.
            }
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Paging()
    {
        var rows = new List<Sequence>();
        foreach (var pagingFirst in new[] { false, true })
        {
            using var searcher = new DS.DirectorySearcher();
            var sync = new DS.DirectorySynchronization(new byte[] { 0, 255 });
            var row = new Sequence();
            if (pagingFirst)
            {
                searcher.PageSize = 17;
                Failure(row, () => searcher.DirectorySynchronization = sync);
                searcher.PageSize = 0;
                searcher.DirectorySynchronization = sync;
            }
            else
            {
                searcher.DirectorySynchronization = sync;
                Failure(row, () => searcher.PageSize = 17);
                searcher.DirectorySynchronization = null;
                searcher.PageSize = 17;
            }
            // Source lines 82/83/98/99 expected literals are excluded: they
            // are not recorded Microsoft observations at those operand roles.
            row.Observe(104, searcher.PageSize);
            row.Observe(105, searcher.DirectorySynchronization is null);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> CacheIntent()
    {
        var rows = new List<Sequence>();
        foreach (var cacheFirst in new[] { false, true })
        {
            using var searcher = new DS.DirectorySearcher();
            var view = new DS.DirectoryVirtualListView(2, 3, 7);
            var row = new Sequence();
            if (cacheFirst)
            {
                searcher.CacheResults = true;
                Failure(row, () => searcher.VirtualListView = view);
                searcher.CacheResults = false;
                searcher.VirtualListView = view;
            }
            else
            {
                searcher.VirtualListView = view;
                Failure(row, () => searcher.CacheResults = true);
                searcher.VirtualListView = null;
                searcher.CacheResults = true;
            }
            row.Observe(179, searcher.CacheResults);
            row.Observe(180, searcher.VirtualListView is null);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> VlvSetters()
    {
        var rows = new List<Sequence>();
        foreach (var input in new (string Property, int Invalid)[] { ("BeforeCount",-1),
            ("AfterCount",int.MinValue),("Offset",-1),("ApproximateTotal",-1),
            ("TargetPercentage",-1),("TargetPercentage",101) })
        {
            var view = new DS.DirectoryVirtualListView(2,3,7) { ApproximateTotal=100, TargetPercentage=40 };
            var row = new Sequence();
            Failure(row, () => typeof(DS.DirectoryVirtualListView).GetProperty(input.Property)!.SetValue(view,input.Invalid));
            // Constant expected operands at 198-202 are excluded. The admitted
            // Microsoft property reads at 203-207 compare the retained state.
            row.Observe(203,view.BeforeCount);
            row.Observe(204,view.AfterCount);
            row.Observe(205,view.Offset);
            row.Observe(206,view.ApproximateTotal);
            row.Observe(207,view.TargetPercentage);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> RejectedSetters()
    {
        var rows = new List<Sequence>();
        foreach (var property in new[] { "SizeLimit", "PageSize", "AttributeScopeQuery", "SearchScope" })
        {
            using var searcher = new DS.DirectorySearcher();
            Action action;
            switch (property)
            {
                case "PageSize": searcher.PageSize=12; action=()=>searcher.PageSize=-1; break;
                case "SizeLimit": searcher.SizeLimit=12; action=()=>searcher.SizeLimit=-1; break;
                case "AttributeScopeQuery": searcher.SearchScope=DS.SearchScope.OneLevel; action=()=>searcher.AttributeScopeQuery="member"; break;
                default: searcher.AttributeScopeQuery="member"; action=()=>searcher.SearchScope=DS.SearchScope.Subtree; break;
            }
            var error = OfflineTheoryMirrors.Capture(action);
            if (error is not ArgumentException argument) throw new InvalidOperationException("Rejected setter did not produce the source-required ArgumentException");
            var row = new Sequence();
            row.Observe(50,searcher.SizeLimit);
            row.Observe(51,searcher.PageSize);
            row.Observe(53,(int)searcher.SearchScope);
            row.Observe(56,argument.ParamName);
            rows.Add(row);
        }
        return rows;
    }
}
