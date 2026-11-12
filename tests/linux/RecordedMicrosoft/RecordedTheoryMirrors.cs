using System.Reflection;
using DS = AdForLinux.DirectoryServices;

internal readonly record struct TheoryMirrorResult(int Methods, int Executions, int Checks);

// Clone-only replays of offline Windows theories. The public capture omitted
// theory-row identities, so each method is checked as a multiset of complete
// per-row sequences. Non-scalar/redacted observations are deliberately skipped.
internal static class RecordedTheoryMirrors
{
    private static readonly string Framework = $"net{Environment.Version.Major}.0-windows";
    private static int methods;
    private static int executions;
    private static int checks;

    internal static TheoryMirrorResult Run()
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Linux only");
        TimeoutBoundaries();
        CoupledOptions();
        SynchronizationFullWidth();
        SynchronizationCopies();
        SynchronizationResets();
        VlvTransitions();
        VlvRejectedSetters();
        VlvTargets();
        if (methods != 8 || executions != 80 || checks != 1369)
            throw new InvalidOperationException($"Unexpected theory coverage: {methods}/{executions}/{checks}");
        return new(methods, executions, checks);
    }

    private static void Verify(string method, List<Sequence> actual)
    {
        var key = Framework + "|" + method;
        var expected = RecordedTheoryExpectations.Values[key].Order(StringComparer.Ordinal).ToArray();
        var observed = actual.Select(sequence => sequence.Text).Order(StringComparer.Ordinal).ToArray();
        if (!expected.SequenceEqual(observed, StringComparer.Ordinal))
        {
            var expectedCounts = expected.GroupBy(value => value).ToDictionary(group => group.Key, group => group.Count());
            var observedCounts = observed.GroupBy(value => value).ToDictionary(group => group.Key, group => group.Count());
            var missing = expectedCounts.Where(pair => observedCounts.GetValueOrDefault(pair.Key) != pair.Value).Take(2);
            var extra = observedCounts.Where(pair => expectedCounts.GetValueOrDefault(pair.Key) != pair.Value).Take(2);
            throw new InvalidOperationException($"Recorded theory multiset differs: {key}; missing={string.Join(" || ", missing.Select(pair => pair.Value + "x " + pair.Key))}; extra={string.Join(" || ", extra.Select(pair => pair.Value + "x " + pair.Key))}");
        }
        methods++;
        executions += actual.Count;
        checks += actual.Sum(sequence => sequence.Count);
    }

    private sealed class Sequence
    {
        private readonly List<string> values = new();
        internal int Count => values.Count;
        internal string Text => string.Join(',', values);

        internal void Value(object? value)
        {
            switch (value)
            {
                case null: values.Add("n"); break;
                case bool boolean: values.Add(boolean ? "b1" : "b0"); break;
                case int integer: values.Add("i32:" + integer); break;
                case long integer: values.Add("i64:" + integer); break;
                // Ordinary strings were redacted from the public capture.
            }
        }

        internal void Exception(Action action, bool unwrapReflection = false)
        {
            Exception? error = null;
            try { action(); }
            catch (Exception ex) { error = ex; }
            if (unwrapReflection && error is TargetInvocationException invocation) error = invocation.InnerException;
            values.Add(error is null ? "n" : "e:" + error.GetType().FullName);
            Value((error as ArgumentException)?.ParamName);
        }
    }

    private static void TimeoutBoundaries()
    {
        const string method = "CompatibilitySearcherStateComparisonTests.Timeout_boundary_rejection_and_recovery_match_microsoft";
        var rows = new List<Sequence>();
        foreach (var property in new[] { "ClientTimeout", "ServerTimeLimit", "ServerPageTimeLimit" })
        foreach (var ticks in new[]
        {
            long.MinValue, -TimeSpan.TicksPerSecond - 1, -TimeSpan.TicksPerSecond, -1L, 0L, 1L,
            (long)int.MaxValue * TimeSpan.TicksPerSecond - 1,
            (long)int.MaxValue * TimeSpan.TicksPerSecond,
            (long)int.MaxValue * TimeSpan.TicksPerSecond + 1,
            (long)int.MaxValue * TimeSpan.TicksPerSecond + TimeSpan.TicksPerSecond,
            long.MaxValue,
        })
        {
            using var ours = new DS.DirectorySearcher();
            var propertyInfo = typeof(DS.DirectorySearcher).GetProperty(property)!;
            propertyInfo.SetValue(ours, TimeSpan.FromSeconds(7));
            var row = new Sequence();
            row.Exception(() => propertyInfo.SetValue(ours, TimeSpan.FromTicks(ticks)), unwrapReflection: true);
            row.Value(((TimeSpan)propertyInfo.GetValue(ours)!).Ticks);
            row.Exception(() => propertyInfo.SetValue(ours, TimeSpan.FromTicks(12345678)), unwrapReflection: true);
            row.Value(((TimeSpan)propertyInfo.GetValue(ours)!).Ticks);
            rows.Add(row);
        }
        Verify(method, rows);
    }

    private static void CoupledOptions()
    {
        const string method = "CompatibilitySearcherStateComparisonTests.Coupled_options_preserve_state_through_rejection_and_reset";
        var rows = new List<Sequence>();
        foreach (var scenario in new[] { "implicit-cache", "explicit-cache", "scope-reset", "scope-rejected", "sync-first", "page-first" })
        {
            using var ours = new DS.DirectorySearcher();
            var view = new DS.DirectoryVirtualListView(2);
            var sync = new DS.DirectorySynchronization(new byte[] { 4, 5 });
            var row = new Sequence();
            void Step(string name, Action action)
            {
                row.Exception(action);
                row.Value(ours.CacheResults);
                row.Value((int)ours.SearchScope);
                row.Value(ours.AttributeScopeQuery);
                row.Value(ours.PageSize);
                row.Value(ours.VirtualListView is not null);
                row.Value(ReferenceEquals(view, ours.VirtualListView));
                row.Value(ReferenceEquals(sync, ours.DirectorySynchronization));
            }
            if (scenario.EndsWith("cache", StringComparison.Ordinal))
            {
                if (scenario == "explicit-cache") Step("explicit default", () => ours.CacheResults = true);
                Step("assign VLV", () => ours.VirtualListView = view);
                Step("enable cache", () => ours.CacheResults = true);
                Step("clear VLV", () => ours.VirtualListView = null);
                Step("disable cache", () => ours.CacheResults = false);
                Step("reassign VLV", () => ours.VirtualListView = view);
            }
            else if (scenario.StartsWith("scope", StringComparison.Ordinal))
            {
                if (scenario == "scope-rejected") Step("explicit default", () => ours.SearchScope = DS.SearchScope.Subtree);
                Step("set attribute", () => ours.AttributeScopeQuery = "member");
                Step("clear attribute", () => ours.AttributeScopeQuery = null);
                Step("scope one level", () => ours.SearchScope = DS.SearchScope.OneLevel);
                Step("rejected attribute", () => ours.AttributeScopeQuery = "member");
                Step("scope base", () => ours.SearchScope = DS.SearchScope.Base);
                Step("recovered attribute", () => ours.AttributeScopeQuery = "member");
            }
            else
            {
                if (scenario == "page-first") Step("initial paging", () => ours.PageSize = 5);
                Step("set sync", () => ours.DirectorySynchronization = sync);
                Step("set paging", () => ours.PageSize = 5);
                Step("clear paging", () => ours.PageSize = 0);
                Step("retry sync", () => ours.DirectorySynchronization = sync);
                Step("clear sync", () => ours.DirectorySynchronization = null);
                Step("recovered paging", () => ours.PageSize = 5);
            }
            rows.Add(row);
        }
        Verify(method, rows);
    }

    private static void SynchronizationFullWidth()
    {
        const string method = "CompatibilitySynchronizationComparisonTests.Full_width_option_validation_matches_for_constructors_and_setter";
        var rows = new List<Sequence>();
        foreach (var option in new[] { 0L, 0x800L, 0x2000L, 0x80000000L, 0x2801L, 0x80002801L, 2L, 0x80002803L, 0x100000000L, -2147483648L, long.MinValue, long.MaxValue })
        {
            var row = new Sequence();
            DS.DirectorySynchronization? actual = null;
            row.Exception(() => actual = new DS.DirectorySynchronization((DS.DirectorySynchronizationOptions)option));
            row.Value(actual is not null);
            if (actual is not null) SyncState(row, actual);
            actual = null;
            row.Exception(() => actual = new DS.DirectorySynchronization((DS.DirectorySynchronizationOptions)option, new byte[] { 0, 127, 255 }));
            row.Value(actual is not null);
            if (actual is not null) SyncState(row, actual);
            actual = new DS.DirectorySynchronization(DS.DirectorySynchronizationOptions.ObjectSecurity, new byte[] { 4, 5 });
            row.Exception(() => actual.Option = (DS.DirectorySynchronizationOptions)option);
            SyncState(row, actual);
            rows.Add(row);
        }
        Verify(method, rows);
    }

    private static void SynchronizationCopies()
    {
        const string method = "CompatibilitySynchronizationComparisonTests.Copies_preserve_options_and_isolate_later_mutations";
        var rows = new List<Sequence>();
        foreach (var useCopyMethod in new[] { false, true })
        foreach (var emptyCookie in new[] { false, true })
        {
            var source = new DS.DirectorySynchronization(DS.DirectorySynchronizationOptions.ParentsFirst,
                emptyCookie ? Array.Empty<byte>() : new byte[] { 1, 2, 255 });
            var copy = useCopyMethod ? source.Copy() : new DS.DirectorySynchronization(source);
            var row = new Sequence();
            row.Value(ReferenceEquals(source, copy));
            SyncState(row, copy);
            source.Option = DS.DirectorySynchronizationOptions.PublicDataOnly;
            source.ResetDirectorySynchronizationCookie(new byte[] { 8, 9 });
            SyncState(row, copy);
            copy.Option = DS.DirectorySynchronizationOptions.IncrementalValues;
            copy.ResetDirectorySynchronizationCookie(new byte[] { 3, 4, 5 });
            SyncState(row, source);
            SyncState(row, copy);
            copy.GetDirectorySynchronizationCookie()[0] = 99;
            SyncState(row, copy);
            SyncState(row, source);
            rows.Add(row);
        }
        Verify(method, rows);
    }

    private static void SynchronizationResets()
    {
        const string method = "CompatibilitySynchronizationComparisonTests.Reset_preserves_options_and_detaches_cookie_buffers";
        var rows = new List<Sequence>();
        foreach (var reset in new[] { "parameterless", "null", "empty", "nonempty" })
        {
            var actual = new DS.DirectorySynchronization(DS.DirectorySynchronizationOptions.IncrementalValues, new byte[] { 1, 2 });
            var old = actual.GetDirectorySynchronizationCookie();
            byte[]? input = reset == "null" ? null : reset == "empty" ? Array.Empty<byte>() : new byte[] { 7, 8, 9 };
            if (reset == "parameterless") actual.ResetDirectorySynchronizationCookie();
            else actual.ResetDirectorySynchronizationCookie(input);
            var row = new Sequence();
            SyncState(row, actual);
            old[0] = 44;
            if (input is { Length: > 0 }) input[0] = 55;
            SyncState(row, actual);
            actual.ResetDirectorySynchronizationCookie(new byte[] { 10, 11 });
            SyncState(row, actual);
            rows.Add(row);
        }
        Verify(method, rows);
    }

    private static void SyncState(Sequence row, DS.DirectorySynchronization value)
    {
        row.Value((long)value.Option);
        row.Value(Convert.ToHexString(value.GetDirectorySynchronizationCookie()));
    }

    private static void VlvTransitions()
    {
        const string method = "CompatibilityVlvStateComparisonTests.Percentage_offset_and_total_transitions_match_microsoft";
        var rows = new List<Sequence>();
        foreach (var input in new (int Total, int Percentage, int Offset)[] { (0,50,0),(1,100,1),(3,33,2),(13,15,2),(101,99,100),(100,100,101),(21474836,100,21474836),(21474837,100,21474837),(int.MaxValue,99,int.MaxValue),(1,50,int.MaxValue) })
        {
            var view = new DS.DirectoryVirtualListView(2, 3, "seed");
            var row = new Sequence();
            void Step(Action action) { row.Exception(action); VlvState(row, view); }
            Step(() => view.ApproximateTotal = input.Total);
            Step(() => view.TargetPercentage = input.Percentage);
            Step(() => view.Offset = input.Offset);
            Step(() => view.ApproximateTotal = 7);
            Step(() => view.ApproximateTotal = 0);
            Step(() => view.Offset = input.Offset);
            Step(() => view.TargetPercentage = input.Percentage);
            rows.Add(row);
        }
        Verify(method, rows);
    }

    private static void VlvRejectedSetters()
    {
        const string method = "CompatibilityVlvStateComparisonTests.Rejected_setter_preserves_all_existing_state_like_microsoft";
        var rows = new List<Sequence>();
        foreach (var input in new (string Property, int Value)[] { ("BeforeCount",-1),("BeforeCount",int.MinValue),("AfterCount",-1),("AfterCount",int.MinValue),("Offset",int.MinValue),("ApproximateTotal",int.MinValue),("TargetPercentage",int.MinValue),("TargetPercentage",int.MaxValue) })
        {
            var view = new DS.DirectoryVirtualListView(2, 3, "seed") { ApproximateTotal = 101, TargetPercentage = 67 };
            var row = new Sequence();
            row.Exception(() => Set());
            VlvState(row, view);
            row.Exception(() => view.Offset = 9);
            VlvState(row, view);
            rows.Add(row);
            void Set()
            {
                switch (input.Property)
                {
                    case "BeforeCount": view.BeforeCount = input.Value; break;
                    case "AfterCount": view.AfterCount = input.Value; break;
                    case "Offset": view.Offset = input.Value; break;
                    case "ApproximateTotal": view.ApproximateTotal = input.Value; break;
                    case "TargetPercentage": view.TargetPercentage = input.Value; break;
                }
            }
        }
        Verify(method, rows);
    }

    private static void VlvTargets()
    {
        const string method = "CompatibilityVlvStateComparisonTests.Target_changes_preserve_position_and_context_like_microsoft";
        var rows = new List<Sequence>();
        foreach (var target in new string?[] { null, "", "  é\0target  " })
        {
            var context = new DS.DirectoryVirtualListViewContext();
            var view = new DS.DirectoryVirtualListView(2, 3, 11, context) { ApproximateTotal = 17 };
            var row = new Sequence();
            row.Exception(() => view.Target = target!);
            VlvState(row, view);
            row.Value(ReferenceEquals(context, view.DirectoryVirtualListViewContext));
            row.Exception(() => view.Offset = 7);
            VlvState(row, view);
            rows.Add(row);
        }
        Verify(method, rows);
    }

    private static void VlvState(Sequence row, DS.DirectoryVirtualListView view)
    {
        row.Value(view.BeforeCount);
        row.Value(view.AfterCount);
        row.Value(view.Offset);
        row.Value(view.ApproximateTotal);
        row.Value(view.TargetPercentage);
        row.Value(view.Target);
        row.Value(view.DirectoryVirtualListViewContext is null);
    }
}
