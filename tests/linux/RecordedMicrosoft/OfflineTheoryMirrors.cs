using System.Globalization;
using System.Text.Json;
using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;

// Source-pinned offline adaptations. The public capture omitted theory inputs;
// compare site-tagged complete scalar sequences as a multiset for each method.
internal static class OfflineTheoryMirrors
{
    internal static IReadOnlyCollection<string> MethodNames { get; private set; } = [];

    internal static TheoryMirrorResult Run()
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Linux only");
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "offline-oracle.json")));
        using var assertions = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "reviewed-assertions-oracle.json")));
        var framework = $"net{Environment.Version.Major}.0-windows";
        var expected = document.RootElement.GetProperty("frameworks").GetProperty(framework).EnumerateObject()
            .Concat(assertions.RootElement.GetProperty("frameworks").GetProperty(framework).EnumerateObject())
            .ToDictionary(property => property.Name, property => property.Value, StringComparer.Ordinal);
        var verified = new HashSet<string>(StringComparer.Ordinal);
        var methods = 0;
        var executions = 0;
        var checks = 0;
        void Verify(string name, List<Sequence> rows)
        {
            if (!verified.Add(name)) throw new InvalidOperationException("Duplicate mirror method: " + name);
            var microsoft = expected[name].EnumerateArray().Select(value => value.GetString()!).Order(StringComparer.Ordinal);
            var linux = rows.Select(row => row.Text).Order(StringComparer.Ordinal);
            if (!microsoft.SequenceEqual(linux, StringComparer.Ordinal))
                throw new InvalidOperationException("Offline recorded method multiset differs: " + name);
            methods++;
            executions += rows.Count;
            checks += rows.Sum(row => row.Count);
        }
        Verify("CompatibilityContextValidationComparisonTests.Full_constructor_local_validation_precedence_matches_microsoft", ContextValidation());
        Verify("CompatibilityContextlessSearcherComparisonTests.Rejected_contextless_filter_assignment_and_followup_match_microsoft", ContextlessSearchers());
        Verify("AdvancedFilterInstanceComparisonTests.Built_in_criteria_can_be_configured_without_an_owner", AdvancedCriteria());
        Verify("AdvancedFiltersOwnerComparisonTests.Protected_constructor_accepts_the_same_owner_values", AdvancedOwners());
        Verify("CompatibilityDisposedEntryValidationComparisonTests.Disposed_entry_and_invalid_argument_precedence_match_microsoft", DisposedEntries());
        Verify("CompatibilityDisposedPropertyContainsComparisonTests.Disposed_owner_and_null_name_validation_have_matching_precedence", DisposedPropertyNames());
        Verify("CompatibilityFailedRefreshWrapperComparisonTests.Failed_refresh_preserves_property_wrapper_like_microsoft", FailedRefreshWrappers());
        Verify("SchemaNameCollectionComparisonTests.Invalid_indexer_exception_type_matches_microsoft", CollectionAssertionMirrors.SchemaIndexes(paired:true));
        ReviewedAssertionMirrors.Run(Verify);
        CollectionAssertionMirrors.Run(Verify);
        if (expected.Count != methods || methods != 22 || executions != 110 || checks != 369)
            throw new InvalidOperationException($"Unexpected offline coverage: {methods}/{executions}/{checks}");
        MethodNames = verified.ToArray();
        return new(methods, executions, checks);
    }

    internal sealed class Sequence
    {
        private readonly List<string> values = new();
        internal int Count => values.Count;
        internal string Text => string.Join(',', values);
        internal void Observe(int line, object? value, bool exceptionType = false)
        {
            var token = value switch
            {
                null => "n",
                bool boolean => boolean ? "b1" : "b0",
                int integer => "i32:" + integer.ToString(CultureInfo.InvariantCulture),
                string name when exceptionType => "e:" + name,
                _ => null, // Non-null parameter/object/type strings were redacted.
            };
            if (token is not null) values.Add(line + "=" + token);
        }
    }

    internal static Exception? Capture(Action action)
    {
        try { action(); return null; }
        catch (Exception error) { return error; }
    }

    private static List<Sequence> ContextValidation()
    {
        const string server = "compatibility-context.invalid";
        var rows = new List<Sequence>();
        foreach (var input in new (int Type, string? Name, int Options, string? User, string? Password)[]
        {
            (999,server,1,null,"synthetic-password"),
            (999,server,1,"synthetic-user",null),
            (999,server,0x400,null,"synthetic-password"),
            (999,server,0,"synthetic-user",null),
            (999,server,0x400,null,null), (999,server,-1,null,null),
            (999,server,0,null,null), (999,server,3,null,null),
            ((int)AM.ContextType.Domain,server,0,null,null),
            ((int)AM.ContextType.Domain,server,3,null,null),
            ((int)AM.ContextType.Domain,server,4,null,null),
            ((int)AM.ContextType.Domain,server,7,null,null),
            ((int)AM.ContextType.Domain,null,1,null,"synthetic-password"),
            ((int)AM.ContextType.Domain,"",1,"synthetic-user",null),
            ((int)AM.ContextType.Domain,null,0x400,null,null),
            ((int)AM.ContextType.Domain,"",0,null,null),
        })
        {
            // Preserve the source guard: every row must reject locally before
            // server verification. Valid contexts must never enter this mirror.
            const int known = (int)(AM.ContextOptions.Negotiate | AM.ContextOptions.SimpleBind |
                AM.ContextOptions.SecureSocketLayer | AM.ContextOptions.Signing |
                AM.ContextOptions.Sealing | AM.ContextOptions.ServerBind);
            var bindModes = input.Options & (int)(AM.ContextOptions.Negotiate | AM.ContextOptions.SimpleBind);
            var rejects = (input.User is null) != (input.Password is null)
                || (input.Options & ~known) != 0
                || !Enum.IsDefined(typeof(AM.ContextType), input.Type)
                || (input.Type == (int)AM.ContextType.Domain && (bindModes == 0 || bindModes == 3));
            if (!rejects) throw new InvalidOperationException("Context row is not admitted for offline execution");
            var error = Capture(() =>
            {
                using var context = new AM.PrincipalContext((AM.ContextType)input.Type, input.Name,
                    null, (AM.ContextOptions)input.Options, input.User, input.Password);
            });
            var row = new Sequence();
            row.Observe(58, error?.GetType().FullName, exceptionType: true);
            row.Observe(59, (error as ArgumentException)?.ParamName);
            rows.Add(row);
        }
        return rows;
    }

    private sealed class Principal : AM.Principal { }
    private sealed class Filters(AM.Principal? owner) : AM.AdvancedFilters(owner!);

    private static List<Sequence> ContextlessSearchers()
    {
        var rows = new List<Sequence>();
        foreach (var member in new[] { "FindOne", "FindAll", "GetUnderlyingSearcher", "GetUnderlyingSearcherType" })
        foreach (var dispose in new[] { false, true })
        {
            using var filter = new Principal();
            using var searcher = new AM.PrincipalSearcher();
            Capture(() => searcher.QueryFilter = filter); // Describe(error) was an opaque tuple.
            var row = new Sequence();
            row.Observe(65, searcher.QueryFilter is null);
            row.Observe(66, searcher.Context is null);
            if (searcher.QueryFilter is not null || searcher.Context is not null)
                throw new InvalidOperationException("Contextless assignment retained unexpected state");
            if (dispose) searcher.Dispose();
            string? nativeType = null;
            Capture(() =>
            {
                switch (member)
                {
                    case "FindOne": using (searcher.FindOne()) { } break;
                    case "FindAll": using (searcher.FindAll()) { } break;
                    case "GetUnderlyingSearcher": nativeType = searcher.GetUnderlyingSearcher().GetType().Name; break;
                    default: nativeType = searcher.GetUnderlyingSearcherType().Name; break;
                }
            }); // Follow-up Describe(error) was also opaque: no exception identity claim.
            row.Observe(108, nativeType);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> AdvancedCriteria()
    {
        var rows = new List<Sequence>();
        foreach (var method in new[] { "LastBadPasswordAttempt", "AccountExpirationDate", "AccountLockoutTime", "BadLogonCount", "LastLogonTime", "LastPasswordSetTime" })
        foreach (var nullOwner in new[] { true, false })
        {
            using var owner = new Principal();
            var filters = new Filters(nullOwner ? null : owner);
            var row = new Sequence();
            foreach (var value in new[] { 3, 7 })
            {
                var date = new DateTime(2030, 1, value, 0, 0, 0, DateTimeKind.Utc);
                var error = Capture(() =>
                {
                    switch (method)
                    {
                        case "LastBadPasswordAttempt": filters.LastBadPasswordAttempt(date, AM.MatchType.Equals); break;
                        case "AccountExpirationDate": filters.AccountExpirationDate(date, AM.MatchType.Equals); break;
                        case "AccountLockoutTime": filters.AccountLockoutTime(date, AM.MatchType.Equals); break;
                        case "BadLogonCount": filters.BadLogonCount(value, AM.MatchType.Equals); break;
                        case "LastLogonTime": filters.LastLogonTime(date, AM.MatchType.Equals); break;
                        case "LastPasswordSetTime": filters.LastPasswordSetTime(date, AM.MatchType.Equals); break;
                    }
                });
                row.Observe(77, error?.GetType().FullName, exceptionType: true);
                row.Observe(78, (error as ArgumentException)?.ParamName);
            }
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> AdvancedOwners()
    {
        var rows = new List<Sequence>();
        foreach (var nullOwner in new[] { true, false })
        {
            using var owner = new Principal();
            var error = Capture(() => _ = new Filters(nullOwner ? null : owner));
            var row = new Sequence();
            row.Observe(23, error?.GetType().FullName, exceptionType: true);
            row.Observe(24, (error as ArgumentException)?.ParamName);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> DisposedEntries()
    {
        var rows = new List<Sequence>();
        foreach (var operation in new[] { "refresh-null", "refresh-null-element", "refresh-empty", "refresh-valid", "move-null-parent", "move-empty-name", "move-whitespace-name", "move-valid-name", "copy-null-parent" })
        {
            using var entry = new DS.DirectoryEntry("LDAP://unused.example.test/CN=source,DC=example,DC=test");
            using var parent = new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test");
            entry.Dispose();
            parent.Dispose();
            var row = new Sequence();
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var error = Capture(() =>
                {
                    switch (operation)
                    {
                        case "refresh-null": entry.RefreshCache(null!); break;
                        case "refresh-null-element": entry.RefreshCache(new string[] { null! }); break;
                        case "refresh-empty": entry.RefreshCache(Array.Empty<string>()); break;
                        case "refresh-valid": entry.RefreshCache(new[] { "description" }); break;
                        case "move-null-parent": entry.MoveTo(null!); break;
                        case "move-empty-name": entry.MoveTo(parent, ""); break;
                        case "move-whitespace-name": entry.MoveTo(parent, " \t "); break;
                        case "move-valid-name": entry.MoveTo(parent, "CN=renamed"); break;
                        case "copy-null-parent": using (entry.CopyTo(null!)) { } break;
                    }
                });
                row.Observe(44, error?.GetType().Name, exceptionType: true);
                row.Observe(45, (error as ArgumentException)?.ParamName);
                row.Observe(47, error?.HResult);
                row.Observe(48, (error as ObjectDisposedException)?.ObjectName);
            }
            // Paths were redacted; do not compare invented string expectations.
            rows.Add(row);
        }
        return rows;
    }
    private static List<Sequence> DisposedPropertyNames()
    {
        var rows = new List<Sequence>();
        foreach (var operation in new[] { "contains-null", "contains-name", "indexer-null" })
        {
            using var entry = new DS.DirectoryEntry();
            var properties = entry.Properties;
            entry.Dispose();
            var error = Capture(() =>
            {
                if (operation == "indexer-null") _ = properties[null!];
                else _ = properties.Contains(operation == "contains-null" ? null! : "description");
            });
            var row = new Sequence();
            row.Observe(37, error?.GetType().FullName, exceptionType: true);
            row.Observe(38, (error as ArgumentException)?.ParamName);
            row.Observe(39, (error as ObjectDisposedException)?.ObjectName);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> FailedRefreshWrappers()
    {
        var rows = new List<Sequence>();
        foreach (var partial in new[] { false, true })
        {
            using var entry = new DS.DirectoryEntry();
            entry.Dispose();
            var original = entry.Properties;
            var row = new Sequence();
            row.Observe(30, ReferenceEquals(original, entry.Properties));
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var before = entry.Properties;
                var error = Capture(() =>
                {
                    if (partial) entry.RefreshCache(new[] { "description" });
                    else entry.RefreshCache();
                });
                var after = entry.Properties;
                row.Observe(49, error?.GetType().Name, exceptionType: true);
                row.Observe(50, error?.HResult);
                row.Observe(51, ReferenceEquals(before, after));
                row.Observe(53, ReferenceEquals(original, after));
                row.Observe(55, ReferenceEquals(after, entry.Properties));
            }
            rows.Add(row);
        }
        return rows;
    }

}

