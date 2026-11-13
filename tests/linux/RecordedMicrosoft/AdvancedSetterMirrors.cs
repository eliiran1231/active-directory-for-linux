using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Only helper calls carrying Microsoft setter errors are oracle observations.
// Literal-null translation controls are excluded by reviewed record identities.
internal static class AdvancedSetterMirrors
{
    private sealed class Filters(AM.Principal owner) : AM.AdvancedFilters(owner)
    {
        internal void Set(string attribute,object value,Type declaredType,AM.MatchType match) =>
            AdvancedFilterSet(attribute,value,declaredType,match);
    }

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var scenario in new[] { "boolean-true","boolean-false","date-declared-date",
                     "date-declared-object","string-array","integer-array-range","scalar-string",
                     "byte-array","value-type-array","array-list" })
        {
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,
                "unused.example.test","DC=example,DC=test",
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            using var owner=new AM.UserPrincipal(context);
            if (owner.IsPersisted) throw new InvalidOperationException("Only unsaved advanced-filter owners are admitted");
            var filters=new Filters(owner);
            using var searcher=new AM.PrincipalSearcher(owner);
            var (attribute,value,declaredType,range)=Input(scenario);
            var row=new Sequence();
            ObserveSetter(row,() => filters.Set(attribute,value,declaredType,
                range ? AM.MatchType.GreaterThanOrEquals : AM.MatchType.Equals));
            var initial=ReadFilter(searcher);
            RequireContains(initial,attribute);
            ObserveSetter(row,() => filters.Set(attribute,"advanced-recovery",typeof(string),AM.MatchType.Equals));
            var replacement=ReadFilter(searcher);
            RequireContains(replacement,attribute);
            RequireContains(replacement,"advanced-recovery");
            if (initial==replacement) throw new InvalidOperationException("Advanced replacement control did not change the local filter");
            // These local source-required readiness controls are not recorded
            // filter-string comparisons and do not add to the observation count.
            rows.Add(row);
        }
        verify("CompatibilityAdvancedExtensionQueryComparisonTests.Custom_advanced_filter_conversion_and_replacement_match_microsoft",rows);
    }

    private static void ObserveSetter(Sequence row,Action action)
    {
        var error=OfflineTheoryMirrors.Capture(action);
        row.Observe(109,error?.GetType().Name,exceptionType:true);
        row.Observe(110,(error as ArgumentException)?.ParamName);
    }

    private static string ReadFilter(AM.PrincipalSearcher searcher) =>
        ((DS.DirectorySearcher)searcher.GetUnderlyingSearcher()).Filter;

    private static void RequireContains(string filter,string fragment)
    {
        if (string.IsNullOrEmpty(filter) || !filter.Contains(fragment,StringComparison.Ordinal))
            throw new InvalidOperationException("Local advanced-filter readiness control failed");
    }

    private static (string,object,Type,bool) Input(string scenario) => scenario switch
    {
        "boolean-true" => ("msNPAllowDialin",true,typeof(bool),false),
        "boolean-false" => ("msNPAllowDialin",false,typeof(bool),false),
        "date-declared-date" => ("accountExpires",new DateTime(2030,6,1,12,0,0,DateTimeKind.Utc),typeof(DateTime),false),
        "date-declared-object" => ("accountExpires",new DateTime(2030,6,1,12,0,0,DateTimeKind.Utc),typeof(object),false),
        "string-array" => ("otherTelephone",new object[] { "555-0101","555-0102" },typeof(string),false),
        "integer-array-range" => ("badPwdCount",new object[] { 2,5 },typeof(int),true),
        "scalar-string" => ("description","initial-control",typeof(string),false),
        "byte-array" => ("description",new byte[] { 1,2 },typeof(byte[]),false),
        "value-type-array" => ("description",new int[] { 2,5 },typeof(int[]),false),
        "array-list" => ("description",new System.Collections.ArrayList { "one","two" },typeof(object),false),
        _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
    };
}
