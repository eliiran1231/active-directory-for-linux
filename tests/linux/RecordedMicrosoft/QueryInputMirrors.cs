using AM = AdForLinux.DirectoryServices.AccountManagement;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

// Recorded error outcomes only; Microsoft filter strings were redacted.
internal static class QueryInputMirrors
{
    [AM.DirectoryObjectClass("user")]
    private sealed class ExtensionUser(AM.PrincipalContext context) : AM.UserPrincipal(context)
    {
        internal void Write(string value) => ExtensionSet("description",value);
    }

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        var rows=new List<Sequence>();
        foreach (var (property,pattern) in new (string,string)[] {
                     ("displayName", "team*"),
                     ("displayName", @"team\*"),
                     ("displayName", @"team\\*"),
                     ("displayName", @"team\q"),
                     ("displayName", @"team\"),
                     ("displayName", "(team)"),
                     ("displayName", @"\28team\29"),
                     ("displayName", @"\(team\)"),
                     ("workstations", @"DESK\*"),
                     ("workstations", @"lab\\box"),
                     ("servicePrincipalNames", @"HTTP/host\*"),
                     ("servicePrincipalNames", @"HTTP/host\\name"),
                     ("extension", @"team\*"),
                     ("extension", @"team\\name") })
        {
            using var context=new AM.PrincipalContext(AM.ContextType.Domain,
                "unused.example.test","DC=example,DC=test",
                AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);
            using AM.Principal principal=property switch
            {
                "servicePrincipalNames" => new AM.ComputerPrincipal(context),
                "extension" => new ExtensionUser(context),
                _ => new AM.UserPrincipal(context),
            };
            if (principal.IsPersisted) throw new InvalidOperationException("Only unsaved query inputs are admitted");
            using var searcher=new AM.PrincipalSearcher(principal);
            var row=new Sequence();
            for (var step=0;step<2;step++)
            {
                var value=step==0 ? pattern : "plain-recovery";
                var setterError=OfflineTheoryMirrors.Capture(() => Set(principal,property,value));
                Observe(row,setterError);
                string? filter=null;
                var buildError=OfflineTheoryMirrors.Capture(() =>
                    filter=((DS.DirectorySearcher)searcher.GetUnderlyingSearcher()).Filter);
                Observe(row,buildError);
                if (step==1 && (setterError is not null || buildError is not null
                        || filter is null || !filter.Contains("plain-recovery",StringComparison.Ordinal)))
                    throw new InvalidOperationException("Local replacement translation control failed");
                // The replacement check is a local source control, not an
                // unavailable comparison against the redacted Microsoft filter.
            }
            rows.Add(row);
        }
        verify("CompatibilityQueryEscapingComparisonTests.Papi_quoted_values_and_subsequent_replacement_match_microsoft",rows);
    }

    private static void Observe(Sequence row,Exception? error)
    {
        row.Observe(116,error?.GetType().Name,exceptionType:true);
        row.Observe(117,(error as ArgumentException)?.ParamName);
    }

    private static void Set(AM.Principal principal, string property, string value)
    {
        switch (property)
        {
            case "displayName": principal.DisplayName = value; break;
            case "workstations":
                var workstations = ((AM.UserPrincipal)principal).PermittedWorkstations;
                workstations.Clear(); workstations.Add(value); break;
            case "servicePrincipalNames":
                var names = ((AM.ComputerPrincipal)principal).ServicePrincipalNames;
                names.Clear(); names.Add(value); break;
            case "extension": ((ExtensionUser)principal).Write(value); break;
            default: throw new ArgumentOutOfRangeException(nameof(property));
        }
    }


}
