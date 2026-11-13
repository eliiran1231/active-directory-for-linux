using AM = AdForLinux.DirectoryServices.AccountManagement;
using Sequence = OfflineTheoryMirrors.Sequence;

// Only the source helper's pre-search exception outcome is public evidence.
// Filter strings and successful search phases are excluded. Referential
// guards deliberately call search APIs only to require rejection before I/O.
internal static class QueryTranslationMirrors
{
    private static AM.PrincipalContext Context() => new(AM.ContextType.Domain,
        "unused.example.test", "DC=example,DC=test",
        AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer, null, null);

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("PrincipalSearcherReferentialComparisonTests.Changed_group_members_QBE_exception_matches_in_an_isolated_OU", ReferentialGuard());
        verify("PrincipalSearcherComparisonTests.Extension_QBE_converters_and_null_behavior_match", Extensions());
        verify("PrincipalSearcherComparisonTests.Null_and_cleared_high_value_QBE_properties_match", NullAssignments());
        verify("PrincipalSearcherComparisonTests.Account_expiration_and_null_QBE_filters_match", Expiration());
        verify("PrincipalSearcherComparisonTests.Unsupported_user_cannot_change_password_QBE_exception_matches", Unsupported());
        verify("PrincipalSearcherComparisonTests.User_account_control_QBE_filters_match", AccountFlags());
        verify("PrincipalSearcherComparisonTests.Group_QBE_filters_match", Groups());
    }

    private static List<Sequence> ReferentialGuard()
    {
        using var context=Context();
        using var member=new AM.UserPrincipal(context) { SamAccountName="guard-member" };
        using var group=new AM.GroupPrincipal(context)
        {
            GroupScope=AM.GroupScope.Global,
            IsSecurityGroup=true,
        };
        if (member.IsPersisted || group.IsPersisted)
            throw new InvalidOperationException("Only unsaved guard fixtures are admitted");
        _=group.Members;
        using var searcher=new AM.PrincipalSearcher(group);
        if (searcher.GetUnderlyingSearcher() is not AdForLinux.DirectoryServices.DirectorySearcher)
            throw new InvalidOperationException("Clean native-searcher control failed");
        group.Members.Add(member);
        var row=new Sequence();
        foreach (var operation in new Action[] {
                     () => _=searcher.GetUnderlyingSearcher(),
                     () => { using var result=searcher.FindOne(); },
                     () => { using var results=searcher.FindAll(); } })
        {
            var error=OfflineTheoryMirrors.Capture(operation);
            row.Observe(96,error?.GetType().Name,exceptionType:true);
        }
        return [row];
    }

    [AM.DirectoryObjectClass("user")]
    [AM.DirectoryRdnPrefix("CN")]
    private sealed class ExtensionUser(AM.PrincipalContext context) : AM.UserPrincipal(context)
    {
        internal void Write(string attribute,object? value) => ExtensionSet(attribute,value);
    }

    private static List<Sequence> Extensions()
    {
        using var context=Context();
        var row=new Sequence();
        foreach (var value in new object?[] { "differential test user",true,
                     new DateTime(2030,6,1,12,0,0,DateTimeKind.Utc),
                     new object[] { "one","two" },new byte[] { 1,2 },null })
        {
            using var user=new ExtensionUser(context);
            var setError=OfflineTheoryMirrors.Capture(() => user.Write("extensionAttribute1",value));
            // Preserve the source control flow; setter observations are not
            // admitted by this partial translation-only projection.
            if (setError is not null) continue;
            using var searcher=new AM.PrincipalSearcher(user);
            string? text=null;
            var error=OfflineTheoryMirrors.Capture(() => text=searcher.GetLdapFilter());
            row.Observe(460,error?.GetType().Name,exceptionType:true);
            row.Observe(461,text); // Only null survived public sanitization.
        }
        return [row];
    }

    private static List<Sequence> NullAssignments()
    {
        using var context=Context();
        using var user=new AM.UserPrincipal(context);
        using var group=new AM.GroupPrincipal(context);
        var row=new Sequence();
        row.Observe(377,OfflineTheoryMirrors.Capture(() => user.Enabled=null)?.GetType().Name,exceptionType:true);
        row.Observe(408,OfflineTheoryMirrors.Capture(() => group.GroupScope=null)?.GetType().Name,exceptionType:true);
        row.Observe(411,OfflineTheoryMirrors.Capture(() => group.IsSecurityGroup=null)?.GetType().Name,exceptionType:true);
        return [row];
    }

    private static Sequence Translate(AM.Principal filter)
    {
        var row = new Sequence();
        row.Observe(460,TranslationError(filter)?.GetType().Name,exceptionType:true);
        return row;
    }

    private static Exception? TranslationError(AM.Principal filter)
    {
        if (filter.IsPersisted) throw new InvalidOperationException("Only unsaved query examples are admitted");
        using var searcher=new AM.PrincipalSearcher(filter);
        return OfflineTheoryMirrors.Capture(() => searcher.GetLdapFilter());
    }

    private static List<Sequence> Expiration()
    {
        var row=new Sequence();
        // Public fixed value in the source-pinned TestDataFixture property;
        // the original fixture itself is never instantiated here.
        foreach (var expiration in new DateTime?[] { new(2030,6,1,12,0,0,DateTimeKind.Utc),null })
        {
            using var context=Context();
            using var user=new AM.UserPrincipal(context) { AccountExpirationDate=expiration };
            row.Observe(460,TranslationError(user)?.GetType().Name,exceptionType:true);
        }
        return [row];
    }

    private static List<Sequence> Unsupported()
    {
        using var context=Context();
        using var user=new AM.UserPrincipal(context) { UserCannotChangePassword=true };
        if (user.IsPersisted) throw new InvalidOperationException("Only unsaved query examples are admitted");
        using var searcher=new AM.PrincipalSearcher(user);
        string? text=null;
        var error=OfflineTheoryMirrors.Capture(() => text=searcher.GetLdapFilter());
        var row=new Sequence();
        row.Observe(460,error?.GetType().Name,exceptionType:true);
        row.Observe(461,text);
        return [row];
    }

    private static List<Sequence> AccountFlags()
    {
        var rows=new List<Sequence>();
        foreach (var property in new[] { "Enabled","SmartcardLogonRequired","DelegationPermitted",
                     "PasswordNotRequired","PasswordNeverExpires","AllowReversiblePasswordEncryption" })
        foreach (var value in new[] { true,false })
        {
            using var context=Context();
            using var user=new AM.UserPrincipal(context);
            typeof(AM.UserPrincipal).GetProperty(property)!.SetValue(user,value);
            rows.Add(Translate(user));
        }
        return rows;
    }

    private static List<Sequence> Groups()
    {
        var rows=new List<Sequence>();
        foreach (var (scope,security) in new[] {
                     (AM.GroupScope.Local,true),(AM.GroupScope.Global,true),
                     (AM.GroupScope.Universal,true),(AM.GroupScope.Global,false) })
        {
            using var context=Context();
            using var group=new AM.GroupPrincipal(context) { GroupScope=scope,IsSecurityGroup=security };
            rows.Add(Translate(group));
        }
        return rows;
    }
}
