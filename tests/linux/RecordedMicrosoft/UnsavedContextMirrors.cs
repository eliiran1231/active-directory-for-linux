using AM = AdForLinux.DirectoryServices.AccountManagement;
using Sequence = OfflineTheoryMirrors.Sequence;

// The Windows sources construct live lab contexts. These partial adaptations
// compare only unsaved local state using a normal configured synthetic context.
// No context binding, Save, persisted identity, or transport behavior is claimed.
internal static class UnsavedContextMirrors
{
    private static AM.PrincipalContext Context() => new(AM.ContextType.Domain,
        "unused.example.test","DC=example,DC=test",
        AM.ContextOptions.SimpleBind | AM.ContextOptions.SecureSocketLayer,null,null);

    private static void RequireUnsaved(AM.Principal principal)
    {
        if (principal.IsPersisted) throw new InvalidOperationException("Only unsaved principals are admitted to the offline context adapter");
    }

    internal static void Run(Action<string,List<Sequence>> verify)
    {
        verify("PrincipalBehaviorComparisonTests.Required_name_setter_validation_matches_microsoft_across_principal_states", NameStates());
        verify("PrincipalBehaviorComparisonTests.GetGroups_with_context_matches_for_unsaved_principals", UnsavedGroups());
        verify("PrincipalBehaviorComparisonTests.Password_members_match_for_unsaved_principals", PasswordFlags());
        verify("UnsavedAccountStateComparisonTests.Unassigned_delegation_permission_matches_microsoft", Delegation());
        verify("UnsavedAccountStateComparisonTests.Setting_an_account_flag_preserves_unassigned_enabled_state", AccountFlags());
        verify("NextBatchPrincipalStateComparisonTests.Group_scope_validation_timing_and_retained_value_match", ScopeValues());
        verify("NextBatchPrincipalStateComparisonTests.Unsaved_group_scope_and_security_have_independent_assignment_state", GroupAssignments());
        verify("CompatibilityUnsavedUnlockComparisonTests.Unlock_unsaved_user_matches_noop_or_disposed_guard", UnsavedUnlock());
        verify("CompatibilityAuthenticableCredentialConstructorComparisonTests.Protected_credential_constructor_initializes_only_supplied_properties", CredentialConstructors());
        verify("NextBatchMembershipComparisonTests.Unsaved_member_operations_do_not_require_a_directory_identity", Membership());
    }

    private static List<Sequence> NameStates()
    {
        using var context=Context();
        var row=new Sequence();
        using (var user=new AM.UserPrincipal(context))
        {
            RequireUnsaved(user);
            user.Name=" ";
            user.SamAccountName="\t";
            user.Description=null;
            row.Observe(114,user.Description);
        }
        using var disposed=new AM.UserPrincipal(context);
        RequireUnsaved(disposed);
        disposed.Dispose();
        row.Observe(133,OfflineTheoryMirrors.Capture(() => disposed.Name="valid")?.GetType().Name,exceptionType:true);
        row.Observe(136,OfflineTheoryMirrors.Capture(() => disposed.SamAccountName="valid")?.GetType().Name,exceptionType:true);
        return [row];
    }

    private static List<Sequence> UnsavedGroups()
    {
        using var context=Context();
        using var user=new AM.UserPrincipal(context);
        RequireUnsaved(user);
        var error=OfflineTheoryMirrors.Capture(() =>
        {
            using var groups=user.GetGroups(context);
            _=groups.Select(group => group.DistinguishedName).ToArray();
        });
        var row=new Sequence();
        row.Observe(354,error?.GetType().FullName,exceptionType:true);
        return [row];
    }

    private static List<Sequence> PasswordFlags()
    {
        using var context=Context();
        using var computer=new AM.ComputerPrincipal(context);
        RequireUnsaved(computer);
        var row=new Sequence();
        row.Observe(371,computer.UserCannotChangePassword);
        computer.UserCannotChangePassword=true;
        row.Observe(374,computer.UserCannotChangePassword);
        // Source ChangePassword assertions have no admitted observations.
        return [row];
    }

    private static List<Sequence> Delegation()
    {
        var rows=new List<Sequence>();
        foreach (var computer in new[] { false,true })
        {
            using var context=Context();
            using AM.AuthenticablePrincipal principal=computer
                ? new AM.ComputerPrincipal(context) : new AM.UserPrincipal(context);
            RequireUnsaved(principal);
            if (principal.Enabled is not null) throw new InvalidOperationException("Unsaved Enabled control changed");
            var row=new Sequence();
            row.Observe(172,principal.DelegationPermitted);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> AccountFlags()
    {
        var rows=new List<Sequence>();
        foreach (var property in new[] { "PasswordNeverExpires","PasswordNotRequired","SmartcardLogonRequired",
                     "AllowReversiblePasswordEncryption","DelegationPermitted" })
        foreach (var value in new[] { false,true })
        {
            using var context=Context();
            using var user=new AM.UserPrincipal(context);
            RequireUnsaved(user);
            if (user.Enabled is not null) throw new InvalidOperationException("Unsaved Enabled control changed");
            var member=typeof(AM.UserPrincipal).GetProperty(property)!;
            member.SetValue(user,value);
            var row=new Sequence();
            // Source line 65's actual operand reads Microsoft. Its expected
            // operand is a literal input; line 66 observes only the clone.
            row.Observe(65,member.GetValue(user));
            foreach (var enabled in new[] { false,true })
            {
                user.Enabled=enabled;
                member.SetValue(user,!value);
            }
            // The source's final Enabled sequence is opaque in the capture.
            RequireUnsaved(user);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> ScopeValues()
    {
        var rows=new List<Sequence>();
        foreach (var value in new[] { -1,3,int.MaxValue,1 })
        {
            using var context=Context();
            using var group=new AM.GroupPrincipal(context) { GroupScope=AM.GroupScope.Global };
            RequireUnsaved(group);
            OfflineTheoryMirrors.Capture(() => group.GroupScope=(AM.GroupScope)value);
            var row=new Sequence();
            row.Observe(86,(int?)group.GroupScope);
            group.GroupScope=AM.GroupScope.Universal;
            row.Observe(91,(int?)group.GroupScope);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> GroupAssignments()
    {
        var rows=new List<Sequence>();
        foreach (var setScope in new[] { false,true })
        foreach (var setSecurity in new[] { false,true })
        {
            using var context=Context();
            using var group=new AM.GroupPrincipal(context);
            RequireUnsaved(group);
            if (setScope) group.GroupScope=AM.GroupScope.Universal;
            if (setSecurity) group.IsSecurityGroup=false;
            var row=new Sequence();
            row.Observe(112,(int?)group.GroupScope);
            row.Observe(113,group.IsSecurityGroup);
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> UnsavedUnlock()
    {
        var rows=new List<Sequence>();
        foreach (var disposed in new[] { false,true })
        {
            using var context=Context();
            using var user=new AM.UserPrincipal(context);
            RequireUnsaved(user);
            if (user.Guid is not null || user.DistinguishedName is not null || user.IsAccountLockedOut())
                throw new InvalidOperationException("The unsaved unlock fixture has unexpected persisted state");
            if (disposed) user.Dispose();
            var row=new Sequence();
            for (var attempt=0;attempt<2;attempt++)
            {
                // UnlockAccount returns before its directory path when Entry is
                // null. The guard above forbids persisted objects in this test.
                var error=OfflineTheoryMirrors.Capture(user.UnlockAccount);
                row.Observe(53,error?.GetType().Name,exceptionType:true);
                row.Observe(54,(error as ArgumentException)?.ParamName);
                RequireUnsaved(user);
                if (!disposed && (user.Guid is not null || user.DistinguishedName is not null || user.IsAccountLockedOut()))
                    throw new InvalidOperationException("Unsaved unlock unexpectedly changed persistence state");
            }
            rows.Add(row);
        }
        return rows;
    }

    [AM.DirectoryObjectClass("user")]
    [AM.DirectoryRdnPrefix("CN")]
    private sealed class CredentialPrincipal : AM.AuthenticablePrincipal
    {
        internal CredentialPrincipal(AM.PrincipalContext context) : base(context) { }
        internal CredentialPrincipal(AM.PrincipalContext context,string? sam,string? password)
            : base(context,sam!,password!,false) { }
    }

    private static List<Sequence> CredentialConstructors()
    {
        // Public synthetic literals from the pinned source; the password stays
        // staged in an unsaved object and is never transmitted or logged.
        const string accountName="compat-ctor-staged";
        const string stagedPassword="Str0ng!Passw0rd#2026";
        var rows=new List<Sequence>();
        foreach (var scenario in new[] { "missing-credentials","credentials","explicit-assignment-control" })
        {
            using var context=Context();
            CredentialPrincipal? principal=null;
            try
            {
                var error=OfflineTheoryMirrors.Capture(() =>
                {
                    if (scenario=="missing-credentials") principal=new(context,null,null);
                    else if (scenario=="credentials") principal=new(context,accountName,stagedPassword);
                    else
                    {
                        principal=new(context);
                        RequireUnsaved(principal);
                        principal.SamAccountName=accountName;
                        principal.SetPassword(stagedPassword);
                        principal.Enabled=false;
                    }
                });
                var row=new Sequence();
                row.Observe(45,error is null ? null : error.GetType().Name+"|"+(error as ArgumentException)?.ParamName);
                if (error is null)
                {
                    RequireUnsaved(principal!);
                    row.Observe(52,principal!.Name);
                    row.Observe(53,principal.SamAccountName);
                    row.Observe(54,principal.Enabled);
                }
                rows.Add(row);
            }
            finally { principal?.Dispose(); }
        }
        return rows;
    }

    private static List<Sequence> Membership()
    {
        var rows=new List<Sequence>();
        foreach (var operation in new[] { "contains","add","remove" })
        {
            using var context=Context();
            using var group=new AM.GroupPrincipal(context);
            using var user=new AM.UserPrincipal(context) { SamAccountName="unsaved-member" };
            RequireUnsaved(group); RequireUnsaved(user);
            bool? value=null;
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                switch (operation)
                {
                    case "contains": value=group.Members.Contains(user); break;
                    case "add": group.Members.Add(user); break;
                    case "remove": value=group.Members.Remove(user); break;
                }
            });
            var row=new Sequence();
            row.Observe(45,value);
            row.Observe(46,group.Members.Count);
            if (operation=="add" && error is null)
            {
                row.Observe(51,group.Members.Contains(user));
                row.Observe(52,group.Members.Remove(user));
                row.Observe(53,group.Members.Count);
            }
            RequireUnsaved(group); RequireUnsaved(user);
            rows.Add(row);
        }
        return rows;
    }
}
