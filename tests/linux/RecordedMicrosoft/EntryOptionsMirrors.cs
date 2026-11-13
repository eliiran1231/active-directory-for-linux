using System.Reflection;
using DS = AdForLinux.DirectoryServices;
using Sequence = OfflineTheoryMirrors.Sequence;

internal static class EntryOptionsMirrors
{
    internal static void Run(Action<string,List<Sequence>> verify)
    {
        foreach (var port in new[] { true,false })
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test");
            var options=entry.Options;
            var error=OfflineTheoryMirrors.Capture(() =>
            {
                if (port) options.PasswordPort=1636;
                else options.PasswordEncoding=DS.PasswordEncodingMethod.PasswordEncodingClear;
            });
            var row=new Sequence();
            row.Observe(port ? 22 : 41,error?.GetType().Name,exceptionType:true);
            row.Observe(port ? 23 : 42,port ? options.PasswordPort : (int)options.PasswordEncoding);
            verify("DirectoryEntryConfigurationCompatibilityTests."+(port
                ? "Password_port_setter_matches_microsoft_for_nondefault_port"
                : "Clear_password_encoding_setter_matches_microsoft"),[row]);
        }
        var rows=new List<Sequence>();
        foreach (var property in new[] { "PageSize","Referral","SecurityMasks","PasswordEncoding","PasswordPort" })
        foreach (var operation in new[] { "get","valid-set","invalid-set" })
        {
            if (property=="PasswordPort" && operation=="invalid-set") continue;
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/CN=user,DC=example,DC=test");
            var options=entry.Options;
            // Normal owner disposal; no private lifecycle fields are edited.
            entry.Dispose();
            var row=new Sequence();
            Observe(row,options,property,operation);
            Observe(row,options,property,"get");
            rows.Add(row);
        }
        verify("CompatibilityEntryOptionsLifecycleComparisonTests.Retained_options_after_entry_disposal_match_microsoft",rows);
        verify("CompatibilityEntryOptionsLifecycleComparisonTests.Retained_options_rebind_after_close_like_microsoft",Close());
        verify("DirectoryEntryOptionDefaultsComparisonTests.Fresh_and_rebound_options_match_microsoft",RepeatedAssignments());
    }

    private static List<Sequence> RepeatedAssignments()
    {
        var rows=new List<Sequence>();
        foreach (var property in new[] { "PageSize","SecurityMasks" })
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/DC=example,DC=test");
            var options=entry.Options;
            int Read(DS.DirectoryEntryConfiguration current) => property=="PageSize" ? current.PageSize : (int)current.SecurityMasks;
            var row=new Sequence();
            if (property=="SecurityMasks") row.Observe(30,Read(options));
            foreach (var input in property=="PageSize" ? new[] { 17,31 } : new[] { 3,5 })
            {
                if (property=="PageSize") options.PageSize=input;
                else options.SecurityMasks=(DS.SecurityMasks)input;
                row.Observe(36,Read(options));
                entry.Close();
                if (property=="SecurityMasks")
                {
                    row.Observe(48,Read(options));
                    row.Observe(49,Read(entry.Options));
                }
            }
            rows.Add(row);
        }
        return rows;
    }

    private static List<Sequence> Close()
    {
        var rows=new List<Sequence>();
        foreach (var property in new[] { "PageSize","SecurityMasks" })
        {
            using var entry=new DS.DirectoryEntry("LDAP://unused.example.test/CN=user,DC=example,DC=test");
            var options=entry.Options;
            if (property=="PageSize") options.PageSize=17;
            else options.SecurityMasks=(DS.SecurityMasks)3;
            var row=new Sequence();
            Observe(row,options,property,"get");
            entry.Close();
            if (property=="SecurityMasks")
            {
                Observe(row,options,property,"get");
                Observe(row,entry.Options,property,"get");
            }
            // PageSize after Close uses portable literals and Microsoft-only
            // comparisons in the source; those helper calls are not admitted.
            rows.Add(row);
        }
        return rows;
    }

    private static void Observe(Sequence row,DS.DirectoryEntryConfiguration options,string property,string operation)
    {
        int? value=null;
        var error=OfflineTheoryMirrors.Capture(() =>
        {
            var member=typeof(DS.DirectoryEntryConfiguration).GetProperty(property)!;
            if (operation=="get") value=Convert.ToInt32(member.GetValue(options));
            else
            {
                var input=operation=="invalid-set"
                    ? property switch { "SecurityMasks"=>16,"PasswordEncoding"=>2,_=>-1 }
                    : property switch { "PageSize"=>17,"Referral"=>0,"SecurityMasks"=>3,"PasswordEncoding"=>1,_=>1636 };
                member.SetValue(options,member.PropertyType.IsEnum ? Enum.ToObject(member.PropertyType,input) : input);
            }
        });
        if (error is TargetInvocationException invocation) error=invocation.InnerException;
        row.Observe(128,error?.GetType().FullName,exceptionType:true);
        var parameter=(error as ArgumentException)?.ParamName;
        if (parameter is null) row.Observe(129,null);
        row.Observe(130,value);
    }
}
