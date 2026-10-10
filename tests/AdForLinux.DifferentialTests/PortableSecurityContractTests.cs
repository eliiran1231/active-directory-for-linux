using Xunit;

namespace AdForLinux.DifferentialTests;

public class PortableSecurityContractTests
{
    [Fact]
    public void Exported_portable_security_types_are_exactly_the_approved_substitutions()
    {
        var exported = typeof(AdForLinux.DirectoryServices.DirectoryEntry).Assembly.GetExportedTypes();
        Assert.Equal(PortableSecurityContract.Types.Keys.Select(t => t.FullName).Order(),
            exported.Where(t => t.Namespace is "AdForLinux.Security.Principal" or "AdForLinux.Security.AccessControl")
                .Select(t => t.FullName).Order());
        Assert.DoesNotContain(exported, t => t.FullName == "AdForLinux.DirectoryServices.DirectoryIdentityResolver");
    }

    [Fact]
    public void Unapproved_names_and_framework_enums_are_not_substituted()
    {
        const string future = "AdForLinux.Security.AccessControl.FuturePublicHelper";
        Assert.Equal(future, PortableSecurityContract.NormalizeName(future));
        Assert.Same(typeof(System.Security.AccessControl.AceFlags), PortableSecurityContract.Map(typeof(System.Security.AccessControl.AceFlags)));
    }
}
