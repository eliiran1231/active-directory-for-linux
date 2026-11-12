using MsDs = System.DirectoryServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using OursDs = AdForLinux.DirectoryServices;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PrincipalDeleteComparisonTests
{
    [Ms.DirectoryObjectClass("organizationalUnit")]
    [Ms.DirectoryRdnPrefix("OU")]
    private sealed class MicrosoftContainerPrincipal : Ms.Principal
    {
        public MicrosoftContainerPrincipal(Ms.PrincipalContext context)
        {
            ContextRaw = context;
        }
    }

    [Ours.DirectoryObjectClass("organizationalUnit")]
    [Ours.DirectoryRdnPrefix("OU")]
    private sealed class OurContainerPrincipal : Ours.Principal
    {
        public OurContainerPrincipal(Ours.PrincipalContext context)
        {
            ContextRaw = context;
        }
    }

    [Fact]
    public void Leaf_principal_delete_and_state_transition_match_microsoft()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var microsoftName = $"d105-ms-{suffix}";
        var ourName = $"d105-our-{suffix}";

        using var microsoftContext = MicrosoftContext(DifferentialSettings.UsersContainer);
        using var ourContext = OurContext(DifferentialSettings.UsersContainer);
        using var microsoft = new Ms.UserPrincipal(microsoftContext)
        {
            Name = microsoftName,
            SamAccountName = microsoftName,
        };
        using var ours = new Ours.UserPrincipal(ourContext)
        {
            Name = ourName,
            SamAccountName = ourName,
        };

        try
        {
            microsoft.Save();
            ours.Save();

            microsoft.Delete();
            ours.Delete();

            Assert.Equal(
                SuiteCapture.Expected(Record.Exception(() => _ = microsoft.DistinguishedName)?.GetType().Name, "assert-equal-expected", 60),
                SuiteCapture.Expected(Record.Exception(() => _ = ours.DistinguishedName)?.GetType().Name, "assert-equal-actual", 60));
            using var microsoftResult = Ms.UserPrincipal.FindByIdentity(microsoftContext, microsoftName);
            using var ourResult = Ours.UserPrincipal.FindByIdentity(ourContext, ourName);
            Assert.Null(microsoftResult);
            Assert.Null(ourResult);
        }
        finally
        {
            DeleteMicrosoftTreeIfPresent(
                $"CN={microsoftName},{DifferentialSettings.UsersContainer}");
            DeleteOurTreeIfPresent($"CN={ourName},{DifferentialSettings.UsersContainer}");
        }
    }

    [Fact]
    public void Populated_custom_principal_delete_failure_and_state_match_microsoft()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var microsoftName = $"d105-ms-{suffix}";
        var ourName = $"d105-our-{suffix}";
        var microsoftDn = $"OU={microsoftName},{DifferentialSettings.BaseDn}";
        var ourDn = $"OU={ourName},{DifferentialSettings.BaseDn}";
        var microsoftChildDn = $"OU=child,{microsoftDn}";
        var ourChildDn = $"OU=child,{ourDn}";

        using var microsoftContext = MicrosoftContext(DifferentialSettings.BaseDn);
        using var ourContext = OurContext(DifferentialSettings.BaseDn);
        using var microsoft = new MicrosoftContainerPrincipal(microsoftContext)
        {
            Name = microsoftName,
        };
        using var ours = new OurContainerPrincipal(ourContext) { Name = ourName };

        try
        {
            microsoft.Save();
            ours.Save();
            CreateMicrosoftOu(microsoftChildDn);
            CreateOurOu(ourChildDn);
            var microsoftEntry = microsoft.GetUnderlyingObject();
            var ourEntry = ours.GetUnderlyingObject();

            var microsoftFailure = Record.Exception(microsoft.Delete);
            var ourFailure = Record.Exception(ours.Delete);

            Assert.NotNull(microsoftFailure);
            Assert.Equal(SuiteCapture.Expected(microsoftFailure.GetType().Name, "assert-equal-expected", 108), SuiteCapture.Expected(ourFailure?.GetType().Name, "assert-equal-actual", 108));
            Assert.Equal(SuiteCapture.Expected(microsoftDn, "assert-equal-expected", 109), SuiteCapture.Expected(microsoft.DistinguishedName, "assert-equal-actual", 109));
            Assert.Equal(SuiteCapture.Expected(ourDn, "assert-equal-expected", 110), SuiteCapture.Expected(ours.DistinguishedName, "assert-equal-actual", 110));
            Assert.Same(microsoftEntry, microsoft.GetUnderlyingObject());
            Assert.Same(ourEntry, ours.GetUnderlyingObject());
            Assert.True(MicrosoftEntryExists(microsoftChildDn));
            Assert.True(OurEntryExists(ourChildDn));

            DeleteMicrosoftTreeIfPresent(microsoftChildDn);
            DeleteOurTreeIfPresent(ourChildDn);
            microsoft.Delete();
            ours.Delete();

            Assert.Equal(
                SuiteCapture.Expected(Record.Exception(() => _ = microsoft.DistinguishedName)?.GetType().Name, "assert-equal-expected", 121),
                SuiteCapture.Expected(Record.Exception(() => _ = ours.DistinguishedName)?.GetType().Name, "assert-equal-actual", 121));
            Assert.Equal(
                SuiteCapture.Expected(Record.Exception(microsoft.Delete)?.GetType().Name, "assert-equal-expected", 124),
                SuiteCapture.Expected(Record.Exception(ours.Delete)?.GetType().Name, "assert-equal-actual", 124));
        }
        finally
        {
            DeleteMicrosoftTreeIfPresent(microsoftDn);
            DeleteOurTreeIfPresent(ourDn);
        }
    }

    private static Ms.PrincipalContext MicrosoftContext(string container) =>
        new(
            Ms.ContextType.Domain,
            DifferentialSettings.ServerName,
            container,
            DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext(string container) =>
        new(
            Ours.ContextType.Domain,
            DifferentialSettings.ServerName,
            container,
            DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword);

    private static void CreateMicrosoftOu(string distinguishedName)
    {
        using var parent = OpenMicrosoft(ParentDn(distinguishedName));
        using var child = parent.Children.Add("OU=child", "organizationalUnit");
        child.CommitChanges();
    }

    private static void CreateOurOu(string distinguishedName)
    {
        using var parent = OpenOurs(ParentDn(distinguishedName));
        using var child = parent.Children.Add("OU=child", "organizationalUnit");
        child.CommitChanges();
    }

    private static bool MicrosoftEntryExists(string distinguishedName)
    {
        try
        {
            using var entry = OpenMicrosoft(distinguishedName);
            _ = entry.NativeGuid;
            return true;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return false;
        }
    }

    private static bool OurEntryExists(string distinguishedName)
    {
        try
        {
            using var entry = OpenOurs(distinguishedName);
            _ = entry.Guid;
            return true;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return false;
        }
    }

    private static void DeleteMicrosoftTreeIfPresent(string distinguishedName)
    {
        try
        {
            using var entry = OpenMicrosoft(distinguishedName);
            entry.DeleteTree();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
        }
    }

    private static void DeleteOurTreeIfPresent(string distinguishedName)
    {
        try
        {
            using var entry = OpenOurs(distinguishedName);
            entry.DeleteTree();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
        }
    }

    private static MsDs.DirectoryEntry OpenMicrosoft(string distinguishedName) =>
        new(
            DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

    private static OursDs.DirectoryEntry OpenOurs(string distinguishedName) =>
        new(
            DifferentialSettings.PathFor(distinguishedName),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

    private static string ParentDn(string distinguishedName) =>
        distinguishedName[(distinguishedName.IndexOf(',') + 1)..];
}
