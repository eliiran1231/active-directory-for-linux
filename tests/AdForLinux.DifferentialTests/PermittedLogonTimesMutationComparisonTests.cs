using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PermittedLogonTimesMutationComparisonTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)] // Controls: explicitly reassign the edited array.
    [InlineData(true, true)]
    public void In_place_logon_hours_edits_survive_save_like_microsoft(bool reloadBeforeEdit, bool reassign)
    {
        using var microsoftContext = new Ms.PrincipalContext(
            Ms.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(
            Ours.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var microsoftName = $"lh-ms-{suffix}";
        var ourName = $"lh-our-{suffix}";
        // A complete 168-hour bitmap; use a nontrivial restriction so the server
        // cannot normalize an unrestricted bitmap to an absent attribute.
        var initial = Enumerable.Repeat((byte)0x55, 21).ToArray();
        using var microsoft = new Ms.UserPrincipal(microsoftContext)
        {
            Name = microsoftName, SamAccountName = microsoftName, Enabled = false,
            PermittedLogonTimes = initial.ToArray(),
        };
        using var ours = new Ours.UserPrincipal(ourContext)
        {
            Name = ourName, SamAccountName = ourName, Enabled = false,
            PermittedLogonTimes = initial.ToArray(),
        };

        try
        {
            microsoft.Save();
            ours.Save();
            Assert.Equal(Convert.ToHexString(initial), ReadMicrosoft(microsoftContext, microsoftName));
            Assert.Equal(Convert.ToHexString(initial), ReadOurs(ourContext, ourName));

            using var reloadedMicrosoft = reloadBeforeEdit
                ? Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.SamAccountName, microsoftName) : null;
            using var reloadedOurs = reloadBeforeEdit
                ? Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.SamAccountName, ourName) : null;
            if (reloadBeforeEdit)
            {
                Assert.NotNull(reloadedMicrosoft);
                Assert.NotNull(reloadedOurs);
            }

            var expectedPrincipal = reloadedMicrosoft ?? microsoft;
            var actualPrincipal = reloadedOurs ?? ours;
            var expectedSnapshots = new List<string>();
            var actualSnapshots = new List<string>();
            // Two saves also exercise resetting the baseline after a successful
            // write. Never call the setter in the regression cases.
            for (var pass = 0; pass < 2; pass++)
            {
                var expectedHours = expectedPrincipal.PermittedLogonTimes;
                var actualHours = actualPrincipal.PermittedLogonTimes;
                Assert.NotNull(expectedHours);
                Assert.NotNull(actualHours);
                expectedHours[pass] = actualHours[pass] = (byte)(0x30 + pass);
                Assert.Equal(expectedHours, actualHours);
                if (reassign)
                {
                    expectedPrincipal.PermittedLogonTimes = expectedHours;
                    actualPrincipal.PermittedLogonTimes = actualHours;
                }

                expectedPrincipal.Save();
                actualPrincipal.Save();
                // A fresh principal is essential: the edited local cache alone
                // cannot prove that the changed bytes reached the directory.
                expectedSnapshots.Add(ReadMicrosoft(microsoftContext, microsoftName));
                actualSnapshots.Add(ReadOurs(ourContext, ourName));
                Assert.Equal(Convert.ToHexString(expectedHours), expectedSnapshots[^1]);
            }

            output.WriteLine($"Microsoft saved bitmaps: {string.Join("; ", expectedSnapshots)}");
            output.WriteLine($"AdForLinux saved bitmaps: {string.Join("; ", actualSnapshots)}");
            Assert.Equal(expectedSnapshots, actualSnapshots);
        }
        finally
        {
            // Independent lookup also cleans up objects if Save created one
            // before failing. Attempt both deletions even if the first fails.
            try { Delete(microsoftContext, microsoftName); }
            finally { Delete(microsoftContext, ourName); }
        }
    }

    private static string ReadMicrosoft(Ms.PrincipalContext context, string name)
    {
        using var user = Ms.UserPrincipal.FindByIdentity(context, Ms.IdentityType.SamAccountName, name);
        Assert.NotNull(user);
        Assert.NotNull(user.PermittedLogonTimes);
        return Convert.ToHexString(user.PermittedLogonTimes);
    }

    private static string ReadOurs(Ours.PrincipalContext context, string name)
    {
        using var user = Ours.UserPrincipal.FindByIdentity(context, Ours.IdentityType.SamAccountName, name);
        Assert.NotNull(user);
        Assert.NotNull(user.PermittedLogonTimes);
        return Convert.ToHexString(user.PermittedLogonTimes);
    }

    private static void Delete(Ms.PrincipalContext context, string name)
    {
        using var user = Ms.UserPrincipal.FindByIdentity(context, Ms.IdentityType.SamAccountName, name);
        user?.Delete();
    }
}
