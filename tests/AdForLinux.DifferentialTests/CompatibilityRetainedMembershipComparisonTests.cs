using System.Collections;
using System.Runtime.ExceptionServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Creates and deletes only the unique groups owned by each test invocation.
// Run solely in a verified disposable AD lab, never against a shared directory.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityRetainedMembershipComparisonTests
{
    [Theory]
    [InlineData("Count")]
    [InlineData("GetEnumerator")]
    [InlineData("Add-null")]
    [InlineData("Remove-null")]
    [InlineData("CopyTo-null")]
    public void Retained_membership_after_owner_delete_matches_microsoft(string operation)
    {
        using var microsoftContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        var suffix = Guid.NewGuid().ToString("N")[..10];
        var expectedName = $"adfl-rm-{suffix}";
        var actualName = $"adfl-ro-{suffix}";
        var expectedSeedAttempted = false;
        var actualSeedAttempted = false;
        Exception? primaryFailure = null;
        var cleanupFailures = new List<Exception>();
        try
        {
            // Save can create an object before reporting a later failure.
            expectedSeedAttempted = true;
            Seed(microsoftContext, expectedName);
            actualSeedAttempted = true;
            Seed(microsoftContext, actualName);
            using var microsoft = Ms.GroupPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.SamAccountName, expectedName);
            using var ours = Ours.GroupPrincipal.FindByIdentity(ourContext, Ours.IdentityType.SamAccountName, actualName);
            Assert.NotNull(microsoft);
            Assert.NotNull(ours);
            var expectedMembers = microsoft.Members;
            var actualMembers = ours.Members;
            // Count specifically primes the result-set bookmark/cache path.
            var expectedCount = expectedMembers.Count;
            var actualCount = actualMembers.Count;
            Assert.Equal(0, expectedCount);
            Assert.Equal(0, actualCount);

            // Retain the collection before deleting the owner. Do not reacquire
            // Group.Members: that getter has its own deleted-principal guard.
            microsoft.Delete();
            ours.Delete();
            Assert.Equal(Observe(() => Read(expectedMembers, operation)),
                Observe(() => Read(actualMembers, operation)));
        }
        catch (Exception error)
        {
            primaryFailure = error;
        }
        finally
        {
            // Probe exact test-owned DNs even if Save failed partway through.
            // Keep every cleanup error without replacing the test failure.
            if (actualSeedAttempted) TryCleanup(microsoftContext, actualName, cleanupFailures);
            if (expectedSeedAttempted) TryCleanup(microsoftContext, expectedName, cleanupFailures);
        }
        if (cleanupFailures.Count > 0)
        {
            if (primaryFailure is not null) cleanupFailures.Insert(0, primaryFailure);
            throw new AggregateException("Retained membership test and/or cleanup failed; primary test failure is first when present.", cleanupFailures);
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
    }

    private static string Read(Ms.PrincipalCollection members, string operation)
    {
        switch (operation)
        {
            case "Count": return members.Count.ToString();
            case "GetEnumerator":
                using (members.GetEnumerator()) { }
                return "created";
            case "Add-null": members.Add((Ms.Principal)null!); return "added";
            case "Remove-null": return members.Remove((Ms.Principal)null!).ToString();
            default: ((ICollection)members).CopyTo(null!, 0); return "copied";
        }
    }

    private static string Read(Ours.PrincipalCollection members, string operation)
    {
        switch (operation)
        {
            case "Count": return members.Count.ToString();
            case "GetEnumerator":
                using (members.GetEnumerator()) { }
                return "created";
            case "Add-null": members.Add((Ours.Principal)null!); return "added";
            case "Remove-null": return members.Remove((Ours.Principal)null!).ToString();
            default: ((ICollection)members).CopyTo(null!, 0); return "copied";
        }
    }

    private static string Observe(Func<string> operation)
    {
        try { return $"value:{operation()}"; }
        catch (Exception error)
        {
            return $"error:{error.GetType().Name};hresult:{error.HResult:X8};parameter:{(error as ArgumentException)?.ParamName}";
        }
    }

    private static void Seed(Ms.PrincipalContext context, string name)
    {
        using var group = new Ms.GroupPrincipal(context, name)
        {
            Name = name, IsSecurityGroup = true, GroupScope = Ms.GroupScope.Global,
        };
        group.Save();
    }

    private static void TryCleanup(Ms.PrincipalContext context, string name, List<Exception> failures)
    {
        try { Cleanup(context, name); }
        catch (Exception error)
        {
            failures.Add(new InvalidOperationException(
                $"Cleanup failed for CN={name},{DifferentialSettings.UsersContainer}.", error));
        }
    }

    private static void Cleanup(Ms.PrincipalContext context, string name)
    {
        using var remaining = Ms.GroupPrincipal.FindByIdentity(context, Ms.IdentityType.DistinguishedName,
            $"CN={name},{DifferentialSettings.UsersContainer}");
        remaining?.Delete();
    }
}
