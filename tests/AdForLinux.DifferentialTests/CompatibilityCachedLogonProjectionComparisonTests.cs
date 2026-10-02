using System.Runtime.ExceptionServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Account creation/deletion requires a verified disposable Windows AD lab.
// Timestamp changes below affect only the public DirectoryEntry property cache:
// this tests cached projection, not the server's acceptance of timestamp writes.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityCachedLogonProjectionComparisonTests
{
    // Pinned source: ADStoreCtx.Insert refreshes underlying DirectoryEntry
    // attributes, while AccountInfo.ResetAllChangeStatus leaves LastLogon
    // unloaded. Load(p, property) reads de.Properties without RefreshCache when
    // there is no UnderlyingSearchObject. A newly saved principal supplies that
    // path; FindByIdentity would instead carry an independent search snapshot.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AccountInfo.cs
    [Theory]
    [InlineData("absent")]
    [InlineData("zero")]
    [InlineData("positive")]
    public void LastLogon_projects_cached_timestamp_presence_like_microsoft(string timestamp)
    {
        WithSavedUsers((expected, actual, expectedEntry, actualEntry) =>
        {
            Assert.True(expectedEntry.UsePropertyCache);
            Assert.True(actualEntry.UsePropertyCache);
            var lastLogon = new DateTime(2030, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc();
            var replicatedLogon = new DateTime(2031, 2, 3, 4, 5, 6, DateTimeKind.Utc).ToFileTimeUtc();
            expectedEntry.Properties["lastLogon"].Value = lastLogon;
            actualEntry.Properties["lastLogon"].Value = lastLogon;
            if (timestamp == "absent")
            {
                expectedEntry.Properties["lastLogonTimestamp"].Clear();
                actualEntry.Properties["lastLogonTimestamp"].Clear();
            }
            else
            {
                var value = timestamp == "zero" ? 0L : replicatedLogon;
                expectedEntry.Properties["lastLogonTimestamp"].Value = value;
                actualEntry.Properties["lastLogonTimestamp"].Value = value;
            }
            // Check cache prerequisites before projecting. Do not call Save,
            // CommitChanges, RefreshCache, or re-find either principal here.
            Assert.Equal(lastLogon, CachedFileTime(expectedEntry.Properties["lastLogon"].Value));
            Assert.Equal(lastLogon, Assert.IsType<long>(actualEntry.Properties["lastLogon"].Value));
            var expectedTimestamp = expectedEntry.Properties["lastLogonTimestamp"];
            var actualTimestamp = actualEntry.Properties["lastLogonTimestamp"];
            Assert.Equal(timestamp == "absent" ? 0 : 1, expectedTimestamp.Count);
            Assert.Equal(expectedTimestamp.Count, actualTimestamp.Count);
            if (timestamp != "absent")
            {
                var expectedRaw = CachedFileTime(expectedTimestamp.Value);
                Assert.Equal(timestamp == "zero" ? 0L : replicatedLogon, expectedRaw);
                Assert.Equal(expectedRaw, Assert.IsType<long>(actualTimestamp.Value));
            }
            var expectedValue = expected.LastLogon;
            var actualValue = actual.LastLogon;
            // Positive controls must actually project a timestamp; matched
            // nulls from an unexpectedly preloaded account state cannot pass.
            if (timestamp != "zero") Assert.NotNull(expectedValue);
            new Comparison($"LastLogon projection with cached timestamp={timestamp}")
                .Check("ticks", expectedValue?.Ticks, actualValue?.Ticks)
                .Check("kind", expectedValue?.Kind, actualValue?.Kind)
                .Assert();
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LastLogon_reread_observes_underlying_cache_changes_like_microsoft(bool changeTimestamp)
    {
        WithSavedUsers((expected, actual, expectedEntry, actualEntry) =>
        {
            Assert.True(expectedEntry.UsePropertyCache);
            Assert.True(actualEntry.UsePropertyCache);
            var initial = new DateTime(2030, 1, 2, 3, 4, 5, DateTimeKind.Utc);
            var replacement = initial.AddDays(11);
            expectedEntry.Properties["lastLogon"].Value = initial.AddDays(-1).ToFileTimeUtc();
            actualEntry.Properties["lastLogon"].Value = initial.AddDays(-1).ToFileTimeUtc();
            expectedEntry.Properties["lastLogonTimestamp"].Value = initial.ToFileTimeUtc();
            actualEntry.Properties["lastLogonTimestamp"].Value = initial.ToFileTimeUtc();
            Assert.Equal(initial.ToFileTimeUtc(), CachedFileTime(expectedEntry.Properties["lastLogonTimestamp"].Value));
            Assert.Equal(initial.ToFileTimeUtc(), CachedFileTime(actualEntry.Properties["lastLogonTimestamp"].Value));

            var expectedFirst = expected.LastLogon;
            var actualFirst = actual.LastLogon;
            // Establish successful projection before testing cache invalidation.
            Assert.NotNull(expectedFirst);
            Assert.Equal(initial.Ticks, expectedFirst.Value.Ticks);
            var comparison = new Comparison($"LastLogon reread after cached timestamp change={changeTimestamp}");
            CompareDate(comparison, "first read", expectedFirst, actualFirst);
            if (changeTimestamp)
            {
                expectedEntry.Properties["lastLogonTimestamp"].Value = replacement.ToFileTimeUtc();
                actualEntry.Properties["lastLogonTimestamp"].Value = replacement.ToFileTimeUtc();
            }
            var currentFileTime = (changeTimestamp ? replacement : initial).ToFileTimeUtc();
            Assert.Equal(currentFileTime, CachedFileTime(expectedEntry.Properties["lastLogonTimestamp"].Value));
            Assert.Equal(currentFileTime, CachedFileTime(actualEntry.Properties["lastLogonTimestamp"].Value));
            // AccountInfo.HandleGet may retain its already-loaded value even
            // though the public DirectoryEntry cache has changed. Compare the
            // oracle, without prescribing whether the second value is old/new.
            CompareDate(comparison, "second read", expected.LastLogon, actual.LastLogon);
            comparison.Assert();
        });
    }

    private static void CompareDate(Comparison comparison, string label, DateTime? expected, DateTime? actual) => comparison
        .Check($"{label}: ticks", expected?.Ticks, actual?.Ticks)
        .Check($"{label}: kind", expected?.Kind, actual?.Kind);

    internal static void WithSavedUsers(Action<Ms.UserPrincipal, Ours.UserPrincipal, MsDirectory.DirectoryEntry, OurDirectory.DirectoryEntry> observe)
    {
        using var microsoftContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        var suffix = Guid.NewGuid().ToString("N");
        var expectedName = $"lg-ms-{suffix}";
        var actualName = $"lg-our-{suffix}";
        var expectedDn = $"CN={expectedName},{DifferentialSettings.UsersContainer}";
        var actualDn = $"CN={actualName},{DifferentialSettings.UsersContainer}";
        using var expected = new Ms.UserPrincipal(microsoftContext)
        { Name = expectedName, SamAccountName = $"lg-ms-{suffix[..10]}", Enabled = false };
        using var actual = new Ours.UserPrincipal(ourContext)
        { Name = actualName, SamAccountName = $"lg-our-{suffix[..10]}", Enabled = false };
        var attempted = new List<string>();
        Exception? primaryFailure = null;
        var cleanupFailures = new List<Exception>();
        try
        {
            CompatibilityOwnedDirectoryObjects.RequireAbsent(expectedDn);
            attempted.Add(expectedDn);
            expected.Save();
            CompatibilityOwnedDirectoryObjects.RequireAbsent(actualDn);
            attempted.Add(actualDn);
            actual.Save();
            var expectedEntry = Assert.IsType<MsDirectory.DirectoryEntry>(expected.GetUnderlyingObject());
            var actualEntry = Assert.IsType<OurDirectory.DirectoryEntry>(actual.GetUnderlyingObject());
            observe(expected, actual, expectedEntry, actualEntry);
        }
        catch (Exception error) { primaryFailure = error; }
        finally
        {
            // Lookup uses exact owned DNs and fresh principals. It cannot flush
            // the staged caches on expected/actual into the directory.
            foreach (var dn in attempted)
            {
                try
                {
                    using var remaining = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.DistinguishedName, dn);
                    remaining?.Delete();
                }
                catch (Exception error) { cleanupFailures.Add(error); }
            }
        }
        if (cleanupFailures.Count > 0)
        {
            if (primaryFailure is not null) cleanupFailures.Insert(0, primaryFailure);
            throw new AggregateException("Cached logon projection test and/or cleanup failed; primary failure is first when present.", cleanupFailures);
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
    }

    internal static long CachedFileTime(object? value)
    {
        Assert.NotNull(value);
        if (value is long fileTime) return fileTime;
        // ADSI can re-read a staged value as public IADsLargeInteger. Normalize
        // that provider representation without inspecting private cache state.
        var type = value.GetType();
        var high = Convert.ToInt32(type.InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty,
            null, value, null), System.Globalization.CultureInfo.InvariantCulture);
        var low = Convert.ToInt32(type.InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty,
            null, value, null), System.Globalization.CultureInfo.InvariantCulture);
        return ((long)high << 32) | (uint)low;
    }
}
