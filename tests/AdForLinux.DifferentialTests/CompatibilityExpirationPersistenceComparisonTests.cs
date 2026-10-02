using System.Runtime.ExceptionServices;
using System.Globalization;
using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Writes disposable accounts. Run only in a verified isolated differential lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityExpirationPersistenceComparisonTests(ITestOutputHelper output)
{
    // Microsoft ADUtils.DateTimeToADFileTime calls ToFileTimeUtc directly;
    // Unspecified is treated as UTC there. Explicit ToUniversalTime first would
    // instead interpret Unspecified as local. The regression is observable only
    // when this Windows host's offset for the test date is nonzero. Do not change
    // the global timezone: log it so a UTC-host pass is not mistaken for coverage
    // of that distinction. Every row still checks Save and fresh reload parity.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADUtils.cs
    // Source blob: 549cbed70e44f38839d7a7a9cc5e3e8375d6cd7e
    [Theory]
    [InlineData(DateTimeKind.Utc)]
    [InlineData(DateTimeKind.Local)]
    [InlineData(DateTimeKind.Unspecified)]
    public void Expiration_Save_conversion_and_fresh_reload_match_microsoft(DateTimeKind kind)
    {
        var value = new DateTime(2030, 6, 1, 12, 34, 56, kind).AddTicks(1234);
        output.WriteLine($"Expiration kind={kind}; local zone={TimeZoneInfo.Local.Id}; offset at test date={TimeZoneInfo.Local.GetUtcOffset(value)}");
        using var microsoftContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var ourContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var parent = Open(DifferentialSettings.UsersContainer);
        var suffix = Guid.NewGuid().ToString("N");
        var names = new[] { $"ex-ms-{suffix}", $"ex-our-{suffix}" };
        var created = new List<MsDirectory.DirectoryEntry>();
        var attempted = new List<string>();
        Exception? primaryFailure = null;
        var errors = new List<Exception>();
        try
        {
            foreach (var name in names)
            {
                CompatibilityOwnedDirectoryObjects.RequireAbsent($"CN={name},{DifferentialSettings.UsersContainer}");
                attempted.Add(name);
                var entry = parent.Children.Add($"CN={name}", "user");
                created.Add(entry);
                entry.Properties["sAMAccountName"].Value = name[..18];
                entry.Properties["userAccountControl"].Value = 0x202;
                entry.CommitChanges();
            }
            using var expected = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.DistinguishedName, $"CN={names[0]},{DifferentialSettings.UsersContainer}");
            using var actual = Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.DistinguishedName, $"CN={names[1]},{DifferentialSettings.UsersContainer}");
            Assert.NotNull(expected);
            Assert.NotNull(actual);
            expected.AccountExpirationDate = value;
            actual.AccountExpirationDate = value;
            var comparison = new Comparison($"AccountExpirationDate persistence kind={kind}");
            var expectedError = Record.Exception(expected.Save);
            var actualError = Record.Exception(actual.Save);
            comparison.Check("Save exception", expectedError?.GetType().Name, actualError?.GetType().Name)
                .Check("Save parameter", (expectedError as ArgumentException)?.ParamName, (actualError as ArgumentException)?.ParamName);
            // Require the oracle's valid write to succeed; two failed saves must
            // not yield a false pass on the unchanged initial account values.
            Assert.Null(expectedError);
            CompareDate(comparison, "cached after Save", expected.AccountExpirationDate, actual.AccountExpirationDate);

            // Read both raw values through Microsoft to isolate persistence from
            // each implementation's high-level FILETIME decoding.
            var expectedRaw = ReadRawFileTime(names[0]);
            var actualRaw = ReadRawFileTime(names[1]);
            Assert.NotNull(expectedRaw);
            comparison.Check("persisted accountExpires", expectedRaw, actualRaw);
            using var expectedReload = Ms.UserPrincipal.FindByIdentity(microsoftContext, Ms.IdentityType.DistinguishedName, $"CN={names[0]},{DifferentialSettings.UsersContainer}");
            using var actualReload = Ours.UserPrincipal.FindByIdentity(ourContext, Ours.IdentityType.DistinguishedName, $"CN={names[1]},{DifferentialSettings.UsersContainer}");
            Assert.NotNull(expectedReload);
            Assert.NotNull(actualReload);
            Assert.NotNull(expectedReload.AccountExpirationDate);
            CompareDate(comparison, "fresh principal", expectedReload.AccountExpirationDate, actualReload.AccountExpirationDate);
            comparison.Assert();
        }
        catch (Exception error)
        {
            primaryFailure = error;
        }
        finally
        {
            foreach (var name in attempted)
            {
                try
                {
                    CleanupOwnedAccount($"CN={name},{DifferentialSettings.UsersContainer}");
                }
                catch (Exception error) { errors.Add(error); }
            }
            foreach (var entry in created)
            {
                try { entry.Dispose(); }
                catch (Exception error) { errors.Add(error); }
            }
        }
        if (errors.Count > 0)
        {
            if (primaryFailure is not null) errors.Insert(0, primaryFailure);
            throw new AggregateException("Account conversion test and/or cleanup failed; primary test failure is first when present.", errors);
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
    }

    private static long? ReadRawFileTime(string name)
    {
        using var entry = Open($"CN={name},{DifferentialSettings.UsersContainer}");
        var value = entry.Properties["accountExpires"].Value;
        if (value is null) return null;
        if (value is long fileTime) return fileTime;
        // ADSI may expose a COM IADsLargeInteger instead of an Int64. Access its
        // public HighPart/LowPart members, as the existing directory helpers do.
        var type = value.GetType();
        var high = Convert.ToInt32(type.InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, value, null), CultureInfo.InvariantCulture);
        var low = Convert.ToInt32(type.InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, value, null), CultureInfo.InvariantCulture);
        return ((long)high << 32) | (uint)low;
    }

    private static void CompareDate(Comparison comparison, string label, DateTime? expected, DateTime? actual)
    {
        comparison.Check($"{label}: ticks", expected?.Ticks, actual?.Ticks)
            .Check($"{label}: kind", expected?.Kind, actual?.Kind);
    }

    private static void CleanupOwnedAccount(string distinguishedName)
    {
        // Probe the exact test-owned DN using configured credentials. SAM may
        // be absent after a partial creation; only no-such-object is ignorable.
        using var entry = Open(distinguishedName);
        try { entry.RefreshCache(new[] { "distinguishedName" }); }
        catch (System.Runtime.InteropServices.COMException error)
            when (error.HResult == unchecked((int)0x80072030))
        {
            return;
        }
        entry.DeleteTree();
    }

    private static MsDirectory.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
