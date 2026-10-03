using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Creates, renames, and deletes owned leaf users. Execute only in an explicitly
// authorized disposable AD lab. These candidates have not been run against AD.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityRenameRetainedCacheComparisonTests
{
    // MoveTo replaces the ADSI object, then RefreshCache clears the managed
    // wrapper only when caching is enabled. With caching disabled and without
    // modified ObjectSecurity, CommitChanges returns before clearing it.
    // No test operation accesses or stages ObjectSecurity.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Rename_retains_or_replaces_managed_cache_like_microsoft(bool usePropertyCache)
    {
        var expectedOwned = new OwnedUser("ms");
        var actualOwned = new OwnedUser("ours");
        Exception? primaryError = null;
        try
        {
            expectedOwned.Create();
            actualOwned.Create();
            using var expected = Open(expectedOwned.OldDn);
            using var actual = new Ours.DirectoryEntry(DifferentialSettings.PathFor(actualOwned.OldDn),
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
                DifferentialSettings.OurAuthenticationTypes);
            expected.UsePropertyCache = actual.UsePropertyCache = usePropertyCache;
            // Prime the provider cache before retaining the dictionary. In the
            // caching control, first-load RefreshCache itself replaces the
            // dictionary; that unrelated transition must precede the baseline.
            expected.RefreshCache();
            actual.RefreshCache();
            var expectedProperties = expected.Properties;
            var actualProperties = actual.Properties;
            var expectedCn = expectedProperties["cn"];
            var actualCn = actualProperties["cn"];
            Assert.Equal(expectedOwned.OldCn, Assert.Single(expectedCn.Cast<object>()));
            Assert.Equal(actualOwned.OldCn, Assert.Single(actualCn.Cast<object>()));
            Assert.Same(expectedProperties, expected.Properties);
            Assert.Same(actualProperties, actual.Properties);

            expected.Rename("CN=" + expectedOwned.NewCn);
            actual.Rename("CN=" + actualOwned.NewCn);

            // Prove that both renames actually succeeded independently of their
            // managed caches. A stale local cn is not a failed rename result.
            expectedOwned.VerifyMoved();
            actualOwned.VerifyMoved();
            Assert.Equal("CN=" + expectedOwned.NewCn, expected.Name, ignoreCase: true);
            Assert.Equal("CN=" + actualOwned.NewCn, actual.Name, ignoreCase: true);
            Assert.EndsWith("/" + expectedOwned.NewDn, expected.Path, StringComparison.OrdinalIgnoreCase);
            Assert.EndsWith("/" + actualOwned.NewDn, actual.Path, StringComparison.OrdinalIgnoreCase);
            using var expectedParent = expected.Parent;
            using var actualParent = actual.Parent;
            Assert.EndsWith("/" + DifferentialSettings.UsersContainer, expectedParent.Path,
                StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(actualParent);
            Assert.EndsWith("/" + DifferentialSettings.UsersContainer, actualParent.Path,
                StringComparison.OrdinalIgnoreCase);

            var expectedAfter = expected.Properties;
            var actualAfter = actual.Properties;
            var expectedCnAfter = expectedAfter["cn"];
            var actualCnAfter = actualAfter["cn"];
            var expectedValue = Assert.IsType<string>(Assert.Single(expectedCnAfter.Cast<object>()));
            var actualValue = Assert.IsType<string>(Assert.Single(actualCnAfter.Cast<object>()));
            // Strong oracle premise: the non-caching path retains the old
            // managed value; the caching control reads the new server value.
            Assert.Equal(!usePropertyCache, ReferenceEquals(expectedProperties, expectedAfter));
            Assert.Equal(usePropertyCache ? expectedOwned.NewCn : expectedOwned.OldCn, expectedValue);
            Assert.Equal(expectedOwned.OldCn, Assert.Single(expectedCn.Cast<object>()));
            Assert.Equal(actualOwned.OldCn, Assert.Single(actualCn.Cast<object>()));
            new Comparison($"Rename managed cache: UsePropertyCache={usePropertyCache}")
                .Check("same property dictionary", ReferenceEquals(expectedProperties, expectedAfter),
                    ReferenceEquals(actualProperties, actualAfter))
                .Check("same cn value wrapper", ReferenceEquals(expectedCn, expectedCnAfter),
                    ReferenceEquals(actualCn, actualCnAfter))
                .Check("reacquired cn equals old name", expectedValue == expectedOwned.OldCn,
                    actualValue == actualOwned.OldCn)
                .Check("reacquired cn equals new name", expectedValue == expectedOwned.NewCn,
                    actualValue == actualOwned.NewCn)
                .Check("cache mode preserved", expected.UsePropertyCache, actual.UsePropertyCache)
                .Assert();
        }
        catch (Exception error) { primaryError = error; }

        var cleanupErrors = new List<Exception>();
        expectedOwned.Cleanup(cleanupErrors);
        actualOwned.Cleanup(cleanupErrors);
        if (cleanupErrors.Count != 0)
        {
            if (primaryError is not null) cleanupErrors.Insert(0, primaryError);
            throw new AggregateException("Rename cache test and/or guarded cleanup failed.", cleanupErrors);
        }
        if (primaryError is not null) ExceptionDispatchInfo.Capture(primaryError).Throw();
    }

    private sealed class OwnedUser
    {
        internal string OldCn { get; }
        internal string NewCn { get; }
        internal string OldDn { get; }
        internal string NewDn { get; }
        private readonly string _sam;
        private readonly string _marker = "rename-owner-" + Guid.NewGuid().ToString("N");
        private Guid? _identity;
        private bool _creationAttempted;

        internal OwnedUser(string side)
        {
            var token = Guid.NewGuid().ToString("N");
            OldCn = $"compat-rn-{side}-{token}";
            NewCn = $"compat-rn-{side}-{Guid.NewGuid():N}";
            OldDn = $"CN={OldCn},{DifferentialSettings.UsersContainer}";
            NewDn = $"CN={NewCn},{DifferentialSettings.UsersContainer}";
            _sam = "rn" + token[..17];
        }

        internal void Create()
        {
            // Guard both possible cleanup locations before arming any cleanup.
            CompatibilityOwnedDirectoryObjects.RequireAbsent(OldDn);
            CompatibilityOwnedDirectoryObjects.RequireAbsent(NewDn);
            _creationAttempted = true;
            using var parent = Open(DifferentialSettings.UsersContainer);
            using var child = parent.Children.Add("CN=" + OldCn, "user");
            child.Properties["sAMAccountName"].Value = _sam;
            child.Properties["description"].Value = _marker;
            child.CommitChanges();
            using var persisted = Open(OldDn);
            RefreshIdentity(persisted);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, persisted.Properties["description"].Value);
            Assert.Equal(OldCn, persisted.Properties["cn"].Value);
            Assert.NotEqual(Guid.Empty, persisted.Guid);
            _identity = persisted.Guid;
        }

        internal void VerifyMoved()
        {
            CompatibilityOwnedDirectoryObjects.RequireAbsent(OldDn);
            using var persisted = Open(NewDn);
            RefreshIdentity(persisted);
            Assert.Equal(NewDn, (string)persisted.Properties["distinguishedName"].Value!, ignoreCase: true);
            Assert.Equal(NewCn, persisted.Properties["cn"].Value);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, persisted.Properties["description"].Value);
            Assert.Equal(_identity, persisted.Guid);
        }

        internal void Cleanup(List<Exception> errors)
        {
            if (!_creationAttempted) return;
            // The rename may have reached the server before a later operation
            // threw. Attempt both exact locations, each independently guarded.
            foreach (var dn in new[] { OldDn, NewDn })
            {
                try
                {
                    using var entry = Open(dn);
                    try { RefreshIdentity(entry); }
                    catch (COMException error) when (error.ErrorCode == unchecked((int)0x80072030)) { continue; }
                    var matches = string.Equals(dn, entry.Properties["distinguishedName"].Value as string,
                            StringComparison.OrdinalIgnoreCase)
                        && string.Equals(_sam, entry.Properties["sAMAccountName"].Value as string, StringComparison.Ordinal)
                        && string.Equals(_marker, entry.Properties["description"].Value as string, StringComparison.Ordinal)
                        && (_identity is null || entry.Guid == _identity.Value);
                    if (!matches) throw new InvalidOperationException($"Refusing cleanup of unrecognized entry: {dn}");
                    using var parent = entry.Parent;
                    parent.Children.Remove(entry);
                }
                catch (Exception error) { errors.Add(error); }
            }
        }

        private static void RefreshIdentity(Ms.DirectoryEntry entry) => entry.RefreshCache(
            new[] { "distinguishedName", "cn", "sAMAccountName", "description", "objectGUID" });
    }

    private static Ms.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
