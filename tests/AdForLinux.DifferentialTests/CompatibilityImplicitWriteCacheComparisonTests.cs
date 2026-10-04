using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Creates, updates, and deletes owned leaf users. Execute only in an explicitly
// authorized disposable AD lab. Source-supported; no live run has confirmed it.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityImplicitWriteCacheComparisonTests
{
    // OnSetComplete calls CommitIfNotCaching, which clears the managed property
    // dictionary after a successful SetInfo. Capture this before the caller's
    // explicit CommitChanges, which otherwise masks the clone's missing reset.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyValueCollection.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/DirectoryEntry.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scalar_write_replaces_managed_cache_at_the_same_commit_boundary(bool usePropertyCache)
    {
        var expectedOwned = new OwnedUser("ms");
        var actualOwned = new OwnedUser("ours");
        Exception? primaryError = null;
        try
        {
            expectedOwned.Create();
            actualOwned.Create();
            using var expected = Open(expectedOwned.Dn);
            using var actual = new Ours.DirectoryEntry(DifferentialSettings.PathFor(actualOwned.Dn),
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
                DifferentialSettings.OurAuthenticationTypes);
            // Set mode and prime the provider cache BEFORE retaining wrappers.
            // This excludes first-load dictionary replacement from the probe.
            expected.UsePropertyCache = actual.UsePropertyCache = usePropertyCache;
            expected.RefreshCache();
            actual.RefreshCache();
            var expectedProperties = expected.Properties;
            var actualProperties = actual.Properties;
            var expectedValues = expectedProperties["description"];
            var actualValues = actualProperties["description"];
            Assert.Equal(Seed, Assert.Single(expectedValues.Cast<object>()));
            Assert.Equal(Seed, Assert.Single(actualValues.Cast<object>()));
            Assert.Same(expectedProperties, expected.Properties);
            Assert.Same(actualProperties, actual.Properties);

            // Index assignment on a known single value avoids whole-Value's
            // Clear-then-Add behavior and performs one scalar replacement.
            expectedValues[0] = actualValues[0] = Edited;
            Assert.Equal(Edited, Assert.Single(expectedValues.Cast<object>()));
            Assert.Equal(Edited, Assert.Single(actualValues.Cast<object>()));
            expectedOwned.VerifyPersisted(usePropertyCache ? Seed : Edited);
            actualOwned.VerifyPersisted(usePropertyCache ? Seed : Edited);

            var expectedAfterWrite = expected.Properties;
            var actualAfterWrite = actual.Properties;
            var expectedReacquired = expectedAfterWrite["description"];
            var actualReacquired = actualAfterWrite["description"];
            Assert.Equal(usePropertyCache, ReferenceEquals(expectedProperties, expectedAfterWrite));
            Assert.Equal(usePropertyCache, ReferenceEquals(expectedValues, expectedReacquired));
            Assert.Equal(Edited, Assert.Single(expectedReacquired.Cast<object>()));
            var comparison = new Comparison($"Implicit scalar commit: UsePropertyCache={usePropertyCache}")
                .Check("same dictionary before explicit commit", ReferenceEquals(expectedProperties, expectedAfterWrite),
                    ReferenceEquals(actualProperties, actualAfterWrite))
                .Check("same value wrapper before explicit commit", ReferenceEquals(expectedValues, expectedReacquired),
                    ReferenceEquals(actualValues, actualReacquired))
                .Check("reacquired local value", expectedReacquired.Value, actualReacquired.Value);

            // Recovery/control: after explicit CommitChanges both paths have
            // persisted the edit. Do not require another wrapper replacement:
            // the non-caching Microsoft CommitChanges path is a clean no-op.
            expected.CommitChanges();
            actual.CommitChanges();
            expectedOwned.VerifyPersisted(Edited);
            actualOwned.VerifyPersisted(Edited);
            Assert.Equal(Edited, expected.Properties["description"].Value);
            Assert.Equal(Edited, actual.Properties["description"].Value);
            comparison.Check("cache mode preserved", expected.UsePropertyCache, actual.UsePropertyCache).Assert();
        }
        catch (Exception error) { primaryError = error; }

        var cleanupErrors = new List<Exception>();
        expectedOwned.Cleanup(cleanupErrors);
        actualOwned.Cleanup(cleanupErrors);
        if (cleanupErrors.Count != 0)
        {
            if (primaryError is not null) cleanupErrors.Insert(0, primaryError);
            throw new AggregateException("Implicit-write cache test and/or guarded cleanup failed.", cleanupErrors);
        }
        if (primaryError is not null) ExceptionDispatchInfo.Capture(primaryError).Throw();
    }

    private const string Seed = "compat-implicit-seed";
    private const string Edited = "compat-implicit-edited";

    private sealed class OwnedUser
    {
        internal string Dn { get; }
        private readonly string _cn;
        private readonly string _sam;
        // Keep ownership evidence separate from the description under test.
        private readonly string _marker = "implicit-owner-" + Guid.NewGuid().ToString("N");
        private Guid? _identity;
        private bool _creationAttempted;

        internal OwnedUser(string side)
        {
            var token = Guid.NewGuid().ToString("N");
            _cn = $"compat-iw-{side}-{token}";
            Dn = $"CN={_cn},{DifferentialSettings.UsersContainer}";
            _sam = "iw" + token[..17];
        }

        internal void Create()
        {
            CompatibilityOwnedDirectoryObjects.RequireAbsent(Dn);
            _creationAttempted = true;
            using var parent = Open(DifferentialSettings.UsersContainer);
            using var child = parent.Children.Add("CN=" + _cn, "user");
            child.Properties["sAMAccountName"].Value = _sam;
            child.Properties["otherTelephone"].Value = _marker;
            child.Properties["description"].Value = Seed;
            child.CommitChanges();
            using var persisted = Open(Dn);
            RefreshIdentity(persisted);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, Assert.Single(persisted.Properties["otherTelephone"].Cast<object>()));
            Assert.Equal(Seed, Assert.Single(persisted.Properties["description"].Cast<object>()));
            Assert.NotEqual(Guid.Empty, persisted.Guid);
            _identity = persisted.Guid;
        }

        internal void VerifyPersisted(string description)
        {
            using var persisted = Open(Dn);
            RefreshIdentity(persisted);
            Assert.Equal(Dn, (string)persisted.Properties["distinguishedName"].Value!, ignoreCase: true);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, Assert.Single(persisted.Properties["otherTelephone"].Cast<object>()));
            Assert.Equal(description, Assert.Single(persisted.Properties["description"].Cast<object>()));
            Assert.Equal(_identity, persisted.Guid);
        }

        internal void Cleanup(List<Exception> errors)
        {
            if (!_creationAttempted) return;
            try
            {
                using var entry = Open(Dn);
                try { RefreshIdentity(entry); }
                catch (COMException error) when (error.ErrorCode == unchecked((int)0x80072030)) { return; }
                var matches = string.Equals(Dn, entry.Properties["distinguishedName"].Value as string,
                        StringComparison.OrdinalIgnoreCase)
                    && string.Equals(_sam, entry.Properties["sAMAccountName"].Value as string, StringComparison.Ordinal)
                    && entry.Properties["otherTelephone"].Cast<object>().SequenceEqual(new object[] { _marker })
                    && (_identity is null || entry.Guid == _identity.Value);
                if (!matches) throw new InvalidOperationException($"Refusing cleanup of unrecognized entry: {Dn}");
                using var parent = entry.Parent;
                parent.Children.Remove(entry);
            }
            catch (Exception error) { errors.Add(error); }
        }

        private static void RefreshIdentity(Ms.DirectoryEntry entry) => entry.RefreshCache(
            new[] { "distinguishedName", "sAMAccountName", "otherTelephone", "description", "objectGUID" });
    }

    private static Ms.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
