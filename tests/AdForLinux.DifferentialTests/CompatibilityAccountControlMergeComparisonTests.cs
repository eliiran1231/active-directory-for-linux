using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;
using MsAccount = System.DirectoryServices.AccountManagement;
using OurAccount = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Creates and changes owned disabled users; requires an explicitly authorized
// disposable AD lab. Source-supported hypothesis, never an offline test.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityAccountControlMergeComparisonTests
{
    // Microsoft merges each staged Boolean into current native UAC during Save.
    // The clone snapshots the entire integer when the Boolean setter runs.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/SDSUtils.cs#L640
    private const int Disabled = 0x2;
    private const int NeverExpires = 0x10000;
    private const int NotDelegated = 0x100000;
    private const int Baseline = 0x200 | Disabled;
    private const int ObservedBits = Disabled | NeverExpires | NotDelegated;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Staged_account_flag_merges_with_native_entry_changes(bool editOtherNativeBit)
    {
        var expectedOwned = new OwnedUser("ms");
        var actualOwned = new OwnedUser("ours");
        Exception? primaryError = null;
        try
        {
            expectedOwned.Create();
            actualOwned.Create();
            using var expectedContext = new MsAccount.PrincipalContext(MsAccount.ContextType.Domain,
                DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
                MsAccount.ContextOptions.SimpleBind | MsAccount.ContextOptions.SecureSocketLayer,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
            using var actualContext = new OurAccount.PrincipalContext(OurAccount.ContextType.Domain,
                DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
                OurAccount.ContextOptions.SimpleBind | OurAccount.ContextOptions.SecureSocketLayer,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
            using var expected = MsAccount.UserPrincipal.FindByIdentity(expectedContext,
                MsAccount.IdentityType.DistinguishedName, expectedOwned.Dn);
            using var actual = OurAccount.UserPrincipal.FindByIdentity(actualContext,
                OurAccount.IdentityType.DistinguishedName, actualOwned.Dn);
            Assert.NotNull(expected);
            Assert.NotNull(actual);
            Assert.False(expected.Enabled);
            Assert.False(actual.Enabled);
            Assert.False(expected.PasswordNeverExpires);
            Assert.False(actual.PasswordNeverExpires);
            expected.PasswordNeverExpires = true;
            actual.PasswordNeverExpires = true;
            Assert.True(expected.PasswordNeverExpires);
            Assert.True(actual.PasswordNeverExpires);

            // Borrow the principals' actual native objects, without disposing
            // them independently. No external-entry refresh assumption is needed.
            var expectedNative = Assert.IsType<Ms.DirectoryEntry>(expected.GetUnderlyingObject());
            var actualNative = Assert.IsType<Ours.DirectoryEntry>(actual.GetUnderlyingObject());
            Assert.Equal(expectedOwned.Identity, expectedNative.Guid);
            Assert.Equal(actualOwned.Identity, actualNative.Guid);
            var expectedNativeFlags = Convert.ToInt32(expectedNative.Properties["userAccountControl"].Value);
            var actualNativeFlags = Convert.ToInt32(actualNative.Properties["userAccountControl"].Value);
            Assert.Equal(Disabled, expectedNativeFlags & ObservedBits);
            Assert.Equal(Disabled, actualNativeFlags & ObservedBits);
            if (editOtherNativeBit)
            {
                expectedNative.Properties["userAccountControl"].Value = expectedNativeFlags | NotDelegated;
                actualNative.Properties["userAccountControl"].Value = actualNativeFlags | NotDelegated;
                expectedNative.CommitChanges();
                actualNative.CommitChanges();
            }
            var beforeSave = Disabled | (editOtherNativeBit ? NotDelegated : 0);
            Assert.Equal(beforeSave, expectedOwned.ReadFlags() & ObservedBits);
            Assert.Equal(beforeSave, actualOwned.ReadFlags() & ObservedBits);

            expected.Save();
            actual.Save();
            var expectedFlags = expectedOwned.ReadFlags();
            var actualFlags = actualOwned.ReadFlags();
            Assert.Equal(beforeSave | NeverExpires, expectedFlags & ObservedBits);
            // Keep account safety a prerequisite on both sides, independent of
            // the compatibility assertion about preserving the unrelated bit.
            Assert.Equal(Disabled, expectedFlags & Disabled);
            Assert.Equal(Disabled, actualFlags & Disabled);
            Assert.Equal(NeverExpires, actualFlags & NeverExpires);
            new Comparison($"Staged UAC bit merge; native edit={editOtherNativeBit}")
                .Check("disabled, expiration and delegation flags", expectedFlags & ObservedBits,
                    actualFlags & ObservedBits)
                .Assert();
        }
        catch (Exception error) { primaryError = error; }

        var cleanupErrors = new List<Exception>();
        expectedOwned.Cleanup(cleanupErrors);
        actualOwned.Cleanup(cleanupErrors);
        if (cleanupErrors.Count != 0)
        {
            if (primaryError is not null) cleanupErrors.Insert(0, primaryError);
            throw new AggregateException("UAC merge comparison and/or guarded cleanup failed.", cleanupErrors);
        }
        if (primaryError is not null) ExceptionDispatchInfo.Capture(primaryError).Throw();
    }

    private sealed class OwnedUser
    {
        internal string Dn { get; }
        internal Guid? Identity => _identity;
        private readonly string _cn;
        private readonly string _sam;
        // Keep ownership evidence separate from the account flags under test.
        private readonly string _marker = "uac-owner-" + Guid.NewGuid().ToString("N");
        private Guid? _identity;
        private bool _creationAttempted;

        internal OwnedUser(string side)
        {
            var token = Guid.NewGuid().ToString("N");
            _cn = $"compat-uac-{side}-{token}";
            Dn = $"CN={_cn},{DifferentialSettings.UsersContainer}";
            _sam = "uc" + token[..17];
        }

        internal void Create()
        {
            CompatibilityOwnedDirectoryObjects.RequireAbsent(Dn);
            _creationAttempted = true;
            using var parent = Open(DifferentialSettings.UsersContainer);
            using var child = parent.Children.Add("CN=" + _cn, "user");
            child.Properties["sAMAccountName"].Value = _sam;
            child.Properties["otherTelephone"].Value = _marker;
            child.Properties["userAccountControl"].Value = Baseline;
            child.CommitChanges();
            using var persisted = Open(Dn);
            RefreshIdentity(persisted);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, Assert.Single(persisted.Properties["otherTelephone"].Cast<object>()));
            Assert.Equal(Disabled, Convert.ToInt32(persisted.Properties["userAccountControl"].Value) & ObservedBits);
            Assert.NotEqual(Guid.Empty, persisted.Guid);
            _identity = persisted.Guid;
        }

        internal int ReadFlags()
        {
            using var persisted = Open(Dn);
            RefreshIdentity(persisted);
            Assert.Equal(Dn, (string)persisted.Properties["distinguishedName"].Value!, ignoreCase: true);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, Assert.Single(persisted.Properties["otherTelephone"].Cast<object>()));
            Assert.Equal(_identity, persisted.Guid);
            return Convert.ToInt32(persisted.Properties["userAccountControl"].Value);
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
            new[] { "distinguishedName", "sAMAccountName", "otherTelephone", "userAccountControl", "objectGUID" });
    }

    private static Ms.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
