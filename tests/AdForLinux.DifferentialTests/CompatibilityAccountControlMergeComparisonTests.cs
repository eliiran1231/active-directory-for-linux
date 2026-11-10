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
            Assert.Equal(SuiteCapture.Expected(expectedOwned.Identity, "assert-equal-expected", 65), SuiteCapture.Expected(expectedNative.Guid, "assert-equal-actual", 65));
            Assert.Equal(SuiteCapture.Expected(actualOwned.Identity, "assert-equal-expected", 66), SuiteCapture.Expected(actualNative.Guid, "assert-equal-actual", 66));
            var expectedNativeFlags = Convert.ToInt32(expectedNative.Properties["userAccountControl"].Value);
            var actualNativeFlags = Convert.ToInt32(actualNative.Properties["userAccountControl"].Value);
            Assert.Equal(SuiteCapture.Expected(Disabled, "assert-equal-expected", 69), SuiteCapture.Expected(expectedNativeFlags & ObservedBits, "assert-equal-actual", 69));
            Assert.Equal(SuiteCapture.Expected(Disabled, "assert-equal-expected", 70), SuiteCapture.Expected(actualNativeFlags & ObservedBits, "assert-equal-actual", 70));
            if (editOtherNativeBit)
            {
                expectedNative.Properties["userAccountControl"].Value = expectedNativeFlags | NotDelegated;
                actualNative.Properties["userAccountControl"].Value = actualNativeFlags | NotDelegated;
                expectedNative.CommitChanges();
                actualNative.CommitChanges();
            }
            var beforeSave = Disabled | (editOtherNativeBit ? NotDelegated : 0);
            Assert.Equal(SuiteCapture.Expected(beforeSave, "assert-equal-expected", 79), SuiteCapture.Expected(expectedOwned.ReadFlags() & ObservedBits, "assert-equal-actual", 79));
            Assert.Equal(SuiteCapture.Expected(beforeSave, "assert-equal-expected", 80), SuiteCapture.Expected(actualOwned.ReadFlags() & ObservedBits, "assert-equal-actual", 80));

            expected.Save();
            actual.Save();
            var expectedFlags = expectedOwned.ReadFlags();
            var actualFlags = actualOwned.ReadFlags();
            Assert.Equal(SuiteCapture.Expected(beforeSave | NeverExpires, "assert-equal-expected", 86), SuiteCapture.Expected(expectedFlags & ObservedBits, "assert-equal-actual", 86));
            // Keep account safety a prerequisite on both sides, independent of
            // the compatibility assertion about preserving the unrelated bit.
            Assert.Equal(SuiteCapture.Expected(Disabled, "assert-equal-expected", 89), SuiteCapture.Expected(expectedFlags & Disabled, "assert-equal-actual", 89));
            Assert.Equal(SuiteCapture.Expected(Disabled, "assert-equal-expected", 90), SuiteCapture.Expected(actualFlags & Disabled, "assert-equal-actual", 90));
            Assert.Equal(SuiteCapture.Expected(NeverExpires, "assert-equal-expected", 91), SuiteCapture.Expected(actualFlags & NeverExpires, "assert-equal-actual", 91));
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
            Assert.Equal(SuiteCapture.Expected(_sam, "assert-equal-expected", 141), SuiteCapture.Expected(persisted.Properties["sAMAccountName"].Value, "assert-equal-actual", 141));
            Assert.Equal(SuiteCapture.Expected(_marker, "assert-equal-expected", 142), SuiteCapture.Expected(Assert.Single(persisted.Properties["otherTelephone"].Cast<object>()), "assert-equal-actual", 142));
            Assert.Equal(SuiteCapture.Expected(Disabled, "assert-equal-expected", 143), SuiteCapture.Expected(Convert.ToInt32(persisted.Properties["userAccountControl"].Value) & ObservedBits, "assert-equal-actual", 143));
            Assert.NotEqual(Guid.Empty, persisted.Guid);
            _identity = persisted.Guid;
        }

        internal int ReadFlags()
        {
            using var persisted = Open(Dn);
            RefreshIdentity(persisted);
            Assert.Equal(SuiteCapture.Expected(Dn, "assert-equal-expected", 152), SuiteCapture.Expected((string)persisted.Properties["distinguishedName"].Value!, "assert-equal-actual", 152), ignoreCase: true);
            Assert.Equal(SuiteCapture.Expected(_sam, "assert-equal-expected", 153), SuiteCapture.Expected(persisted.Properties["sAMAccountName"].Value, "assert-equal-actual", 153));
            Assert.Equal(SuiteCapture.Expected(_marker, "assert-equal-expected", 154), SuiteCapture.Expected(Assert.Single(persisted.Properties["otherTelephone"].Cast<object>()), "assert-equal-actual", 154));
            Assert.Equal(SuiteCapture.Expected(_identity, "assert-equal-expected", 155), SuiteCapture.Expected(persisted.Guid, "assert-equal-actual", 155));
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
