using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;
using OurDirectory = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Creates/deletes owned users and invokes Save(context). Both contexts target
// the same container; no scalar property changes are staged. Requires explicit
// authorization for a disposable AD lab. These cases have not been run on AD.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilitySaveContextNativeOwnershipComparisonTests
{
    // Microsoft Save(context) -> ADStoreCtx.Move -> SDSUtils.MoveDirectoryEntry
    // mutates the existing underlying entry rather than replacing its wrapper.
    // The same-container MoveHere must succeed as a runtime prerequisite; a
    // provider rejection is not evidence for the native-ownership candidate.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/SDSUtils.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Save_context_preserves_retained_native_entry_like_microsoft(bool distinctContext)
    {
        var expectedOwned = new OwnedUser("ms");
        var actualOwned = new OwnedUser("ours");
        Exception? primaryError = null;
        try
        {
            expectedOwned.Create();
            actualOwned.Create();
            using var expectedContext = MicrosoftContext();
            using var actualContext = OurContext();
            using var alternateExpected = distinctContext ? MicrosoftContext() : null;
            using var alternateActual = distinctContext ? OurContext() : null;
            var expectedTarget = alternateExpected ?? expectedContext;
            var actualTarget = alternateActual ?? actualContext;
            using var expected = Ms.UserPrincipal.FindByIdentity(expectedContext,
                Ms.IdentityType.DistinguishedName, expectedOwned.Dn);
            using var actual = Ours.UserPrincipal.FindByIdentity(actualContext,
                Ours.IdentityType.DistinguishedName, actualOwned.Dn);
            Assert.NotNull(expected);
            Assert.NotNull(actual);
            Assert.Same(expectedContext, expected.Context);
            Assert.Same(actualContext, actual.Context);
            var expectedNative = Assert.IsType<MsDirectory.DirectoryEntry>(expected.GetUnderlyingObject());
            var actualNative = Assert.IsType<OurDirectory.DirectoryEntry>(actual.GetUnderlyingObject());
            // Borrowed native wrappers remain owned by their principals.
            // No separate using/disposal can manufacture the lifetime result.
            var expectedName = expectedNative.Name;
            var actualName = actualNative.Name;
            Assert.Equal("CN=" + expectedOwned.Cn, expectedName, ignoreCase: true);
            Assert.Equal("CN=" + actualOwned.Cn, actualName, ignoreCase: true);
            Assert.Same(expectedNative, expected.GetUnderlyingObject());
            Assert.Same(actualNative, actual.GetUnderlyingObject());

            var expectedSaveError = Record.Exception(() => expected.Save(expectedTarget));
            var actualSaveError = Record.Exception(() => actual.Save(actualTarget));
            RequireSaveSuccess(expectedSaveError, "Microsoft", distinctContext);
            RequireSaveSuccess(actualSaveError, "clone", distinctContext);
            Assert.Same(expectedTarget, expected.Context);
            Assert.Same(actualTarget, actual.Context);
            expectedOwned.VerifyPersisted();
            actualOwned.VerifyPersisted();

            var expectedCurrent = Assert.IsType<MsDirectory.DirectoryEntry>(expected.GetUnderlyingObject());
            var actualCurrent = Assert.IsType<OurDirectory.DirectoryEntry>(actual.GetUnderlyingObject());
            Assert.Equal(expectedName, expectedCurrent.Name);
            Assert.Equal(actualName, actualCurrent.Name);
            string? expectedRetainedName = null;
            string? actualRetainedName = null;
            var expectedReadError = Record.Exception(() => expectedRetainedName = expectedNative.Name);
            var actualReadError = Record.Exception(() => actualRetainedName = actualNative.Name);
            Assert.Null(expectedReadError);
            Assert.Equal(expectedName, expectedRetainedName);
            Assert.Same(expectedNative, expectedCurrent);
            if (!distinctContext)
            {
                Assert.Null(actualReadError);
                Assert.Equal(actualName, actualRetainedName);
                Assert.Same(actualNative, actualCurrent);
            }
            new Comparison($"Save(context) native ownership: distinctContext={distinctContext}")
                .Check("retained native wrapper identity", ReferenceEquals(expectedNative, expectedCurrent),
                    ReferenceEquals(actualNative, actualCurrent))
                .Check("retained Name exception", expectedReadError?.GetType().Name, actualReadError?.GetType().Name)
                .Check("retained Name disposed object", (expectedReadError as ObjectDisposedException)?.ObjectName,
                    (actualReadError as ObjectDisposedException)?.ObjectName)
                .Check("retained Name remains readable", expectedRetainedName == expectedName,
                    actualRetainedName == actualName)
                .Assert();
        }
        catch (Exception error) { primaryError = error; }

        var cleanupErrors = new List<Exception>();
        expectedOwned.Cleanup(cleanupErrors);
        actualOwned.Cleanup(cleanupErrors);
        if (cleanupErrors.Count != 0)
        {
            if (primaryError is not null) cleanupErrors.Insert(0, primaryError);
            throw new AggregateException("Save(context) ownership test and/or guarded cleanup failed.", cleanupErrors);
        }
        if (primaryError is not null) ExceptionDispatchInfo.Capture(primaryError).Throw();
    }

    private static void RequireSaveSuccess(Exception? error, string side, bool distinctContext)
    {
        if (error is not null)
            Assert.Fail($"Successful same-container Save prerequisite failed ({side}, distinctContext={distinctContext}); " +
                $"native lifetime comparison not reached. Exception={error.GetType().FullName}, HResult=0x{error.HResult:X8}.");
    }

    private sealed class OwnedUser
    {
        internal string Cn { get; }
        internal string Dn { get; }
        private readonly string _sam;
        private readonly string _marker = "save-context-owner-" + Guid.NewGuid().ToString("N");
        private Guid? _identity;
        private bool _creationAttempted;

        internal OwnedUser(string side)
        {
            var token = Guid.NewGuid().ToString("N");
            Cn = $"compat-sc-{side}-{token}";
            Dn = $"CN={Cn},{DifferentialSettings.UsersContainer}";
            _sam = "sc" + token[..17];
        }

        internal void Create()
        {
            CompatibilityOwnedDirectoryObjects.RequireAbsent(Dn);
            _creationAttempted = true;
            using var parent = Open(DifferentialSettings.UsersContainer);
            using var child = parent.Children.Add("CN=" + Cn, "user");
            child.Properties["sAMAccountName"].Value = _sam;
            child.Properties["description"].Value = _marker;
            child.CommitChanges();
            using var persisted = Open(Dn);
            RefreshIdentity(persisted);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, persisted.Properties["description"].Value);
            Assert.NotEqual(Guid.Empty, persisted.Guid);
            _identity = persisted.Guid;
        }

        internal void VerifyPersisted()
        {
            using var persisted = Open(Dn);
            RefreshIdentity(persisted);
            Assert.Equal(Dn, (string)persisted.Properties["distinguishedName"].Value!, ignoreCase: true);
            Assert.Equal(Cn, persisted.Properties["cn"].Value);
            Assert.Equal(_sam, persisted.Properties["sAMAccountName"].Value);
            Assert.Equal(_marker, persisted.Properties["description"].Value);
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
                    && string.Equals(_marker, entry.Properties["description"].Value as string, StringComparison.Ordinal)
                    && (_identity is null || entry.Guid == _identity.Value);
                if (!matches) throw new InvalidOperationException($"Refusing cleanup of unrecognized entry: {Dn}");
                using var parent = entry.Parent;
                parent.Children.Remove(entry);
            }
            catch (Exception error) { errors.Add(error); }
        }

        private static void RefreshIdentity(MsDirectory.DirectoryEntry entry) => entry.RefreshCache(
            new[] { "distinguishedName", "cn", "sAMAccountName", "description", "objectGUID" });
    }

    private static Ms.PrincipalContext MicrosoftContext() => new(Ms.ContextType.Domain,
        DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
        DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
    private static Ours.PrincipalContext OurContext() => new(Ours.ContextType.Domain,
        DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
        DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
    private static MsDirectory.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
}
