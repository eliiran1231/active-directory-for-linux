using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Creates/password-configures/deletes owned users. Requires explicit disposable
// AD-lab authorization. Never run as an offline test. Source-supported only.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityFailedInsertRetryComparisonTests
{
    // Microsoft's failed insert deletes the directory object without clearing
    // UnderlyingObject. PushChangesToNative creates a new entry only when that
    // field is null. Probe a corrected retry on the SAME public principal.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs
    [Fact]
    public void Corrected_password_retry_on_same_failed_principal_matches_microsoft()
    {
        var expectedControlOwned = new OwnedUser("ms-control");
        var actualControlOwned = new OwnedUser("ours-control");
        var expectedOwned = new OwnedUser("ms-retry");
        var actualOwned = new OwnedUser("ours-retry");
        var owned = new[] { expectedControlOwned, actualControlOwned, expectedOwned, actualOwned };
        Exception? primaryError = null;
        try
        {
            // Explicit encrypted SimpleBind matches the established deferred-
            // password tests and excludes the separate protected-Negotiate gap.
            using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
                DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
                Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
            using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
                DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
                Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer,
                DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

            using var expectedControl = NewMicrosoft(expectedContext, expectedControlOwned);
            using var actualControl = NewOurs(actualContext, actualControlOwned);
            expectedControl.SetPassword(ValidPassword);
            actualControl.SetPassword(ValidPassword);
            expectedControlOwned.ArmCreation();
            var expectedControlError = Record.Exception(expectedControl.Save);
            RequireSuccess(expectedControlError, "Microsoft valid-password control");
            Assert.True(expectedControlOwned.ReadExistsAndVerify());
            actualControlOwned.ArmCreation();
            var actualControlError = Record.Exception(actualControl.Save);
            RequireSuccess(actualControlError, "clone valid-password control");
            Assert.True(actualControlOwned.ReadExistsAndVerify());

            using (var savedExpectedControl = Ms.UserPrincipal.FindByIdentity(expectedContext,
                Ms.IdentityType.DistinguishedName, expectedControlOwned.Dn))
            using (var savedActualControl = Ms.UserPrincipal.FindByIdentity(expectedContext,
                Ms.IdentityType.DistinguishedName, actualControlOwned.Dn))
            {
                Assert.NotNull(savedExpectedControl);
                Assert.NotNull(savedActualControl);
                Assert.Equal(expectedControlOwned.Dn, savedExpectedControl.DistinguishedName, ignoreCase: true);
                Assert.Equal(actualControlOwned.Dn, savedActualControl.DistinguishedName, ignoreCase: true);
                Assert.NotNull(savedExpectedControl.LastPasswordSet);
                Assert.NotNull(savedActualControl.LastPasswordSet);
            }

            using var expected = NewMicrosoft(expectedContext, expectedOwned);
            using var actual = NewOurs(actualContext, actualOwned);
            expected.SetPassword(RejectedPassword);
            actual.SetPassword(RejectedPassword);
            expectedOwned.ArmCreation();
            var expectedInitialError = Record.Exception(expected.Save);
            actualOwned.ArmCreation();
            var actualInitialError = Record.Exception(actual.Save);
            RequirePasswordRejection(expectedInitialError, "Microsoft");
            RequirePasswordRejection(actualInitialError, "clone");
            // Require complete rollback before retry: no existing object can
            // turn a duplicate-name collision into a spurious retry difference.
            CompatibilityOwnedDirectoryObjects.RequireAbsent(expectedOwned.Dn);
            CompatibilityOwnedDirectoryObjects.RequireAbsent(actualOwned.Dn);
            Assert.Null(expected.Guid);
            Assert.Null(actual.Guid);
            Assert.Null(expected.DistinguishedName);
            Assert.Null(actual.DistinguishedName);
            Assert.Equal(expectedOwned.Cn, expected.Name);
            Assert.Equal(actualOwned.Cn, actual.Name);
            Assert.Equal(expectedOwned.Sam, expected.SamAccountName);
            Assert.Equal(actualOwned.Sam, actual.SamAccountName);
            Assert.Equal(expectedOwned.Marker, expected.Description);
            Assert.Equal(actualOwned.Marker, actual.Description);
            Assert.False(expected.Enabled);
            Assert.False(actual.Enabled);

            // Intentionally reuse these exact instances. Constructing corrected
            // replacement principals would test the already-covered path.
            expected.SetPassword(ValidPassword);
            actual.SetPassword(ValidPassword);
            var expectedRetryError = Record.Exception(expected.Save);
            var actualRetryError = Record.Exception(actual.Save);
            var expectedExists = expectedOwned.ReadExistsAndVerify();
            var actualExists = actualOwned.ReadExistsAndVerify();
            new Comparison("Corrected deferred-password retry on same principal")
                .Check("retry exception", Error(expectedRetryError), Error(actualRetryError))
                .Check("owned exact DN exists after retry", expectedExists, actualExists)
                .Assert();
        }
        catch (Exception error) { primaryError = error; }

        var cleanupErrors = new List<Exception>();
        foreach (var item in owned) item.Cleanup(cleanupErrors);
        if (cleanupErrors.Count != 0)
        {
            if (primaryError is not null) cleanupErrors.Insert(0, primaryError);
            throw new AggregateException("Failed-insert retry test and/or guarded cleanup failed.", cleanupErrors);
        }
        if (primaryError is not null) ExceptionDispatchInfo.Capture(primaryError).Throw();
    }

    // Existing deferred-password comparison tests use these policy controls.
    // No password is included in observations or failure diagnostics.
    private const string ValidPassword = "Str0ng!Passw0rd#2026";
    private const string RejectedPassword = "short";

    private static void RequireSuccess(Exception? error, string stage)
    {
        if (error is not null)
            Assert.Fail($"{stage} prerequisite failed; retry comparison not reached. Exception={error.GetType().Name}.");
    }

    private static void RequirePasswordRejection(Exception? error, string side)
    {
        if (error?.GetType() != typeof(InvalidOperationException))
            Assert.Fail($"{side} deferred-password rejection prerequisite failed; retry comparison not reached. " +
                $"Expected InvalidOperationException, observed {error?.GetType().Name ?? "success"}.");
    }

    private static string Error(Exception? error) => error is null ? "success"
        : $"{error.GetType().Name}|{(error as ArgumentException)?.ParamName}";

    private static Ms.UserPrincipal NewMicrosoft(Ms.PrincipalContext context, OwnedUser owned) => new(context)
    {
        Name = owned.Cn, SamAccountName = owned.Sam, Description = owned.Marker, Enabled = false,
    };
    private static Ours.UserPrincipal NewOurs(Ours.PrincipalContext context, OwnedUser owned) => new(context)
    {
        Name = owned.Cn, SamAccountName = owned.Sam, Description = owned.Marker, Enabled = false,
    };

    private sealed class OwnedUser
    {
        internal string Cn { get; }
        internal string Dn { get; }
        internal string Sam { get; }
        internal string Marker { get; } = "retry-owner-" + Guid.NewGuid().ToString("N");
        private Guid? _identity;
        private bool _creationAttempted;

        internal OwnedUser(string side)
        {
            var token = Guid.NewGuid().ToString("N");
            Cn = $"compat-retry-{side}-{token}";
            Dn = $"CN={Cn},{DifferentialSettings.UsersContainer}";
            Sam = "rt" + token[..17];
        }

        internal void ArmCreation()
        {
            CompatibilityOwnedDirectoryObjects.RequireAbsent(Dn);
            _creationAttempted = true;
        }

        internal bool ReadExistsAndVerify()
        {
            using var entry = Open(Dn);
            try { RefreshIdentity(entry); }
            catch (COMException error) when (error.ErrorCode == unchecked((int)0x80072030)) { return false; }
            Assert.Equal(Dn, (string)entry.Properties["distinguishedName"].Value!, ignoreCase: true);
            Assert.Equal(Sam, entry.Properties["sAMAccountName"].Value);
            Assert.Equal(Marker, entry.Properties["description"].Value);
            Assert.NotEqual(Guid.Empty, entry.Guid);
            if (_identity is { } identity) Assert.Equal(identity, entry.Guid);
            _identity = entry.Guid;
            return true;
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
                    && string.Equals(Sam, entry.Properties["sAMAccountName"].Value as string, StringComparison.Ordinal)
                    && string.Equals(Marker, entry.Properties["description"].Value as string, StringComparison.Ordinal)
                    && (_identity is null || entry.Guid == _identity.Value);
                if (!matches) throw new InvalidOperationException($"Refusing cleanup of unrecognized entry: {Dn}");
                using var parent = entry.Parent;
                parent.Children.Remove(entry);
            }
            catch (Exception error) { errors.Add(error); }
        }

        private static void RefreshIdentity(MsDirectory.DirectoryEntry entry) => entry.RefreshCache(
            new[] { "distinguishedName", "sAMAccountName", "description", "objectGUID" });
    }

    private static MsDirectory.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
        DifferentialSettings.BindDn, DifferentialSettings.BindPassword,
        MsDirectory.AuthenticationTypes.SecureSocketsLayer);
}
