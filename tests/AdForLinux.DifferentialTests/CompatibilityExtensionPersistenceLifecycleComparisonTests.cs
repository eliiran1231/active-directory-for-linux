using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;
using MsDirectory = System.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Creates/deletes isolated users. Source-supported candidates, not runtime-
// confirmed gaps. Execute only in an explicitly authorized disposable AD lab.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityExtensionPersistenceLifecycleComparisonTests
{
    // Microsoft ResetAllChangeStatus changes the extension-cache load state,
    // retaining cached arrays; it does not clear the extension cache on Save.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Extension_array_retains_local_alias_across_save_like_microsoft(bool save)
    {
        WithOwnedPair(pair =>
        {
            var expectedInput = new object[] { pair.Marker };
            var actualInput = new object[] { pair.Marker };
            pair.Expected.Write(expectedInput);
            pair.Actual.Write(actualInput);
            Assert.Same(expectedInput, pair.Expected.Read());
            Assert.Same(actualInput, pair.Actual.Read());
            if (save) pair.SaveBothAndVerify();

            var expectedAfter = pair.Expected.Read();
            var actualAfter = pair.Actual.Read();
            Assert.Same(expectedInput, expectedAfter);
            var comparison = new Comparison($"Extension array alias: save={save}")
                .Check("retained supplied array", ReferenceEquals(expectedInput, expectedAfter),
                    ReferenceEquals(actualInput, actualAfter));

            // This is a local edit only. Do not Save again: an independent read
            // proves that array mutation was not mistaken for persistence.
            expectedInput[0] = actualInput[0] = "local-array-edit";
            var expectedValues = pair.Expected.Read();
            var actualValues = pair.Actual.Read();
            Assert.Equal(new object[] { "local-array-edit" }, expectedValues);
            comparison.Check("local value after retained-array edit", Show(expectedValues), Show(actualValues));
            if (save) pair.VerifyBothPersistedMarkers();
            comparison.Assert();
        });
    }

    // Delete sets the principal's deleted flag, but cached ExtensionGet and
    // ExtensionSet do not call CheckDisposedOrDeleted in Microsoft's v9 source.
    [Fact]
    public void Cached_extension_operations_after_delete_match_microsoft()
    {
        WithOwnedPair(pair =>
        {
            pair.Expected.Write(new object[] { pair.Marker });
            pair.Actual.Write(new object[] { pair.Marker });
            pair.SaveBothAndVerify();
            const string staged = "staged-after-save";
            pair.Expected.Write(new object[] { staged });
            pair.Actual.Write(new object[] { staged });
            Assert.Equal(new object[] { staged }, pair.Expected.Read());
            Assert.Equal(new object[] { staged }, pair.Actual.Read());
            pair.Expected.Delete();
            pair.Actual.Delete();
            CompatibilityOwnedDirectoryObjects.RequireAbsent(pair.ExpectedDn);
            CompatibilityOwnedDirectoryObjects.RequireAbsent(pair.ActualDn);

            var expectedNameError = Record.Exception(() => _ = pair.Expected.Name);
            var actualNameError = Record.Exception(() => _ = pair.Actual.Name);
            Assert.IsType<InvalidOperationException>(expectedNameError);
            var comparison = new Comparison("Extension cache after verified Delete")
                .Check("ordinary Name getter rejects deleted owner", Error(expectedNameError), Error(actualNameError));

            object[]? expectedRead = null;
            object?[]? actualRead = null;
            var expectedReadError = Record.Exception(() => expectedRead = pair.Expected.Read());
            var actualReadError = Record.Exception(() => actualRead = pair.Actual.Read());
            Assert.Null(expectedReadError);
            Assert.Equal(new object[] { staged }, expectedRead);
            comparison.Check("cached read exception", Error(expectedReadError), Error(actualReadError))
                .Check("cached read value", Show(expectedRead), Show(actualRead));

            const string replacement = "replacement-after-delete";
            var expectedWriteError = Record.Exception(() => pair.Expected.Write(new object[] { replacement }));
            var actualWriteError = Record.Exception(() => pair.Actual.Write(new object[] { replacement }));
            Assert.Null(expectedWriteError);
            expectedRead = null;
            actualRead = null;
            expectedReadError = Record.Exception(() => expectedRead = pair.Expected.Read());
            actualReadError = Record.Exception(() => actualRead = pair.Actual.Read());
            Assert.Null(expectedReadError);
            Assert.Equal(new object[] { replacement }, expectedRead);
            comparison.Check("replacement write exception", Error(expectedWriteError), Error(actualWriteError))
                .Check("replacement read exception", Error(expectedReadError), Error(actualReadError))
                .Check("replacement read value", Show(expectedRead), Show(actualRead));
            // Local extension operations must not recreate the deleted entries.
            CompatibilityOwnedDirectoryObjects.RequireAbsent(pair.ExpectedDn);
            CompatibilityOwnedDirectoryObjects.RequireAbsent(pair.ActualDn);
            comparison.Assert();
        });
    }

    private static string Error(Exception? error) => error is null ? "success"
        : $"{error.GetType().Name}|{(error as ArgumentException)?.ParamName}";
    private static string Show(object?[]? values) => values is null ? "<no array>"
        : $"{values.Length}:[{string.Join("|", values.Select(value => value?.ToString() ?? "<null>"))}]";

    [Ms.DirectoryObjectClass("user")]
    [Ms.DirectoryRdnPrefix("CN")]
    private sealed class MicrosoftUser(Ms.PrincipalContext context) : Ms.UserPrincipal(context)
    {
        internal object[] Read() => ExtensionGet("otherTelephone");
        internal void Write(object[] values) => ExtensionSet("otherTelephone", values);
    }

    [Ours.DirectoryObjectClass("user")]
    [Ours.DirectoryRdnPrefix("CN")]
    private sealed class OurUser(Ours.PrincipalContext context) : Ours.UserPrincipal(context)
    {
        internal object?[] Read() => ExtensionGet("otherTelephone");
        internal void Write(object[] values) => ExtensionSet("otherTelephone", values);
    }

    private static void WithOwnedPair(Action<OwnedPair> action)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var expected = new MicrosoftUser(expectedContext);
        using var actual = new OurUser(actualContext);
        var pair = new OwnedPair(expected, actual);
        Exception? primaryError = null;
        try { action(pair); }
        catch (Exception error) { primaryError = error; }
        var cleanupErrors = pair.Cleanup();
        if (cleanupErrors.Count != 0)
        {
            if (primaryError is not null) cleanupErrors.Insert(0, primaryError);
            throw new AggregateException("Extension lifecycle test and/or guarded cleanup failed.", cleanupErrors);
        }
        if (primaryError is not null) ExceptionDispatchInfo.Capture(primaryError).Throw();
    }

    private sealed class OwnedPair
    {
        internal MicrosoftUser Expected { get; }
        internal OurUser Actual { get; }
        internal string ExpectedDn { get; }
        internal string ActualDn { get; }
        internal string Marker { get; } = "compat-ext-" + Guid.NewGuid().ToString("N");
        private readonly string _expectedSam;
        private readonly string _actualSam;
        private bool _expectedAttempted;
        private bool _actualAttempted;
        private Guid? _expectedGuid;
        private Guid? _actualGuid;

        internal OwnedPair(MicrosoftUser expected, OurUser actual)
        {
            Expected = expected;
            Actual = actual;
            var expectedToken = Guid.NewGuid().ToString("N");
            var actualToken = Guid.NewGuid().ToString("N");
            Expected.Name = "compat-ext-ms-" + expectedToken;
            Actual.Name = "compat-ext-ours-" + actualToken;
            Expected.SamAccountName = _expectedSam = "exm" + expectedToken[..16];
            Actual.SamAccountName = _actualSam = "exo" + actualToken[..16];
            ExpectedDn = $"CN={Expected.Name},{DifferentialSettings.UsersContainer}";
            ActualDn = $"CN={Actual.Name},{DifferentialSettings.UsersContainer}";
        }

        internal void SaveBothAndVerify()
        {
            CompatibilityOwnedDirectoryObjects.RequireAbsent(ExpectedDn);
            _expectedAttempted = true;
            Expected.Save();
            _expectedGuid = VerifyPersistedMarker(ExpectedDn, _expectedSam);
            CompatibilityOwnedDirectoryObjects.RequireAbsent(ActualDn);
            _actualAttempted = true;
            Actual.Save();
            _actualGuid = VerifyPersistedMarker(ActualDn, _actualSam);
        }

        internal void VerifyBothPersistedMarkers()
        {
            Assert.Equal(_expectedGuid, VerifyPersistedMarker(ExpectedDn, _expectedSam));
            Assert.Equal(_actualGuid, VerifyPersistedMarker(ActualDn, _actualSam));
        }

        private Guid VerifyPersistedMarker(string dn, string sam)
        {
            using var entry = Open(dn);
            entry.RefreshCache(new[] { "distinguishedName", "sAMAccountName", "otherTelephone", "objectGUID" });
            Assert.Equal(dn, (string)entry.Properties["distinguishedName"].Value!, ignoreCase: true);
            Assert.Equal(sam, entry.Properties["sAMAccountName"].Value);
            Assert.Equal(Marker, Assert.Single(entry.Properties["otherTelephone"].Cast<object>()));
            Assert.NotEqual(Guid.Empty, entry.Guid);
            return entry.Guid;
        }

        internal List<Exception> Cleanup()
        {
            var errors = new List<Exception>();
            if (_expectedAttempted) TryCleanup(ExpectedDn, _expectedSam, _expectedGuid);
            if (_actualAttempted) TryCleanup(ActualDn, _actualSam, _actualGuid);
            return errors;

            void TryCleanup(string dn, string sam, Guid? guid)
            {
                try { CleanupOne(dn, sam, guid); }
                catch (Exception error) { errors.Add(error); }
            }
        }

        private void CleanupOne(string dn, string sam, Guid? guid)
        {
            using var entry = Open(dn);
            try { entry.RefreshCache(new[] { "distinguishedName", "sAMAccountName", "otherTelephone", "objectGUID" }); }
            catch (COMException error) when (error.ErrorCode == unchecked((int)0x80072030)) { return; }
            // If Save failed before recording a GUID, both unique SAM and the
            // unique extension marker must prove ownership. Never delete an
            // unrecognized entry, even if it occupies our generated exact DN.
            var matches = string.Equals(dn, entry.Properties["distinguishedName"].Value as string, StringComparison.OrdinalIgnoreCase)
                && string.Equals(sam, entry.Properties["sAMAccountName"].Value as string, StringComparison.Ordinal)
                && (guid is { } identity ? entry.Guid == identity
                    : entry.Properties["otherTelephone"].Cast<object>().SequenceEqual(new object[] { Marker }));
            if (!matches) throw new InvalidOperationException($"Refusing cleanup of unrecognized entry: {dn}");
            using var parent = entry.Parent;
            parent.Children.Remove(entry);
        }

        private static MsDirectory.DirectoryEntry Open(string dn) => new(DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);
    }
}
