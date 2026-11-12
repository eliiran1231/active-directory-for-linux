using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    // An internal transport callback can manufacture same-principal reentrancy.
    // These observations are retained as diagnostics, not a supported API contract.
    private sealed class PrincipalReentrancyDiagnosticTheoryAttribute : TheoryAttribute
    {
        public PrincipalReentrancyDiagnosticTheoryAttribute()
        {
            if (!OfflineTestGuard.Enabled
                || Environment.GetEnvironmentVariable("ADFL_RUN_PRINCIPAL_REENTRANCY_DIAGNOSTICS") != "1")
                Skip = "Diagnostic only: same-principal in-flight edits have no established supported contract. Opt in with the guarded offline runner and ADFL_RUN_PRINCIPAL_REENTRANCY_DIAGNOSTICS=1.";
        }
    }

    [PrincipalReentrancyDiagnosticTheory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Diagnostic_inflight_scalar_or_extension_edit_acknowledgement(bool extension, bool sameAttribute)
    {
        using var fixture = new Fixture();
        using var user = fixture.Attach(new MaterializedCustomUser(fixture.Context));
        var initialAttribute = extension ? "department" : "description";
        var laterAttribute = sameAttribute ? initialAttribute : extension ? "title" : "displayName";
        if (extension) user.WriteAttribute(initialAttribute, "first");
        else user.Description = "first";
        fixture.BeforeWrite = () =>
        {
            fixture.BeforeWrite = null;
            if (extension) user.WriteAttribute(laterAttribute, "during submission");
            else if (sameAttribute) user.Description = "during submission";
            else user.DisplayName = "during submission";
        };

        user.Save();
        Assert.Equal("first", Assert.Single(fixture.Server[initialAttribute]));
        Assert.Equal(1, fixture.Attempts);
        Assert.Single(fixture.Writes);
        if (extension) Assert.Equal("during submission", Assert.Single(user.ReadAttribute(laterAttribute)));
        else Assert.Equal("during submission", sameAttribute ? user.Description : user.DisplayName);
        // Candidate acknowledgement semantics, pending an established public
        // concurrent/reentrant usage contract. The diagnostic currently fails.
        user.Save();
        Assert.Equal(new object[] { "during submission" }, fixture.Server.GetValueOrDefault(laterAttribute, []));
        Assert.Equal(2, fixture.Attempts);
        Assert.Equal(2, fixture.Writes.Count);
        if (!sameAttribute) Assert.Equal("first", Assert.Single(fixture.Server[initialAttribute]));
    }
}
