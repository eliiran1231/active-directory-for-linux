using System.DirectoryServices.Protocols;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private static void AssertOnlyDescriptionWrite(LdapModifyCommand command, string value)
    {
        Assert.Equal("CN=item,DC=example,DC=test", command.DistinguishedName);
        Assert.Empty(command.Controls);
        var change = Assert.Single(command.Changes);
        Assert.Equal("description", change.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
        Assert.Equal(Encoding.UTF8.GetBytes(value), Assert.Single(change.Values));
    }

    [Theory]
    [InlineData(ResultCode.ConstraintViolation, typeof(InvalidOperationException), unchecked((int)0x8007202F))]
    [InlineData(ResultCode.EntryAlreadyExists, typeof(PrincipalExistsException), unchecked((int)0x80071392))]
    [InlineData(ResultCode.Busy, typeof(PrincipalServerDownException), unchecked((int)0x8007200E))]
    [InlineData(ResultCode.ProtocolError, typeof(PrincipalOperationException), unchecked((int)0x80072021))]
    public void Public_principal_definitive_error_maps_category_preserves_edits_and_allows_explicit_corrected_retry(
        ResultCode result, Type expectedType, int hresult)
    {
        using var fixture = new NeutralPrincipalSaveFixture();
        const string diagnostic = "controlled definitive LDAP rejection";
        fixture.State.Outcome = "rejected";
        fixture.State.Rejection = new(result, "DC=matched", diagnostic,
            ["ldap://never-follow.invalid/"], [new("1.2.3.4", [0, 255], true)]);
        fixture.User.Description = "first request";

        var failure = Record.Exception(fixture.User.Save);
        Assert.IsType(expectedType, failure);
        var directory = Assert.IsType<DirectoryServicesCOMException>(failure!.InnerException);
        Assert.Equal(hresult, directory.ErrorCode);
        if (failure is PrincipalOperationException operation) Assert.Equal(hresult, operation.ErrorCode);
        Assert.Equal((int)result, directory.ExtendedError);
        Assert.Equal(diagnostic, directory.ExtendedErrorMessage);
        Assert.Contains(diagnostic, failure.Message, StringComparison.Ordinal);
        Assert.IsType<DirectoryOperationException>(directory.InnerException);
        Assert.Equal(1, fixture.State.Invocations);
        Assert.Equal(1, fixture.State.Submissions);
        AssertOnlyDescriptionWrite(Assert.Single(fixture.State.Commands), "first request");
        Assert.Equal("before", Assert.Single(fixture.State.Server["description"]));
        Assert.Equal("first request", fixture.User.Description);
        Assert.False(fixture.User.IsDeleted);
        fixture.AssertReleased(1);

        // A definitive envelope is Completed even for ProtocolError/Busy. It
        // does not become an uncertain write or trigger an implicit retry.
        fixture.User.Description = "caller correction";
        fixture.State.Outcome = "success";
        fixture.User.Save();
        Assert.Equal(2, fixture.State.Invocations);
        Assert.Equal(2, fixture.State.Submissions);
        Assert.Equal(2, fixture.State.Commands.Count);
        AssertOnlyDescriptionWrite(fixture.State.Commands[1], "caller correction");
        Assert.Equal("caller correction", Assert.Single(fixture.State.Server["description"]));
        fixture.AssertReleased(2);
        fixture.User.Save();
        Assert.Equal(2, fixture.State.Submissions);
        Assert.Equal(2, fixture.State.Invocations);
        fixture.AssertReleased(2);
        // Synthetic result codes/diagnostics are translation inputs, not proof
        // AD emits every selected code for this attribute/operation. Rich inner
        // response metadata parity is separately recorded, not required here.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Public_principal_raw_protocol_error_taxonomy_does_not_erase_submission_outcome(bool afterSubmission)
    {
        using var fixture = new NeutralPrincipalSaveFixture();
        fixture.State.ProtocolFailure = new LdapException(49, "controlled authentication-class failure");
        fixture.State.FailAfterSubmission = afterSubmission;
        fixture.User.Description = "uncertain request";

        var failure = Assert.Throws<AuthenticationException>(fixture.User.Save);
        var directory = Assert.IsType<COMException>(failure.InnerException);
        Assert.Equal(unchecked((int)0x8007052E), directory.ErrorCode);
        Assert.Contains("controlled authentication-class failure", failure.Message, StringComparison.Ordinal);
        Assert.Equal(1, fixture.State.Invocations);
        Assert.Equal(afterSubmission ? 1 : 0, fixture.State.Submissions);
        Assert.Equal(afterSubmission ? 1 : 0, fixture.State.Commands.Count);
        if (afterSubmission) AssertOnlyDescriptionWrite(fixture.State.Commands[0], "uncertain request");
        Assert.Equal("before", Assert.Single(fixture.State.Server["description"])); // fixture models unapplied outcome only
        Assert.Equal("uncertain request", fixture.User.Description);
        fixture.AssertReleased(1);

        var nextValue = "caller correction";
        if (afterSubmission)
        {
            // Raw entry commit tests the uncertainty gate without reapplying
            // principal intent (the separate known refused-retry version bug).
            Assert.Throws<InvalidOperationException>(fixture.Entry.CommitChanges);
            Assert.Equal(1, fixture.State.Submissions);
            Assert.Equal(1, fixture.State.Invocations);
            fixture.Entry.RefreshCache(["description"]);
            nextValue = Assert.IsType<string>(fixture.Entry.Properties["description"].Value);
            Assert.Equal("before", nextValue);
        }
        fixture.User.Description = nextValue; // explicit acceptance of readback when outcome was unknown
        fixture.State.ProtocolFailure = null;
        fixture.User.Save();
        Assert.Equal(2, fixture.State.Invocations);
        Assert.Equal(afterSubmission ? 2 : 1, fixture.State.Submissions);
        Assert.Equal(afterSubmission ? 2 : 1, fixture.State.Commands.Count);
        AssertOnlyDescriptionWrite(fixture.State.Commands[^1], nextValue);
        Assert.Equal(nextValue, Assert.Single(fixture.State.Server["description"]));
        fixture.AssertReleased(2);
        fixture.User.Save();
        Assert.Equal(afterSubmission ? 2 : 1, fixture.State.Submissions);
        Assert.Equal(2, fixture.State.Invocations);
        fixture.AssertReleased(2);
        // Identical public exception category is not evidence of identical
        // delivery state. No real authentication attempt or credential is used.
    }
}
