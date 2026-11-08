using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Successful_save_must_preserve_scalar_or_extension_edits_made_during_submission_regression(bool extension, bool sameAttribute)
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
        // These edits were absent from the submitted request. Its success must
        // acknowledge only the captured values, leaving the newer intent pending.
        user.Save();
        Assert.Equal(new object[] { "during submission" }, fixture.Server.GetValueOrDefault(laterAttribute, []));
        Assert.Equal(2, fixture.Attempts);
        Assert.Equal(2, fixture.Writes.Count);
        if (!sameAttribute) Assert.Equal("first", Assert.Single(fixture.Server[initialAttribute]));
    }
}
