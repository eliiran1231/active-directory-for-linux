using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Fact]
    public void Fresh_Basic_SSL_result_entry_has_its_own_referral_default_without_performing_IO()
    {
        using var root = new DirectoryEntry("LDAP://offline.invalid:636/DC=example,DC=test", null, null,
            AuthenticationTypes.SecureSocketsLayer);
        var admissions = 0;
        root.OperationSessionFactory = (_, _, _, _, _) =>
        {
            admissions++;
            throw new InvalidOperationException("Entry construction must not acquire a session.");
        };
        root.Options.Referral = ReferralChasingOption.None;

        using var reopened = root.CreateEntryForDn("CN=known,DC=example,DC=test");

        Assert.Equal(ReferralChasingOption.None, root.Options.Referral);
        Assert.Equal(ReferralChasingOption.External, reopened.Options.Referral);
        Assert.Equal(AuthenticationTypes.SecureSocketsLayer, reopened.AuthenticationType);
        Assert.Equal("LDAP://offline.invalid:636/CN=known,DC=example,DC=test", reopened.Path);
        Assert.Equal(0, admissions);
        // Separate entry configuration is the compatibility behavior, not a
        // newly asserted production defect. It blocks the proposed probe's
        // stronger requirement that every internal read stay referral-free.
    }
}
