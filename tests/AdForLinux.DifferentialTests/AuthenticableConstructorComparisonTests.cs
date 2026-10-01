using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Normal subclass constructors expose the protected API, without a context,
// directory connection, reflection, or fabricated objects.
public sealed class AuthenticableConstructorComparisonTests
{
    private sealed class MicrosoftPrincipal : Ms.AuthenticablePrincipal
    {
        public MicrosoftPrincipal(Ms.PrincipalContext context) : base(context) { }
        public MicrosoftPrincipal(Ms.PrincipalContext context, string name, string password, bool enabled)
            : base(context, name, password, enabled) { }
    }

    private sealed class OurPrincipal : Ours.AuthenticablePrincipal
    {
        public OurPrincipal(Ours.PrincipalContext context) : base(context) { }
        public OurPrincipal(Ours.PrincipalContext context, string name, string password, bool enabled)
            : base(context, name, password, enabled) { }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Null_context_validation_matches_microsoft(bool credentialOverload)
    {
        var expected = Record.Exception(() =>
        {
            using var principal = credentialOverload
                ? new MicrosoftPrincipal(null!, "name", "password", false)
                : new MicrosoftPrincipal(null!);
        });
        var actual = Record.Exception(() =>
        {
            using var principal = credentialOverload
                ? new OurPrincipal(null!, "name", "password", false)
                : new OurPrincipal(null!);
        });

        Assert.IsAssignableFrom<ArgumentException>(expected);
        Assert.Equal((expected.GetType(), (expected as ArgumentException)?.ParamName),
            (actual?.GetType(), (actual as ArgumentException)?.ParamName));
    }
}
