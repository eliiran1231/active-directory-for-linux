using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Valid contexts can bind to AD. Principals remain unsaved: no account creation,
// password transmission or other directory mutation occurs in these methods.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityAuthenticableCredentialConstructorComparisonTests
{
    // Unlike the public UserPrincipal/ComputerPrincipal credential constructors,
    // this protected constructor skips missing credentials and never assigns Name.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AuthenticablePrincipal.cs#L337
    [Theory]
    [InlineData("missing-credentials")]
    [InlineData("credentials")]
    [InlineData("explicit-assignment-control")]
    public void Protected_credential_constructor_initializes_only_supplied_properties(string scenario)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            Ms.ContextOptions.SimpleBind | Ms.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            Ours.ContextOptions.SimpleBind | Ours.ContextOptions.SecureSocketLayer,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        MicrosoftPrincipal? expected = null;
        OurPrincipal? actual = null;
        try
        {
            var expectedError = Record.Exception(() => expected = MakeMicrosoft(expectedContext, scenario));
            var actualError = Record.Exception(() => actual = MakeOurs(actualContext, scenario));
            Assert.Null(expectedError);
            Assert.NotNull(expected);
            Assert.Null(expected.Name);
            Assert.Equal(scenario == "missing-credentials" ? null : AccountName, expected.SamAccountName);
            Assert.False(expected.Enabled);
            Assert.Null(expected.Guid);
            Assert.Null(expected.DistinguishedName);
            Assert.Same(expectedContext, expected.Context);
            var comparison = new Comparison($"Protected AuthenticablePrincipal credential constructor: {scenario}")
                .Check("constructor exception", Error(expectedError), Error(actualError));
            if (actualError is null)
            {
                Assert.NotNull(actual);
                Assert.Same(actualContext, actual.Context);
                Assert.Null(actual.Guid);
                Assert.Null(actual.DistinguishedName);
                comparison.Check("Name", expected.Name, actual.Name)
                    .Check("SamAccountName", expected.SamAccountName, actual.SamAccountName)
                    .Check("Enabled", expected.Enabled, actual.Enabled);
            }
            comparison.Assert();
        }
        finally
        {
            expected?.Dispose();
            actual?.Dispose();
        }
    }

    private const string AccountName = "compat-ctor-staged";
    // Merely staged in an unsaved principal; never sent or included in diagnostics.
    private const string StagedPassword = "Str0ng!Passw0rd#2026";
    private static string? Error(Exception? error) => error is null ? null
        : $"{error.GetType().Name}|{(error as ArgumentException)?.ParamName}";

    private static MicrosoftPrincipal MakeMicrosoft(Ms.PrincipalContext context, string scenario)
    {
        if (scenario == "missing-credentials") return new(context, null, null);
        if (scenario == "credentials") return new(context, AccountName, StagedPassword);
        var principal = new MicrosoftPrincipal(context);
        principal.SamAccountName = AccountName;
        principal.SetPassword(StagedPassword);
        principal.Enabled = false;
        return principal;
    }

    private static OurPrincipal MakeOurs(Ours.PrincipalContext context, string scenario)
    {
        if (scenario == "missing-credentials") return new(context, null, null);
        if (scenario == "credentials") return new(context, AccountName, StagedPassword);
        var principal = new OurPrincipal(context);
        principal.SamAccountName = AccountName;
        principal.SetPassword(StagedPassword);
        principal.Enabled = false;
        return principal;
    }

    [Ms.DirectoryObjectClass("user")]
    [Ms.DirectoryRdnPrefix("CN")]
    public sealed class MicrosoftPrincipal : Ms.AuthenticablePrincipal
    {
        public MicrosoftPrincipal(Ms.PrincipalContext context) : base(context) { }
        public MicrosoftPrincipal(Ms.PrincipalContext context, string? sam, string? password)
            : base(context, sam!, password!, false) { }
    }

    [Ours.DirectoryObjectClass("user")]
    [Ours.DirectoryRdnPrefix("CN")]
    public sealed class OurPrincipal : Ours.AuthenticablePrincipal
    {
        public OurPrincipal(Ours.PrincipalContext context) : base(context) { }
        public OurPrincipal(Ours.PrincipalContext context, string? sam, string? password)
            : base(context, sam!, password!, false) { }
    }
}
