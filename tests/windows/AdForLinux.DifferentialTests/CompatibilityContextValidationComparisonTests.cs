using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class CompatibilityContextValidationComparisonTests
{
    // Safety basis: the pinned Microsoft package's full constructor validates
    // credentials, option bits, Domain bind combinations, then contextType,
    // all BEFORE DoServerVerifyAndPropRetrieval. Every row below must reject
    // inside that prefix; do not add valid constructor cases to this class.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Context.cs
    // Source blob: c5262bc1b1c18d5cc4de1d58ca47a80b4d2cd4ac
    private const string SyntheticServer = "compatibility-context.invalid";

    [Theory]
    [InlineData("missing user before invalid type", 999, SyntheticServer, 1, null, "synthetic-password")]
    [InlineData("missing password before invalid type", 999, SyntheticServer, 1, "synthetic-user", null)]
    [InlineData("credentials before type and unknown options", 999, SyntheticServer, 0x400, null, "synthetic-password")]
    [InlineData("credentials before type and missing bind mode", 999, SyntheticServer, 0, "synthetic-user", null)]
    [InlineData("unknown option before invalid type", 999, SyntheticServer, 0x400, null, null)]
    [InlineData("negative options before invalid type", 999, SyntheticServer, -1, null, null)]
    [InlineData("invalid type with missing bind mode", 999, SyntheticServer, 0, null, null)]
    [InlineData("invalid type with both bind modes", 999, SyntheticServer, 3, null, null)]
    [InlineData("Domain missing bind mode", (int)Ms.ContextType.Domain, SyntheticServer, 0, null, null)]
    [InlineData("Domain both bind modes", (int)Ms.ContextType.Domain, SyntheticServer, 3, null, null)]
    [InlineData("Domain TLS without bind mode", (int)Ms.ContextType.Domain, SyntheticServer, 4, null, null)]
    [InlineData("Domain both bind modes with TLS", (int)Ms.ContextType.Domain, SyntheticServer, 7, null, null)]
    [InlineData("credentials before null server", (int)Ms.ContextType.Domain, null, 1, null, "synthetic-password")]
    [InlineData("credentials before empty server", (int)Ms.ContextType.Domain, "", 1, "synthetic-user", null)]
    [InlineData("unknown options before null server", (int)Ms.ContextType.Domain, null, 0x400, null, null)]
    [InlineData("missing bind mode before empty server", (int)Ms.ContextType.Domain, "", 0, null, null)]
    public void Full_constructor_local_validation_precedence_matches_microsoft(
        string scenario, int contextType, string? name, int options, string? userName, string? password)
    {
        // This guard prevents accidental future data additions from reaching
        // server verification. It encodes only the source-audited rejection
        // conditions, not an expected exception type or validation precedence.
        Assert.True(RejectsBeforeServerVerification(contextType, options, userName, password),
            "Offline constructor rows must fail a source-audited local validation check.");
        var expected = Record.Exception(() =>
        {
            using var context = new Ms.PrincipalContext((Ms.ContextType)contextType,
                name, null, (Ms.ContextOptions)options, userName, password);
        });
        var actual = Record.Exception(() =>
        {
            using var context = new Ours.PrincipalContext((Ours.ContextType)contextType,
                name, null, (Ours.ContextOptions)options, userName, password);
        });

        Assert.NotNull(expected);
        // Avoid comparing localized exception text or enum type names embedded
        // in messages. ParamName exposes the winning validation rule directly.
        new Comparison($"PrincipalContext full constructor: {scenario}")
            .Check("exception type", expected.GetType().FullName, actual?.GetType().FullName)
            .Check("parameter", (expected as ArgumentException)?.ParamName, (actual as ArgumentException)?.ParamName)
            .Assert();
    }

    private static bool RejectsBeforeServerVerification(int contextType, int options, string? userName, string? password)
    {
        const int knownOptions = (int)(Ms.ContextOptions.Negotiate | Ms.ContextOptions.SimpleBind |
            Ms.ContextOptions.SecureSocketLayer | Ms.ContextOptions.Signing |
            Ms.ContextOptions.Sealing | Ms.ContextOptions.ServerBind);
        var bindModes = options & (int)(Ms.ContextOptions.Negotiate | Ms.ContextOptions.SimpleBind);
        return (userName is null) != (password is null)
            || (options & ~knownOptions) != 0
            || !Enum.IsDefined(typeof(Ms.ContextType), contextType)
            || (contextType == (int)Ms.ContextType.Domain &&
                (bindModes == 0 || bindModes == (int)(Ms.ContextOptions.Negotiate | Ms.ContextOptions.SimpleBind)));
    }
}
