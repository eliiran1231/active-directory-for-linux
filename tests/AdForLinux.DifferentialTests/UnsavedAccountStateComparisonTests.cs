using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Context construction/property validation can contact AD, but these tests never
// save a principal or mutate the directory. Use the usual AD_* settings.
[Collection("differential")]
public sealed class UnsavedAccountStateComparisonTests(ITestOutputHelper output)
{
    private static Ms.PrincipalContext MicrosoftContext() =>
        new(Ms.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.MicrosoftContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    private static Ours.PrincipalContext OurContext() =>
        new(Ours.ContextType.Domain, DifferentialSettings.ServerName,
            DifferentialSettings.UsersContainer, DifferentialSettings.OurContextOptions,
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Unassigned_delegation_permission_matches_microsoft(bool computer)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        using Ms.AuthenticablePrincipal microsoft = computer
            ? new Ms.ComputerPrincipal(microsoftContext) : new Ms.UserPrincipal(microsoftContext);
        using Ours.AuthenticablePrincipal ours = computer
            ? new Ours.ComputerPrincipal(ourContext) : new Ours.UserPrincipal(ourContext);

        Assert.Null(microsoft.Enabled);
        Assert.Null(ours.Enabled);
        Compare(microsoft.DelegationPermitted, ours.DelegationPermitted);
    }

    [Theory]
    [InlineData("PasswordNeverExpires", false)]
    [InlineData("PasswordNeverExpires", true)]
    [InlineData("PasswordNotRequired", false)]
    [InlineData("PasswordNotRequired", true)]
    [InlineData("SmartcardLogonRequired", false)]
    [InlineData("SmartcardLogonRequired", true)]
    [InlineData("AllowReversiblePasswordEncryption", false)]
    [InlineData("AllowReversiblePasswordEncryption", true)]
    [InlineData("DelegationPermitted", false)]
    [InlineData("DelegationPermitted", true)]
    public void Setting_an_account_flag_preserves_unassigned_enabled_state(string property, bool value)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var microsoft = new Ms.UserPrincipal(microsoftContext);
        using var ours = new Ours.UserPrincipal(ourContext);
        Assert.Null(microsoft.Enabled);
        Assert.Null(ours.Enabled);

        // Reflection selects the same public property; no private state is used.
        var expectedProperty = typeof(Ms.UserPrincipal).GetProperty(property)!;
        var actualProperty = typeof(Ours.UserPrincipal).GetProperty(property)!;
        expectedProperty.SetValue(microsoft, value);
        actualProperty.SetValue(ours, value);
        Assert.Equal(value, expectedProperty.GetValue(microsoft));
        Assert.Equal(value, actualProperty.GetValue(ours));

        var expected = new List<bool?> { microsoft.Enabled };
        var actual = new List<bool?> { ours.Enabled };
        // Controls: explicit Enabled assignments must still work and survive
        // subsequent changes to another flag. Collect before asserting so the
        // initial mismatch does not prevent these transitions from running.
        foreach (var enabled in new[] { false, true })
        {
            microsoft.Enabled = ours.Enabled = enabled;
            expectedProperty.SetValue(microsoft, !value);
            actualProperty.SetValue(ours, !value);
            expected.Add(microsoft.Enabled);
            actual.Add(ours.Enabled);
        }

        output.WriteLine($"Microsoft Enabled: {Format(expected)}; AdForLinux Enabled: {Format(actual)}");
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void Pending_password_preserves_the_requested_enabled_value(bool computer, bool credentialOverload)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        const string name = "unsaved-account";
        const string password = "Unsaved!Password42";
        using Ms.AuthenticablePrincipal microsoft = (computer, credentialOverload) switch
        {
            (true, true) => new Ms.ComputerPrincipal(microsoftContext, name, password, true),
            (true, false) => new Ms.ComputerPrincipal(microsoftContext),
            (false, true) => new Ms.UserPrincipal(microsoftContext, name, password, true),
            _ => new Ms.UserPrincipal(microsoftContext),
        };
        using Ours.AuthenticablePrincipal ours = (computer, credentialOverload) switch
        {
            (true, true) => new Ours.ComputerPrincipal(ourContext, name, password, true),
            (true, false) => new Ours.ComputerPrincipal(ourContext),
            (false, true) => new Ours.UserPrincipal(ourContext, name, password, true),
            _ => new Ours.UserPrincipal(ourContext),
        };
        if (!credentialOverload)
        {
            microsoft.SetPassword(password);
            ours.SetPassword(password);
            microsoft.Enabled = ours.Enabled = true;
        }

        var expected = new List<bool?> { microsoft.Enabled };
        var actual = new List<bool?> { ours.Enabled };
        foreach (var enabled in new[] { false, true })
        {
            microsoft.Enabled = ours.Enabled = enabled;
            expected.Add(microsoft.Enabled);
            actual.Add(ours.Enabled);
        }

        output.WriteLine($"Microsoft Enabled: {Format(expected)}; AdForLinux Enabled: {Format(actual)}");
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("utc")] // Control: ordinary UTC dates round-trip in both libraries.
    [InlineData("null")] // Control: clears an already assigned expiration date.
    [InlineData("local")]
    [InlineData("unspecified")]
    [InlineData("filetime-zero")]
    [InlineData("before-filetime-epoch")]
    public void Expiration_assignment_preserves_value_kind_and_validation_timing(string scenario)
    {
        using var microsoftContext = MicrosoftContext();
        using var ourContext = OurContext();
        using var microsoft = new Ms.UserPrincipal(microsoftContext);
        using var ours = new Ours.UserPrincipal(ourContext);
        var seed = new DateTime(2030, 6, 1, 12, 0, 0, DateTimeKind.Utc);
        microsoft.AccountExpirationDate = ours.AccountExpirationDate = seed;
        Assert.Equal(DateState(microsoft.AccountExpirationDate), DateState(ours.AccountExpirationDate));
        DateTime? value = scenario switch
        {
            "utc" => seed.AddDays(1),
            "null" => null,
            "local" => DateTime.SpecifyKind(seed, DateTimeKind.Local),
            "unspecified" => DateTime.SpecifyKind(seed, DateTimeKind.Unspecified),
            "filetime-zero" => DateTime.FromFileTimeUtc(0),
            "before-filetime-epoch" => new DateTime(1500, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
        };

        var expectedError = Record.Exception(() => microsoft.AccountExpirationDate = value);
        var actualError = Record.Exception(() => ours.AccountExpirationDate = value);
        var expected = (Error(expectedError), DateState(microsoft.AccountExpirationDate));
        var actual = (Error(actualError), DateState(ours.AccountExpirationDate));

        // Both instances must remain usable even if the assignment was rejected.
        microsoft.AccountExpirationDate = ours.AccountExpirationDate = seed;
        Assert.Equal(DateState(microsoft.AccountExpirationDate), DateState(ours.AccountExpirationDate));
        Compare(expected, actual);
    }

    private void Compare<T>(T expected, T actual)
    {
        output.WriteLine($"Microsoft: {expected}; AdForLinux: {actual}");
        Assert.Equal(expected, actual);
    }

    // DateTime.Equals ignores Kind, which is part of this public round trip.
    private static (long? Ticks, DateTimeKind? Kind) DateState(DateTime? value) =>
        (value?.Ticks, value?.Kind);

    private static (Type? Type, string? Parameter) Error(Exception? error) =>
        (error?.GetType(), (error as ArgumentException)?.ParamName);

    private static string Format(IEnumerable<bool?> values) =>
        string.Join(", ", values.Select(value => value?.ToString() ?? "null"));
}
