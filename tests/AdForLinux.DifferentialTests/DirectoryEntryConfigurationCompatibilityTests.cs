using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class DirectoryEntryConfigurationCompatibilityTests
{
    [Fact]
    public void Password_port_setter_matches_microsoft_for_nondefault_port()
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();

        var microsoftOptions = Assert.IsType<Ms.DirectoryEntryConfiguration>(microsoft.Options);
        var ourOptions = ours.Options;
        var microsoftError = Record.Exception(() => microsoftOptions.PasswordPort = 1636);
        var ourError = Record.Exception(() => ourOptions.PasswordPort = 1636);

        new Comparison("DirectoryEntryConfiguration.PasswordPort = 1636")
            .Check("exception type", microsoftError?.GetType().Name, ourError?.GetType().Name)
            .Check("stored port", microsoftOptions.PasswordPort, ourOptions.PasswordPort)
            .Assert();
    }

    [Fact]
    public void Clear_password_encoding_setter_matches_microsoft()
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();

        var microsoftOptions = Assert.IsType<Ms.DirectoryEntryConfiguration>(microsoft.Options);
        var ourOptions = ours.Options;
        var microsoftError = Record.Exception(() =>
            microsoftOptions.PasswordEncoding = Ms.PasswordEncodingMethod.PasswordEncodingClear);
        var ourError = Record.Exception(() =>
            ourOptions.PasswordEncoding = Ours.PasswordEncodingMethod.PasswordEncodingClear);

        new Comparison("DirectoryEntryConfiguration.PasswordEncoding = Clear")
            .Check("exception type", microsoftError?.GetType().Name, ourError?.GetType().Name)
            .Check("stored encoding", (int)microsoftOptions.PasswordEncoding, (int)ourOptions.PasswordEncoding)
            .Assert();
    }

    private static Ms.DirectoryEntry MicrosoftEntry() => new(
        DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
        DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword,
        DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry() => new(
        DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
        DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword,
        DifferentialSettings.OurAuthenticationTypes);
}
