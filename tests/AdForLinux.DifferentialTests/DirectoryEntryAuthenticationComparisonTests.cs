using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Verifies the Windows LDAP ADSI provider's validation of authentication flags
/// against the explicit portable validation performed by AdForLinux.
/// </summary>
public class DirectoryEntryAuthenticationComparisonTests
{
    [Theory]
    [InlineData(0x11, true)] // Secure | Anonymous
    [InlineData(0x40, false)] // Signing
    [InlineData(0x80, false)] // Sealing
    [InlineData(0xC0, false)] // Signing | Sealing
    public void Invalid_authentication_combinations_are_rejected_by_both_providers(
        int authenticationTypes,
        bool expectsInvalidArgument)
    {
        var microsoftAuthenticationTypes = (Ms.AuthenticationTypes)authenticationTypes;
        var ourAuthenticationTypes = (Ours.AuthenticationTypes)authenticationTypes;
        if (DifferentialSettings.UseTls)
        {
            microsoftAuthenticationTypes |= Ms.AuthenticationTypes.SecureSocketsLayer;
            ourAuthenticationTypes |= Ours.AuthenticationTypes.SecureSocketsLayer;
        }

        using var microsoft = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            microsoftAuthenticationTypes);
        using var ours = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            ourAuthenticationTypes);

        var microsoftError = Assert.IsAssignableFrom<COMException>(
            Record.Exception(() => microsoft.RefreshCache(new[] { "distinguishedName" })));
        Assert.IsType<PlatformNotSupportedException>(Record.Exception(() => ours.BuildOptions()));

        if (expectsInvalidArgument)
        {
            Assert.Equal(unchecked((int)0x80070057), microsoftError.HResult); // E_INVALIDARG
        }
        else
        {
            // ADSI reports inappropriate authentication on LDAP and an
            // unwilling-to-perform provider error when signing/sealing is
            // requested over an SSL-configured connection.
            Assert.Contains(
                microsoftError.HResult,
                new[] { unchecked((int)0x80072028), unchecked((int)0x80072035) });
        }
    }
}
