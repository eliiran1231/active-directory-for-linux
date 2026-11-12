#pragma warning disable CA1416 // Shared framework enum values only.
using System.Security.Principal;
using P = AdForLinux.Security.Principal;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    // Regression expectations reported by Windows probe 37737445450. These are
    // focused assertions, not replacement or reconstructed oracle recordings.
    [Theory]
    [InlineData("S-1-5-32-575", 95, true)]
    [InlineData("S-1-5-32-575", 96, false)]
    [InlineData("S-1-5-32-576", 95, false)]
    [InlineData("S-1-5-32-576", 96, true)]
    [InlineData("RA", 95, true)]
    [InlineData("RA", 96, false)]
    [InlineData("ES", 95, false)]
    [InlineData("ES", 96, true)]
    public void Native_classification_extends_past_managed_constructor_bound(string value, int type, bool expected)
    {
        var sid = new P.SecurityIdentifier(value);
        Assert.Equal(expected, sid.IsWellKnown((WellKnownSidType)type));
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        Assert.Equal(expected, new P.SecurityIdentifier(bytes, 0).IsWellKnown((WellKnownSidType)type));
        Assert.Equal("sidType", Assert.Throws<ArgumentException>(() =>
            new P.SecurityIdentifier((WellKnownSidType)type, null)).ParamName);
    }
}
