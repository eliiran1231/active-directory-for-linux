using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public class SynchronizationCookieIdentityComparisonTests
{
    [Theory]
    [InlineData("Default")]
    [InlineData("EmptyInput")]
    [InlineData("NullInput")]
    [InlineData("Reset")]
    [InlineData("ResetNull")]
    [InlineData("ResetEmpty")]
    [InlineData("Nonempty")]
    public void Repeated_cookie_reads_have_the_same_identity_semantics_as_microsoft(string scenario)
    {
        var microsoft = new Ms.DirectorySynchronization(new byte[] { 1, 2, 3 });
        var ours = new Ours.DirectorySynchronization(new byte[] { 1, 2, 3 });
        switch (scenario)
        {
            case "Default":
                microsoft = new Ms.DirectorySynchronization();
                ours = new Ours.DirectorySynchronization();
                break;
            case "EmptyInput":
                microsoft = new Ms.DirectorySynchronization(Array.Empty<byte>());
                ours = new Ours.DirectorySynchronization(Array.Empty<byte>());
                break;
            case "NullInput":
                microsoft = new Ms.DirectorySynchronization((byte[]?)null);
                ours = new Ours.DirectorySynchronization((byte[]?)null);
                break;
            case "Reset":
                microsoft.ResetDirectorySynchronizationCookie();
                ours.ResetDirectorySynchronizationCookie();
                break;
            case "ResetNull":
                microsoft.ResetDirectorySynchronizationCookie(null);
                ours.ResetDirectorySynchronizationCookie(null);
                break;
            case "ResetEmpty":
                microsoft.ResetDirectorySynchronizationCookie(Array.Empty<byte>());
                ours.ResetDirectorySynchronizationCookie(Array.Empty<byte>());
                break;
        }

        var expectedFirst = microsoft.GetDirectorySynchronizationCookie();
        var expectedSecond = microsoft.GetDirectorySynchronizationCookie();
        var actualFirst = ours.GetDirectorySynchronizationCookie();
        var actualSecond = ours.GetDirectorySynchronizationCookie();
        Assert.Equal(expectedFirst, actualFirst);
        Assert.Equal(expectedSecond, actualSecond);
        Assert.Equal(ReferenceEquals(expectedFirst, expectedSecond),
            ReferenceEquals(actualFirst, actualSecond));
    }
}
