using System.Globalization;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    // Microsoft's ADUtils.DateTimeToADString and DateTimeToADFileTime call
    // ToFileTimeUtc directly. Unspecified therefore preserves its UTC ticks;
    // Local alone applies the local offset. No process timezone is changed.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADUtils.cs
    [Theory]
    [InlineData(DateTimeKind.Utc)]
    [InlineData(DateTimeKind.Local)]
    [InlineData(DateTimeKind.Unspecified)]
    public void Expiration_FILETIME_conversion_only_offsets_explicit_Local_values(DateTimeKind kind)
    {
        var value=new DateTime(2030,6,1,12,34,56,kind).AddTicks(1234);
        const long wallClockFileTime=135510212960001234;
        var expected=kind==DateTimeKind.Local
            ? wallClockFileTime-TimeZoneInfo.Local.GetUtcOffset(value).Ticks
            : wallClockFileTime;
        Assert.Equal(expected.ToString(CultureInfo.InvariantCulture),AdFileTime.FromDateTime(value));
        var decoded=AdFileTime.ToDateTime(AdFileTime.FromDateTime(value));
        Assert.NotNull(decoded);
        Assert.Equal(DateTimeKind.Utc,decoded.Value.Kind);
        Assert.Equal(expected,decoded.Value.ToFileTimeUtc());
    }
}
