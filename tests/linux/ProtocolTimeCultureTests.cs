using System.Globalization;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public sealed class ProtocolTimeCultureTests
{
    [Theory]
    [InlineData("")]
    [InlineData("fa-IR")]
    [InlineData("ar-SA")]
    public void Ad_time_attributes_keep_protocol_meaning_across_cultures(string culture)
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
            Assert.Equal(TimeSpan.FromMinutes(30), AdFileTime.ToDuration("-18000000000"));
            Assert.Equal(TimeSpan.FromMinutes(30), AdFileTime.ToDuration(-18000000000L));
            Assert.Null(AdFileTime.ToDuration("0"));
            Assert.Null(AdFileTime.ToDuration(long.MinValue));
            Assert.Null(AdFileTime.ToDuration(null));
            Assert.Null(AdFileTime.ToDuration("-9223372036854775808"));
            Assert.Null(AdFileTime.ToDateTime("9223372036854775807"));
            Assert.Throws<ArgumentOutOfRangeException>(() => AdFileTime.ToDateTime("-1"));
            var instant = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
            var wire = instant.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);
            Assert.Equal(wire, AdFileTime.FromDateTime(instant));
            Assert.Equal(instant, AdFileTime.ToDateTime(wire));
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }
}
