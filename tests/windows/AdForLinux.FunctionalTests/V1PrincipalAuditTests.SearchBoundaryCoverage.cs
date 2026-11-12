using System.Globalization;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using P = System.DirectoryServices.Protocols;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private static P.SearchRequest BuildOfflineSearchRequest(DirectorySearcher searcher)
        => (P.SearchRequest)typeof(DirectorySearcher).GetMethod("BuildRequest",
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null)!.Invoke(searcher, null)!;

    [Theory]
    [InlineData(SearchScope.Base, P.SearchScope.Base)]
    [InlineData(SearchScope.OneLevel, P.SearchScope.OneLevel)]
    [InlineData(SearchScope.Subtree, P.SearchScope.Subtree)]
    public void Search_request_preserves_scope_projection_limits_and_control_meaning(SearchScope scope, P.SearchScope expectedScope)
    {
        using var root = new DirectoryEntry("LDAP://offline.invalid/OU=people,DC=example,DC=test");
        using var searcher = new DirectorySearcher(root, "(&(objectClass=user)(cn=Alice))", ["cn", "objectGUID"], scope)
        {
            SizeLimit = 23,
            ServerTimeLimit = TimeSpan.FromSeconds(17),
            PropertyNamesOnly = true,
            DerefAlias = DereferenceAlias.FindingBaseObject,
            Tombstone = true,
            ExtendedDN = ExtendedDN.Standard,
            SecurityMasks = SecurityMasks.Owner | SecurityMasks.Dacl,
            Sort = new SortOption("cn", SortDirection.Descending),
        };

        var request = BuildOfflineSearchRequest(searcher);
        Assert.Equal("OU=people,DC=example,DC=test", request.DistinguishedName);
        Assert.Equal("(&(objectClass=user)(cn=Alice))", request.Filter);
        Assert.Equal(expectedScope, request.Scope);
        Assert.Equal(new[] { "cn", "objectGUID", "ADsPath" }, request.Attributes.Cast<string>());
        Assert.Equal(23, request.SizeLimit);
        Assert.Equal(TimeSpan.FromSeconds(17), request.TimeLimit);
        Assert.True(request.TypesOnly);
        Assert.Equal(P.DereferenceAlias.FindingBaseObject, request.Aliases);
        Assert.Equal(4, request.Controls.Count);
        Assert.Single(request.Controls.OfType<P.ShowDeletedControl>());
        Assert.Equal(P.ExtendedDNFlag.StandardString, Assert.Single(request.Controls.OfType<P.ExtendedDNControl>()).Flag);
        Assert.Equal(P.SecurityMasks.Owner | P.SecurityMasks.Dacl,
            Assert.Single(request.Controls.OfType<P.SecurityDescriptorFlagControl>()).SecurityMasks);
        var key = Assert.Single(Assert.Single(request.Controls.OfType<P.SortRequestControl>()).SortKeys);
        Assert.Equal("cn", key.AttributeName);
        Assert.True(key.ReverseOrder);

        // Building the same query again must not grow its requested projection.
        Assert.Equal(request.Attributes.Cast<string>(), BuildOfflineSearchRequest(searcher).Attributes.Cast<string>());
    }

    [Fact]
    public void Directory_sync_cookies_are_isolated_across_input_getter_copy_and_requests()
    {
        byte[] initial = [1, 2, 3, 255];
        var sync = new DirectorySynchronization(DirectorySynchronizationOptions.IncrementalValues, initial);
        initial[0] = 9;
        var returned = sync.GetDirectorySynchronizationCookie();
        returned[1] = 9;
        var copy = sync.Copy();
        sync.ResetDirectorySynchronizationCookie([8, 7]);
        using var root = new DirectoryEntry("LDAP://offline.invalid/DC=example,DC=test");
        using var searcher = new DirectorySearcher(root) { DirectorySynchronization = copy };

        var first = Assert.Single(BuildOfflineSearchRequest(searcher).Controls.OfType<P.DirSyncRequestControl>());
        Assert.Equal(new byte[] { 1, 2, 3, 255 }, first.Cookie);
        Assert.Equal(P.DirectorySynchronizationOptions.IncrementalValues, first.Option);
        copy.ResetDirectorySynchronizationCookie([4, 5]);
        var next = Assert.Single(BuildOfflineSearchRequest(searcher).Controls.OfType<P.DirSyncRequestControl>());
        Assert.Equal(new byte[] { 4, 5 }, next.Cookie);
        Assert.Equal(new byte[] { 1, 2, 3, 255 }, first.Cookie);
        Assert.Equal(new byte[] { 8, 7 }, sync.GetDirectorySynchronizationCookie());
    }

    [Theory]
    [InlineData("20240229013045Z", 2024, 2, 29, 1, 30, 45)]
    [InlineData("20240301013045+0230", 2024, 2, 29, 23, 0, 45)]
    [InlineData("20240229233045-0130", 2024, 3, 1, 1, 0, 45)]
    [InlineData("240229013045Z", 2024, 2, 29, 1, 30, 45)]
    public void Directory_time_conversion_normalizes_offsets_across_calendar_boundaries(
        string raw, int year, int month, int day, int hour, int minute, int second)
    {
        var converted = Assert.IsType<DateTime>(SearchEntryReader.ConvertValue(raw, LdapValueKind.DateTime));
        Assert.Equal(new DateTime(year, month, day, hour, minute, second, DateTimeKind.Unspecified), converted);
        Assert.Equal(DateTimeKind.Unspecified, converted.Kind);
    }

    [Fact]
    public void Directory_time_conversion_preserves_seven_fractional_digits()
    {
        var converted = Assert.IsType<DateTime>(SearchEntryReader.ConvertValue("20240229013045.1234567Z", LdapValueKind.DateTime));
        Assert.Equal(new DateTime(2024, 2, 29, 1, 30, 45).AddTicks(1234567), converted);
    }

    [Theory]
    [InlineData("20230229013045Z")]
    [InlineData("20240230013045Z")]
    [InlineData("20240229013060Z")]
    [InlineData("not-a-time")]
    [InlineData("")]
    public void Invalid_directory_time_is_rejected_instead_of_becoming_a_default(string raw)
        => Assert.Throws<FormatException>(() => SearchEntryReader.ConvertValue(raw, LdapValueKind.DateTime));

    [Fact]
    public void Directory_integer_conversion_uses_wire_culture_and_preserves_signed_boundaries()
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            Assert.Equal(int.MinValue, Assert.IsType<int>(SearchEntryReader.ConvertValue("-2147483648", LdapValueKind.Int32)));
            Assert.Equal(int.MaxValue, Assert.IsType<int>(SearchEntryReader.ConvertValue("2147483647", LdapValueKind.Int32)));
            Assert.Equal(long.MinValue, Assert.IsType<long>(SearchEntryReader.ConvertValue("-9223372036854775808", LdapValueKind.Int64)));
            Assert.Equal(long.MaxValue, Assert.IsType<long>(SearchEntryReader.ConvertValue("9223372036854775807", LdapValueKind.Int64)));
            Assert.Throws<OverflowException>(() => SearchEntryReader.ConvertValue("2147483648", LdapValueKind.Int32));
            Assert.Throws<OverflowException>(() => SearchEntryReader.ConvertValue("9223372036854775808", LdapValueKind.Int64));
            Assert.Throws<FormatException>(() => SearchEntryReader.ConvertValue("1,234", LdapValueKind.Int32));
        }
        finally { CultureInfo.CurrentCulture = original; }
    }

    [Theory]
    [InlineData("TRUE", true)]
    [InlineData("FALSE", false)]
    public void Directory_boolean_conversion_preserves_protocol_values(string raw, bool expected)
        => Assert.Equal(expected, Assert.IsType<bool>(SearchEntryReader.ConvertValue(raw, LdapValueKind.Boolean)));

    [Theory]
    [InlineData("1")]
    [InlineData("0")]
    [InlineData("yes")]
    public void Nonboolean_wire_values_are_rejected(string raw)
        => Assert.Throws<FormatException>(() => SearchEntryReader.ConvertValue(raw, LdapValueKind.Boolean));
}
