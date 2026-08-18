using System.Collections;
using System.Globalization;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

/// <summary>
/// Live Windows ADSI comparisons for issue #39. Objects are created directly
/// below AD_BASE_DN so callers can give this class an isolated test OU.
/// </summary>
[Collection("differential")]
public sealed class PropertyValueTypeComparisonTests
{
    private static Ms.DirectoryEntry MicrosoftEntry(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);

    private static Ours.DirectoryEntry OurEntry(string dn) =>
        new(
            DifferentialSettings.PathFor(dn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

    [Fact]
    public void DirectoryEntry_and_SearchResult_preserve_schema_CLR_types()
    {
        var name = $"i39-{Guid.NewGuid():N}"[..18];
        var dn = $"CN={name},{DifferentialSettings.BaseDn}";

        try
        {
            CreateMicrosoftTypedUser(dn, name);

            using var microsoft = MicrosoftEntry(dn);
            using var ours = OurEntry(dn);

            CompareProperty(microsoft.Properties["userAccountControl"], ours.Properties["userAccountControl"]);
            CompareProperty(microsoft.Properties["msNPAllowDialin"], ours.Properties["msNPAllowDialin"]);
            CompareProperty(microsoft.Properties["msTSExpireDate"], ours.Properties["msTSExpireDate"]);
            CompareProperty(microsoft.Properties["objectSid"], ours.Properties["objectSid"]);
            CompareProperty(microsoft.Properties["objectGUID"], ours.Properties["objectGUID"]);
            CompareProperty(microsoft.Properties["audio"], ours.Properties["audio"]);
            CompareProperty(microsoft.Properties["description"], ours.Properties["description"]);

            using var microsoftSearcher = new Ms.DirectorySearcher(
                microsoft,
                "(objectClass=*)",
                TypeAttributes,
                Ms.SearchScope.Base);
            using var ourSearcher = new Ours.DirectorySearcher(
                ours,
                "(objectClass=*)",
                TypeAttributes,
                Ours.SearchScope.Base);
            var microsoftResult = microsoftSearcher.FindOne();
            var ourResult = ourSearcher.FindOne();
            Assert.NotNull(microsoftResult);
            Assert.NotNull(ourResult);

            foreach (var attributeName in TypeAttributes)
            {
                CompareValues(
                    microsoftResult.Properties[attributeName].Cast<object>(),
                    ourResult.Properties[attributeName].Cast<object>());
            }
        }
        finally
        {
            SafeDeleteMicrosoft(dn);
        }
    }

    [Fact]
    public void Typed_writes_are_culture_invariant_and_round_trip()
    {
        var name = $"i39w-{Guid.NewGuid():N}"[..18];
        var dn = $"CN={name},{DifferentialSettings.BaseDn}";
        var previousCulture = CultureInfo.CurrentCulture;
        var previousUiCulture = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("ar-SA");
            using (var parent = OurEntry(DifferentialSettings.BaseDn))
            using (var user = parent.Children.Add($"CN={name}", "user"))
            {
                user.Properties["sAMAccountName"].Value = name;
                user.Properties["msNPAllowDialin"].Value = true;
                user.Properties["msTSExpireDate"].Value = TestTimestamp;
                user.Properties["audio"].Add(new byte[] { 0, 1, 2, 255 });
                user.Properties["audio"].Add(new byte[] { 9, 8, 7 });
                user.CommitChanges();
            }

            using var microsoft = MicrosoftEntry(dn);
            using var ours = OurEntry(dn);
            CompareProperty(microsoft.Properties["msNPAllowDialin"], ours.Properties["msNPAllowDialin"]);
            CompareProperty(microsoft.Properties["msTSExpireDate"], ours.Properties["msTSExpireDate"]);
            CompareProperty(microsoft.Properties["audio"], ours.Properties["audio"]);
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
            CultureInfo.CurrentUICulture = previousUiCulture;
            SafeDeleteOur(dn);
        }
    }

    private static readonly string[] TypeAttributes =
    {
        "userAccountControl", "msNPAllowDialin", "msTSExpireDate", "accountExpires",
        "objectSid", "objectGUID", "audio", "description",
    };

    private static readonly DateTime TestTimestamp =
        new(2031, 2, 3, 4, 5, 6, DateTimeKind.Utc);

    private static void CreateMicrosoftTypedUser(string dn, string name)
    {
        using var parent = MicrosoftEntry(DifferentialSettings.BaseDn);
        using var user = parent.Children.Add($"CN={name}", "user");
        user.Properties["sAMAccountName"].Value = name;
        user.Properties["msNPAllowDialin"].Value = true;
        user.Properties["msTSExpireDate"].Value = TestTimestamp;
        user.Properties["audio"].Add(new byte[] { 0, 1, 2, 255 });
        user.Properties["audio"].Add(new byte[] { 9, 8, 7 });
        user.Properties["description"].Add("one");
        user.Properties["description"].Add("two");
        user.CommitChanges();
    }

    private static void CompareProperty(Ms.PropertyValueCollection expected, Ours.PropertyValueCollection actual) =>
        CompareValues(expected.Cast<object>(), actual.Cast<object>());

    private static void CompareValues(IEnumerable<object> expected, IEnumerable<object> actual)
    {
        var expectedValues = expected.ToArray();
        var actualValues = actual.ToArray();
        Assert.Equal(expectedValues.Length, actualValues.Length);

        var unmatched = actualValues.ToList();
        foreach (var expectedValue in expectedValues)
        {
            var match = unmatched.FindIndex(value => ValuesEqual(expectedValue, value));
            Assert.True(
                match >= 0,
                $"No exact type/value match for {Format(expectedValue)} in [{string.Join(", ", unmatched.Select(Format))}].");
            unmatched.RemoveAt(match);
        }
    }

    private static bool ValuesEqual(object expected, object actual)
    {
        if (expected.GetType() != actual.GetType())
        {
            return false;
        }

        return expected is byte[] expectedBytes
            ? expectedBytes.SequenceEqual((byte[])actual)
            : expected.Equals(actual);
    }

    private static string Format(object value) => value is byte[] bytes
        ? $"Byte[]:{Convert.ToHexString(bytes)}"
        : $"{value.GetType().Name}:{value}";

    private static void SafeDeleteMicrosoft(string dn)
    {
        try
        {
            using var entry = MicrosoftEntry(dn);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup for a failed differential assertion.
        }
    }

    private static void SafeDeleteOur(string dn)
    {
        try
        {
            using var entry = OurEntry(dn);
            entry.DeleteTree();
        }
        catch
        {
            // Best effort cleanup for a failed differential assertion.
        }
    }
}
