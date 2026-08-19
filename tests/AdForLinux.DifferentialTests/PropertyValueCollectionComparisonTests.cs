using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

[Collection("differential")]
public sealed class PropertyValueCollectionComparisonTests : IClassFixture<TestDataFixture>
{
    private readonly TestDataFixture _data;

    public PropertyValueCollectionComparisonTests(TestDataFixture data)
    {
        _data = data;
    }

    [Fact]
    public void Case_varied_strings_and_equal_byte_arrays_use_object_equality()
    {
        using var microsoft = new Ms.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        using var ours = new Ours.DirectoryEntry(
            DifferentialSettings.PathFor(_data.UserDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

        var microsoftResult = Exercise(
            microsoft.Properties["description"],
            microsoft.Properties["audio"]);
        var ourResult = Exercise(
            ours.Properties["description"],
            ours.Properties["audio"]);

        new Comparison("PropertyValueCollection object equality")
            .Check("case-varied Contains", microsoftResult.CaseContains, ourResult.CaseContains)
            .Check("case-varied IndexOf", microsoftResult.CaseIndex, ourResult.CaseIndex)
            .Check("case-varied Remove count", microsoftResult.AfterCaseRemove, ourResult.AfterCaseRemove)
            .Check("equal byte[] Contains", microsoftResult.BytesContains, ourResult.BytesContains)
            .Check("equal byte[] IndexOf", microsoftResult.BytesIndex, ourResult.BytesIndex)
            .Check("equal byte[] Remove count", microsoftResult.AfterBytesRemove, ourResult.AfterBytesRemove)
            .Assert();
    }

    private static EqualityResult Exercise(
        Ms.PropertyValueCollection strings,
        Ms.PropertyValueCollection binary)
    {
        strings.Value = "CaseSensitive";
        var caseContains = strings.Contains("casesensitive");
        var caseIndex = strings.IndexOf("casesensitive");
        strings.Remove("casesensitive");
        var afterCaseRemove = strings.Count;

        var storedBytes = new byte[] { 1, 2, 3 };
        binary.Value = storedBytes;
        var equalBytes = new byte[] { 1, 2, 3 };
        var bytesContains = binary.Contains(equalBytes);
        var bytesIndex = binary.IndexOf(equalBytes);
        binary.Remove(equalBytes);
        return new EqualityResult(
            caseContains,
            caseIndex,
            afterCaseRemove,
            bytesContains,
            bytesIndex,
            binary.Count);
    }

    private static EqualityResult Exercise(
        Ours.PropertyValueCollection strings,
        Ours.PropertyValueCollection binary)
    {
        strings.Value = "CaseSensitive";
        var caseContains = strings.Contains("casesensitive");
        var caseIndex = strings.IndexOf("casesensitive");
        strings.Remove("casesensitive");
        var afterCaseRemove = strings.Count;

        var storedBytes = new byte[] { 1, 2, 3 };
        binary.Value = storedBytes;
        var equalBytes = new byte[] { 1, 2, 3 };
        var bytesContains = binary.Contains(equalBytes);
        var bytesIndex = binary.IndexOf(equalBytes);
        binary.Remove(equalBytes);
        return new EqualityResult(
            caseContains,
            caseIndex,
            afterCaseRemove,
            bytesContains,
            bytesIndex,
            binary.Count);
    }

    private sealed record EqualityResult(
        bool CaseContains,
        int CaseIndex,
        int AfterCaseRemove,
        bool BytesContains,
        int BytesIndex,
        int AfterBytesRemove);
}
