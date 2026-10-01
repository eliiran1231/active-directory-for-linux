using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class DirectoryEntryPathEquivalenceComparisonTests
{
    [Theory]
    [InlineData("case", "Alice", "ALICE")]
    [InlineData("different-name", "Alice", "Bob")]
    [InlineData("soft-hyphen", "Alice", "Al\u00adice")]
    [InlineData("canonical-equivalence", "Jos\u00e9", "Jose\u0301")]
    [InlineData("width", "Alice", "\uff21lice")]
    [InlineData("kana", "\u3042", "\u30a2")]
    public void Equivalent_path_assignment_preserves_text_and_property_wrapper_like_microsoft(
        string scenario, string initialName, string replacementName)
    {
        // Only local configuration and wrapper identity are observed. No bind,
        // DNS lookup, or directory normalization participates in the comparison.
        const string prefix = "LDAP://unused.example.test/CN=";
        const string suffix = ",DC=example,DC=test";
        using var microsoft = new Ms.DirectoryEntry(prefix + initialName + suffix);
        using var ours = new Ours.DirectoryEntry(prefix + initialName + suffix);
        var microsoftProperties = microsoft.Properties;
        var ourProperties = ours.Properties;

        microsoft.Path = prefix + replacementName + suffix;
        ours.Path = prefix + replacementName + suffix;

        new Comparison($"Path equivalence: {scenario}")
            .Check("stored Path", microsoft.Path, ours.Path)
            .Check("preserved property wrapper", ReferenceEquals(microsoftProperties, microsoft.Properties),
                ReferenceEquals(ourProperties, ours.Properties))
            .Assert();
    }
}
