using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class DirectoryEntryObjectValidationComparisonTests
{
    [Theory]
    [InlineData("null")]
    [InlineData("plain-object")]
    [InlineData("boxed-number")]
    [InlineData("path-as-object")]
    public void Object_constructor_rejects_non_ADSI_objects_like_microsoft(string input)
    {
        object? value = input switch
        {
            "null" => null,
            "plain-object" => new object(),
            "boxed-number" => 42,
            "path-as-object" => "LDAP://unused.example.test/DC=example,DC=test",
            _ => throw new ArgumentOutOfRangeException(nameof(input)),
        };

        // The static object type deliberately selects the ADSI-object overload,
        // including for strings. None of these inputs implements IADs, so this
        // tests portable input validation, not support for a live COM object.
        var expected = Record.Exception(() => { using var entry = new Ms.DirectoryEntry(value!); });
        var actual = Record.Exception(() => { using var entry = new Ours.DirectoryEntry(value!); });

        var expectedArgument = Assert.IsType<ArgumentException>(expected);
        Assert.Equal(
            (expectedArgument.GetType(), expectedArgument.ParamName),
            (actual?.GetType(), (actual as ArgumentException)?.ParamName));
    }
}
