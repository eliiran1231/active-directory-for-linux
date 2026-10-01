using System.Collections;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Public API only: constructing/accessing collection wrappers must not bind.
public sealed class PropertyCollectionBindingComparisonTests
{
    // Signing without Secure is deliberately incomplete configuration. Our
    // binding validation rejects it before network access; Microsoft permits
    // accessing these wrappers before the caller finishes configuring binding.
    private const string Path = "LDAP://unused.example.test/DC=example,DC=test";

    [Theory]
    [InlineData("collection")]
    [InlineData("names")]
    [InlineData("values")]
    [InlineData("read-only")]
    [InlineData("null-key")]
    public void Collection_access_defers_binding_like_microsoft(string operation)
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();
        object? expectedValue = null;
        object? actualValue = null;
        var expectedError = Record.Exception(() => expectedValue = Observe(microsoft.Properties, operation));
        var actualError = Record.Exception(() => actualValue = Observe(ours.Properties, operation));

        if (operation == "null-key")
            Assert.IsType<ArgumentNullException>(expectedError);
        else
            Assert.Null(expectedError);

        new Comparison($"unbound Properties: {operation}")
            .Check("exception type", expectedError?.GetType().FullName, actualError?.GetType().FullName)
            .Check("parameter", (expectedError as ArgumentException)?.ParamName,
                (actualError as ArgumentException)?.ParamName)
            .Check("result", expectedValue, actualValue)
            .Check("Path", microsoft.Path, ours.Path)
            .Assert();
    }

    [Fact]
    public void Construction_and_configuration_are_an_offline_control()
    {
        using var microsoft = MicrosoftEntry();
        using var ours = OurEntry();
        Assert.Equal(microsoft.Path, ours.Path);
        Assert.Equal(microsoft.UsePropertyCache, ours.UsePropertyCache);
        Assert.Equal((int)microsoft.AuthenticationType, (int)ours.AuthenticationType);
    }

    private static object? Observe(Ms.PropertyCollection properties, string operation) => operation switch
    {
        "collection" => properties is not null,
        "names" => properties.PropertyNames is not null,
        "values" => properties.Values is not null,
        "read-only" => ((IDictionary)properties).IsReadOnly,
        "null-key" => properties[null!],
        _ => throw new ArgumentOutOfRangeException(nameof(operation)),
    };

    private static object? Observe(Ours.PropertyCollection properties, string operation) => operation switch
    {
        "collection" => properties is not null,
        "names" => properties.PropertyNames is not null,
        "values" => properties.Values is not null,
        "read-only" => ((IDictionary)properties).IsReadOnly,
        "null-key" => properties[null!],
        _ => throw new ArgumentOutOfRangeException(nameof(operation)),
    };

    private static Ms.DirectoryEntry MicrosoftEntry() => new(Path, null, null, Ms.AuthenticationTypes.Signing);

    private static Ours.DirectoryEntry OurEntry() => new(Path, null, null, Ours.AuthenticationTypes.Signing);
}
