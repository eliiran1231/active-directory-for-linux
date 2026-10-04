using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

// Read-only probe: no fixture objects, passwords or server policies are changed.
// Run this class alone in a fresh test process to exclude earlier ADSI activity.
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class DirectoryEntryOptionDefaultsComparisonTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("PageSize", 17, 31)]
    [InlineData("SecurityMasks", 3, 5)]
    public void Fresh_and_rebound_options_match_microsoft(string property, int first, int second)
    {
        using var microsoft = MicrosoftEntry();
        using var ours = new Ours.DirectoryEntry(DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn, DifferentialSettings.BindPassword, DifferentialSettings.OurAuthenticationTypes);
        var expected = Assert.IsType<Ms.DirectoryEntryConfiguration>(microsoft.Options);
        var actual = ours.Options;
        var initial = Read(expected, property);
        // README documents zero as the portable PageSize default. Preserve the
        // live Microsoft baseline and strict parity for every other option.
        var portableDefault = property == "PageSize" ? 0 : initial;
        var comparison = new Comparison($"Fresh/rebound options: {property}");
        output.WriteLine($"{property}: initial Microsoft={initial}, clone={Read(actual, property)}");
        comparison.Check("fresh value (documented default policy)", portableDefault, Read(actual, property));

        foreach (var value in new[] { first, second })
        {
            Set(expected, property, value);
            Set(actual, property, value);
            comparison.Check($"assigned {value}", Read(expected, property), Read(actual, property));
            using var independent = MicrosoftEntry();
            var independentValue = Read(independent.Options!, property);
            output.WriteLine($"{property}: independent Microsoft after assigning {value}={independentValue}");
            comparison.Check($"independent entry after {value}", initial, independentValue);

            microsoft.Close();
            ours.Close();
            var rebound = Read(expected, property);
            output.WriteLine($"{property}: rebound after {value}: Microsoft={rebound}, clone={Read(actual, property)}");
            comparison.Check($"Microsoft resets after {value}", initial, rebound)
                .Check($"Microsoft entry options after {value}", initial, Read(microsoft.Options!, property))
                .Check($"retained after {value}", portableDefault, Read(actual, property))
                .Check($"entry options after {value}", portableDefault, Read(ours.Options, property));
        }
        comparison.Assert();
    }

    private static Ms.DirectoryEntry MicrosoftEntry() => new(
        DifferentialSettings.PathFor(DifferentialSettings.BaseDn), DifferentialSettings.BindDn,
        DifferentialSettings.BindPassword, DifferentialSettings.MicrosoftAuthenticationTypes);

    private static int Read(object options, string property) =>
        Convert.ToInt32(options.GetType().GetProperty(property)!.GetValue(options));

    private static void Set(object options, string property, int value)
    {
        var member = options.GetType().GetProperty(property)!;
        member.SetValue(options, member.PropertyType.IsEnum ? Enum.ToObject(member.PropertyType, value) : value);
    }
}
