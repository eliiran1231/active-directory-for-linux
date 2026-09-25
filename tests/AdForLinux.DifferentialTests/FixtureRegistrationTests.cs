using Xunit;

namespace AdForLinux.DifferentialTests;

public class FixtureRegistrationTests
{
    public static IEnumerable<object[]> TestDataFixtureConsumers =>
        typeof(TestDataFixture).Assembly.GetTypes()
            .Where(type => !type.IsAbstract && type.GetConstructors().Any(constructor =>
                constructor.GetParameters().Any(parameter =>
                    parameter.ParameterType == typeof(TestDataFixture))))
            .OrderBy(type => type.FullName)
            .Select(type => new object[] { type });

    // Check registration without constructing fixtures or connecting to AD.
    // Missing registration otherwise fails only after deploying to the lab.
    [Theory]
    [MemberData(nameof(TestDataFixtureConsumers))]
    public void Test_data_consumers_register_their_class_fixture(Type testClass)
    {
        Assert.True(typeof(IClassFixture<TestDataFixture>).IsAssignableFrom(testClass),
            $"{testClass.FullName} must implement IClassFixture<TestDataFixture>.");
    }
}
