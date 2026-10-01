using System.Collections;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public sealed class PrincipalValueCollectionCopyFailureComparisonTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)] // Controls: every element fits the covariant array.
    [InlineData(true, true)]
    public void Copy_to_covariant_array_matches_failure_and_partial_writes(bool generic, bool compatible)
    {
        var microsoft = CreateMicrosoft<object>();
        var ours = new Ours.PrincipalValueCollection<object>();
        object[] source = ["first", compatible ? "second" : 42, "third"];
        foreach (var value in source)
        {
            microsoft.Add(value);
            ours.Add(value);
        }

        // Both CopyTo overloads accept string[] through array covariance.
        object[] expectedDestination = new string[] { "guard", "old-1", "old-2", "old-3", "tail" };
        object[] actualDestination = new string[] { "guard", "old-1", "old-2", "old-3", "tail" };
        var expectedError = Record.Exception(() => Copy(microsoft, expectedDestination, generic));
        var actualError = Record.Exception(() => Copy(ours, actualDestination, generic));

        Compare(expectedError, actualError, expectedDestination, actualDestination);
        Assert.Equal(source, microsoft.ToArray());
        Assert.Equal(source, ours.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Non_generic_copy_to_incompatible_element_type_matches_microsoft(bool empty)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        if (!empty)
        {
            microsoft.Add("first");
            ours.Add("first");
        }

        var expectedDestination = new[] { 17, 23 };
        var actualDestination = new[] { 17, 23 };
        var expectedError = Record.Exception(() => ((ICollection)microsoft).CopyTo(expectedDestination, 0));
        var actualError = Record.Exception(() => ((ICollection)ours).CopyTo(actualDestination, 0));
        Compare(expectedError, actualError, expectedDestination, actualDestination);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Non_generic_copy_to_multidimensional_array_matches_validation(int count)
    {
        var microsoft = CreateMicrosoft<string>();
        var ours = new Ours.PrincipalValueCollection<string>();
        for (var i = 0; i < count; i++)
        {
            microsoft.Add("first");
            ours.Add("first");
        }

        var expectedDestination = new string[2, 2];
        var actualDestination = new string[2, 2];
        var expectedError = Record.Exception(() => ((ICollection)microsoft).CopyTo(expectedDestination, 0));
        var actualError = Record.Exception(() => ((ICollection)ours).CopyTo(actualDestination, 0));
        Compare(expectedError, actualError, expectedDestination, actualDestination);
    }

    private static void Copy(ICollection<object> values, object[] destination, bool generic)
    {
        if (generic) values.CopyTo(destination, 1);
        else ((ICollection)values).CopyTo(destination, 1);
    }

    private void Compare(Exception? expectedError, Exception? actualError, Array expected, Array actual)
    {
        var expectedState = $"{Describe(expectedError)}; destination=[{string.Join(",", expected.Cast<object?>())}]";
        var actualState = $"{Describe(actualError)}; destination=[{string.Join(",", actual.Cast<object?>())}]";
        output.WriteLine($"Microsoft: {expectedState}");
        output.WriteLine($"AdForLinux: {actualState}");
        Assert.Equal(expectedState, actualState);
    }

    private static string Describe(Exception? error) => error is null
        ? "success"
        : $"{error.GetType().Name}; ParamName={(error as ArgumentException)?.ParamName ?? "<null>"}";

    private static Ms.PrincipalValueCollection<T> CreateMicrosoft<T>()
    {
        // Normal internal constructor, as in the other offline collection tests.
        // No private fields are modified; all compared operations are public.
        var constructor = typeof(Ms.PrincipalValueCollection<T>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.PrincipalValueCollection<T>>(constructor.Invoke(null));
    }
}
