using System.Collections;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;
#if !RECORDED_MICROSOFT_ORACLE
using Ms = System.DirectoryServices.AccountManagement;
#endif
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
        var caseId = $"{GetType().FullName}.{nameof(Copy_to_covariant_array_matches_failure_and_partial_writes)}(generic: {generic}, compatible: {compatible})";
#if !RECORDED_MICROSOFT_ORACLE
        var microsoft = CreateMicrosoft<object>();
#endif
        var ours = new Ours.PrincipalValueCollection<object>();
        object[] source = ["first", compatible ? "second" : 42, "third"];
        foreach (var value in source)
        {
#if !RECORDED_MICROSOFT_ORACLE
            microsoft.Add(value);
#endif
            ours.Add(value);
        }

        // Both CopyTo overloads accept string[] through array covariance.
#if RECORDED_MICROSOFT_ORACLE
        var expectedState = RecordedMicrosoftOracle.Read(caseId);
#else
        object[] expectedDestination = new string[] { "guard", "old-1", "old-2", "old-3", "tail" };
        var expectedError = Record.Exception(() => Copy(microsoft, expectedDestination, generic));
        var expectedState = State(expectedError, expectedDestination);
#endif
        object[] actualDestination = new string[] { "guard", "old-1", "old-2", "old-3", "tail" };
        var actualError = Record.Exception(() => Copy(ours, actualDestination, generic));
        Compare(caseId, expectedState, State(actualError, actualDestination));
#if !RECORDED_MICROSOFT_ORACLE
        Assert.Equal(source, microsoft.ToArray());
#endif
        Assert.Equal(source, ours.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Non_generic_copy_to_incompatible_element_type_matches_microsoft(bool empty)
    {
        var caseId = $"{GetType().FullName}.{nameof(Non_generic_copy_to_incompatible_element_type_matches_microsoft)}(empty: {empty})";
#if !RECORDED_MICROSOFT_ORACLE
        var microsoft = CreateMicrosoft<string>();
#endif
        var ours = new Ours.PrincipalValueCollection<string>();
        if (!empty)
        {
#if !RECORDED_MICROSOFT_ORACLE
            microsoft.Add("first");
#endif
            ours.Add("first");
        }

#if RECORDED_MICROSOFT_ORACLE
        var expectedState = RecordedMicrosoftOracle.Read(caseId);
#else
        var expectedDestination = new[] { 17, 23 };
        var expectedError = Record.Exception(() => ((ICollection)microsoft).CopyTo(expectedDestination, 0));
        var expectedState = State(expectedError, expectedDestination);
#endif
        var actualDestination = new[] { 17, 23 };
        var actualError = Record.Exception(() => ((ICollection)ours).CopyTo(actualDestination, 0));
        Compare(caseId, expectedState, State(actualError, actualDestination));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Non_generic_copy_to_multidimensional_array_matches_validation(int count)
    {
        var caseId = $"{GetType().FullName}.{nameof(Non_generic_copy_to_multidimensional_array_matches_validation)}(count: {count})";
#if !RECORDED_MICROSOFT_ORACLE
        var microsoft = CreateMicrosoft<string>();
#endif
        var ours = new Ours.PrincipalValueCollection<string>();
        for (var i = 0; i < count; i++)
        {
#if !RECORDED_MICROSOFT_ORACLE
            microsoft.Add("first");
#endif
            ours.Add("first");
        }

#if RECORDED_MICROSOFT_ORACLE
        var expectedState = RecordedMicrosoftOracle.Read(caseId);
#else
        var expectedDestination = new string[2, 2];
        var expectedError = Record.Exception(() => ((ICollection)microsoft).CopyTo(expectedDestination, 0));
        var expectedState = State(expectedError, expectedDestination);
#endif
        var actualDestination = new string[2, 2];
        var actualError = Record.Exception(() => ((ICollection)ours).CopyTo(actualDestination, 0));
        Compare(caseId, expectedState, State(actualError, actualDestination));
    }

    private static void Copy(ICollection<object> values, object[] destination, bool generic)
    {
        if (generic) values.CopyTo(destination, 1);
        else ((ICollection)values).CopyTo(destination, 1);
    }

    private static string State(Exception? error, Array destination) =>
        $"{Describe(error)}; destination=[{string.Join(",", destination.Cast<object?>())}]";

    private void Compare(string caseId, string expectedState, string actualState)
    {
        output.WriteLine($"Microsoft: {expectedState}");
        output.WriteLine($"AdForLinux: {actualState}");
#if !RECORDED_MICROSOFT_ORACLE
        DifferentialRecording.Write(output, caseId, expectedState, actualState);
#endif
        Assert.Equal(expectedState, actualState);
    }

    private static string Describe(Exception? error) => error is null
        ? "success"
        : $"{error.GetType().Name}; ParamName={(error as ArgumentException)?.ParamName ?? "<null>"}";

#if !RECORDED_MICROSOFT_ORACLE
    private static Ms.PrincipalValueCollection<T> CreateMicrosoft<T>()
    {
        // Normal internal constructor, as in the other offline collection tests.
        // No private fields are modified; all compared operations are public.
        var constructor = typeof(Ms.PrincipalValueCollection<T>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, Type.EmptyTypes, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.PrincipalValueCollection<T>>(constructor.Invoke(null));
    }
#endif
}
