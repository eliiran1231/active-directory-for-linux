using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;
using Ms = System.DirectoryServices;
using Ours = AdForLinux.DirectoryServices;

namespace AdForLinux.DifferentialTests;

public sealed class ResultPropertyDeferredErrorComparisonTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Indexer_rethrows_deferred_value_error_like_microsoft(bool useComException)
    {
        Exception deferredError = useComException
            ? new COMException("Attribute conversion failed", unchecked((int)0x8000500c))
            : new NotSupportedException("Unsupported ADSI value type");
        object[] values = { "readable-before", deferredError, "readable-after" };
        var microsoft = CreateMicrosoft(values);
        var ours = new Ours.ResultPropertyValueCollection(values);

        // Reflection only supplies the payload normally built by the search
        // result decoder. Reading/copying/searching values uses public APIs.
        Assert.Equal(SuiteCapture.Expected(microsoft[0], "assert-equal-expected", 25), SuiteCapture.Expected(ours[0], "assert-equal-actual", 25));
        Assert.Equal(SuiteCapture.Expected(microsoft[2], "assert-equal-expected", 26), SuiteCapture.Expected(ours[2], "assert-equal-actual", 26));
        Assert.Equal(SuiteCapture.Expected(microsoft.Contains(deferredError), "assert-equal-expected", 27), SuiteCapture.Expected(ours.Contains(deferredError), "assert-equal-actual", 27));
        Assert.Equal(SuiteCapture.Expected(microsoft.IndexOf(deferredError), "assert-equal-expected", 28), SuiteCapture.Expected(ours.IndexOf(deferredError), "assert-equal-actual", 28));
        var expectedCopy = new object[3];
        var actualCopy = new object[3];
        microsoft.CopyTo(expectedCopy, 0);
        ours.CopyTo(actualCopy, 0);
        Assert.Equal(SuiteCapture.Expected(expectedCopy, "assert-equal-expected", 33), SuiteCapture.Expected(actualCopy, "assert-equal-actual", 33));

        var expectedError = Record.Exception(() => { _ = microsoft[1]; });
        var actualError = Record.Exception(() => { _ = ours[1]; });

        Assert.Same(deferredError, expectedError);
        Assert.Equal(SuiteCapture.Expected(expectedError?.GetType(), "assert-equal-expected", 39), SuiteCapture.Expected(actualError?.GetType(), "assert-equal-actual", 39));
        Assert.Same(deferredError, actualError);
    }

    private static Ms.ResultPropertyValueCollection CreateMicrosoft(object[] values)
    {
        var constructor = typeof(Ms.ResultPropertyValueCollection).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(object[]) }, null);
        Assert.NotNull(constructor);
        return Assert.IsType<Ms.ResultPropertyValueCollection>(constructor.Invoke(new object[] { values }));
    }
}
