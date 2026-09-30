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
        Assert.Equal(microsoft[0], ours[0]);
        Assert.Equal(microsoft[2], ours[2]);
        Assert.Equal(microsoft.Contains(deferredError), ours.Contains(deferredError));
        Assert.Equal(microsoft.IndexOf(deferredError), ours.IndexOf(deferredError));
        var expectedCopy = new object[3];
        var actualCopy = new object[3];
        microsoft.CopyTo(expectedCopy, 0);
        ours.CopyTo(actualCopy, 0);
        Assert.Equal(expectedCopy, actualCopy);

        var expectedError = Record.Exception(() => { _ = microsoft[1]; });
        var actualError = Record.Exception(() => { _ = ours[1]; });

        Assert.Same(deferredError, expectedError);
        Assert.Equal(expectedError?.GetType(), actualError?.GetType());
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
