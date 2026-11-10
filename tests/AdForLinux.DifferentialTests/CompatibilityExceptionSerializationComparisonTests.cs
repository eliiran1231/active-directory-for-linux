using System.Runtime.Serialization;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Exercise only the existing protected/public serialization contracts. No
// BinaryFormatter, serialized bytes, reflection or directory connection is used.
// The pinned Microsoft 9.0.0 implementation deliberately rejects the
// NoMatchingPrincipalException serialization constructor, unlike its siblings:
// https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/exceptions.cs
#pragma warning disable SYSLIB0050, SYSLIB0051
[Trait("Category", "CompatibilityCoverageOffline")]
public sealed class CompatibilityExceptionSerializationComparisonTests
{
    [Theory]
    [InlineData("populated")]
    [InlineData("empty")]
    [InlineData("null")]
    public void No_matching_principal_serialization_constructor_matches_microsoft(string payload)
    {
        // Populated data is emitted by the public exception API, not guessed
        // framework field names. Null/empty distinguish rejection precedence
        // from successful base Exception deserialization.
        var expectedInfo = payload switch
        {
            "populated" => Serialize(new Ms.NoMatchingPrincipalException("missing principal", new InvalidOperationException("inner"))),
            "empty" => NewInfo(typeof(Ms.NoMatchingPrincipalException)),
            _ => null,
        };
        var actualInfo = payload switch
        {
            "populated" => Serialize(new Ours.NoMatchingPrincipalException("missing principal", new InvalidOperationException("inner"))),
            "empty" => NewInfo(typeof(Ours.NoMatchingPrincipalException)),
            _ => null,
        };
        var expectedError = Record.Exception(() => new MicrosoftNoMatch(expectedInfo!));
        var actualError = Record.Exception(() => new OurNoMatch(actualInfo!));
        Assert.Equal(SuiteCapture.Expected(Error(expectedError), "assert-equal-expected", 40), SuiteCapture.Expected(Error(actualError), "assert-equal-actual", 40));
    }

    [Theory]
    [InlineData(false, 1722, null)]
    [InlineData(false, -2147024891, null)]
    [InlineData(true, 1722, null)]
    [InlineData(true, -2147024891, "dc-東京.example.test")]
    public void Exception_metadata_survives_protected_constructor_like_microsoft(bool serverDown, int errorCode, string? serverName)
    {
        var inner = new InvalidOperationException("original failure");
        Exception expectedSource = serverDown
            ? new Ms.PrincipalServerDownException("operation failed", inner, errorCode, serverName!)
            : new Ms.PrincipalOperationException("operation failed", inner, errorCode);
        Exception actualSource = serverDown
            ? new Ours.PrincipalServerDownException("operation failed", inner, errorCode, serverName!)
            : new Ours.PrincipalOperationException("operation failed", inner, errorCode);
        var expectedInfo = Serialize(expectedSource);
        var actualInfo = Serialize(actualSource);
        AssertMetadata(expectedInfo, actualInfo, serverDown);

        Exception expected = serverDown
            ? new MicrosoftServerDown(expectedInfo)
            : new MicrosoftOperation(expectedInfo);
        Exception actual = serverDown
            ? new OurServerDown(actualInfo)
            : new OurOperation(actualInfo);
        Assert.Equal(SuiteCapture.Expected(expected.Message, "assert-equal-expected", 67), SuiteCapture.Expected(actual.Message, "assert-equal-actual", 67));
        Assert.Equal(SuiteCapture.Expected(expected.HResult, "assert-equal-expected", 68), SuiteCapture.Expected(actual.HResult, "assert-equal-actual", 68));
        Assert.Same(inner, expected.InnerException);
        Assert.Same(inner, actual.InnerException);
        if (!serverDown)
            Assert.Equal(SuiteCapture.Expected(((Ms.PrincipalOperationException)expected).ErrorCode, "assert-equal-expected", 72),
                SuiteCapture.Expected(((Ours.PrincipalOperationException)actual).ErrorCode, "assert-equal-actual", 72));

        // ServerDown has no public ErrorCode/ServerName getters. Re-emit its
        // documented serialization fields to observe preserved metadata.
        var expectedRoundTrip = Serialize(expected);
        var actualRoundTrip = Serialize(actual);
        AssertMetadata(expectedRoundTrip, actualRoundTrip, serverDown);
        AssertMetadata(expectedInfo, expectedRoundTrip, serverDown);
        AssertMetadata(actualInfo, actualRoundTrip, serverDown);
    }

    private static void AssertMetadata(SerializationInfo expected, SerializationInfo actual, bool serverDown)
    {
        Assert.Equal(SuiteCapture.Expected(expected.GetInt32("errorCode"), "assert-equal-expected", 86), SuiteCapture.Expected(actual.GetInt32("errorCode"), "assert-equal-actual", 86));
        if (serverDown) Assert.Equal(SuiteCapture.Expected(expected.GetString("serverName"), "assert-equal-expected", 87), SuiteCapture.Expected(actual.GetString("serverName"), "assert-equal-actual", 87));
    }

    private static SerializationInfo NewInfo(Type type) => new(type, new FormatterConverter());

    private static SerializationInfo Serialize(Exception exception)
    {
        var info = NewInfo(exception.GetType());
        exception.GetObjectData(info, default);
        return info;
    }

    private static (Type? Type, string? Parameter) Error(Exception? error) =>
        (error?.GetType(), (error as ArgumentException)?.ParamName);

    private sealed class MicrosoftNoMatch(SerializationInfo info) : Ms.NoMatchingPrincipalException(info, default);
    private sealed class OurNoMatch(SerializationInfo info) : Ours.NoMatchingPrincipalException(info, default);
    private sealed class MicrosoftOperation(SerializationInfo info) : Ms.PrincipalOperationException(info, default);
    private sealed class OurOperation(SerializationInfo info) : Ours.PrincipalOperationException(info, default);
    private sealed class MicrosoftServerDown(SerializationInfo info) : Ms.PrincipalServerDownException(info, default);
    private sealed class OurServerDown(SerializationInfo info) : Ours.PrincipalServerDownException(info, default);
}
#pragma warning restore SYSLIB0050, SYSLIB0051
