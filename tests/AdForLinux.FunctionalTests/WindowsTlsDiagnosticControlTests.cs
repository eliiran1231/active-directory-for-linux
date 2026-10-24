using System.Security.Cryptography;
using Xunit;

namespace AdForLinux.FunctionalTests;

// Pure delegates: no Windows APIs, certificates, LDAP or trust-store access.
public sealed class WindowsTlsDiagnosticControlTests
{
    private static bool Managed(int outcome) => outcome switch
    {
        0 => true,
        1 => false,
        _ => throw new CryptographicException("Sensitive diagnostic details must not be logged."),
    };

    [Theory]
    [InlineData(0, "valid")]
    [InlineData(1, "not valid")]
    [InlineData(2, "exception HResult=80131501")]
    public void Managed_outcome_does_not_skip_native_control(int outcome, string expected)
    {
        int nativeAttempts = 0;
        WindowsTlsDiagnosticControl.ObserveThenRun(() => Managed(outcome), () => nativeAttempts++, out var observed);
        Assert.Equal(1, nativeAttempts);
        Assert.Equal(expected, observed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Native_failure_propagates_and_stops_dependent_assertions(int outcome)
    {
        var nativeFailure = new InvalidOperationException("Native control failed.");
        int nativeAttempts = 0;
        bool dependentAssertionsReached = false;
        var actual = Record.Exception(() =>
        {
            WindowsTlsDiagnosticControl.ObserveThenRun(() => Managed(outcome), () =>
            {
                nativeAttempts++;
                throw nativeFailure;
            }, out _);
            dependentAssertionsReached = true;
        });
        Assert.Same(nativeFailure, actual);
        Assert.Equal(1, nativeAttempts);
        Assert.False(dependentAssertionsReached);
    }
}
