using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public sealed class PrincipalEqualityDisposalComparisonTests
{
    private sealed class MicrosoftPrincipal : Ms.Principal { }
    private sealed class OurPrincipal : Ours.Principal { }

    [Theory]
    [InlineData(false, false)] // Live unsaved principals are the control.
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Equality_of_distinct_unsaved_principals_matches_after_disposal(
        bool disposeLeft, bool disposeRight)
    {
        using var microsoftLeft = new MicrosoftPrincipal();
        using var microsoftRight = new MicrosoftPrincipal();
        using var ourLeft = new OurPrincipal();
        using var ourRight = new OurPrincipal();
        if (disposeLeft)
        {
            microsoftLeft.Dispose();
            ourLeft.Dispose();
        }
        if (disposeRight)
        {
            microsoftRight.Dispose();
            ourRight.Dispose();
        }

        // Identity and null comparisons are useful controls even when disposed.
        Assert.Equal(SuiteCapture.Expected(microsoftLeft.Equals(microsoftLeft), "assert-equal-expected", 36), SuiteCapture.Expected(ourLeft.Equals(ourLeft), "assert-equal-actual", 36));
        bool? expectedValue = null;
        bool? actualValue = null;
        var expected = Record.Exception(() => { expectedValue = microsoftLeft.Equals(microsoftRight); });
        var actual = Record.Exception(() => { actualValue = ourLeft.Equals(ourRight); });

        Assert.Equal(SuiteCapture.Expected(expected?.GetType(), "assert-equal-expected", 42), SuiteCapture.Expected(actual?.GetType(), "assert-equal-actual", 42));
        Assert.Equal(SuiteCapture.Expected(expectedValue, "assert-equal-expected", 43), SuiteCapture.Expected(actualValue, "assert-equal-actual", 43));
        Assert.Equal(SuiteCapture.Expected(microsoftLeft.Equals(null), "assert-equal-expected", 44), SuiteCapture.Expected(ourLeft.Equals(null), "assert-equal-actual", 44));
    }
}
