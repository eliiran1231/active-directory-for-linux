using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Context construction can bind. Unsaved cases never call Save; persisted cases
// reuse the owned-user fixture, whose cleanup uses fresh exact-DN lookups.
[Collection("differential")]
[Trait("Category", "CompatibilityNextBatchLive")]
public sealed class NextBatchPrincipalStateComparisonTests
{
    internal static Ms.PrincipalContext MicrosoftContext() => new(Ms.ContextType.Domain,
        DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
        DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    internal static Ours.PrincipalContext OurContext() => new(Ours.ContextType.Domain,
        DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
        DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

    internal static string Error(Exception? error) => error is null ? "success" :
        $"{error.GetType().Name}; parameter={(error as ArgumentException)?.ParamName ?? "<null>"}";

    [Theory]
    [InlineData("user", false)]
    [InlineData("user", true)]
    [InlineData("computer", false)]
    [InlineData("computer", true)]
    [InlineData("group", false)]
    [InlineData("group", true)]
    public void Principal_constructor_checks_disposed_context(string kind, bool disposed)
    {
        using var expectedContext = MicrosoftContext();
        using var actualContext = OurContext();
        if (disposed) { expectedContext.Dispose(); actualContext.Dispose(); }
        var expected = Record.Exception(() =>
        {
            using Ms.Principal principal = kind switch
            {
                "user" => new Ms.UserPrincipal(expectedContext),
                "computer" => new Ms.ComputerPrincipal(expectedContext),
                _ => new Ms.GroupPrincipal(expectedContext),
            };
        });
        var actual = Record.Exception(() =>
        {
            using Ours.Principal principal = kind switch
            {
                "user" => new Ours.UserPrincipal(actualContext),
                "computer" => new Ours.ComputerPrincipal(actualContext),
                _ => new Ours.GroupPrincipal(actualContext),
            };
        });
        if (!disposed) Assert.Null(expected);
        Assert.Equal(Error(expected), Error(actual));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("valid-name")]
    public void Named_group_constructor_validates_name_like_microsoft(string? name)
    {
        using var expectedContext = MicrosoftContext();
        using var actualContext = OurContext();
        var expected = Record.Exception(() => { using var group = new Ms.GroupPrincipal(expectedContext, name!); });
        var actual = Record.Exception(() => { using var group = new Ours.GroupPrincipal(actualContext, name!); });
        if (name == "valid-name") Assert.Null(expected);
        Assert.Equal(Error(expected), Error(actual));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(3)]
    [InlineData(int.MaxValue)]
    [InlineData(1)] // defined value control
    public void Group_scope_validation_timing_and_retained_value_match(int value)
    {
        using var expectedContext = MicrosoftContext();
        using var actualContext = OurContext();
        using var expected = new Ms.GroupPrincipal(expectedContext) { GroupScope = Ms.GroupScope.Global };
        using var actual = new Ours.GroupPrincipal(actualContext) { GroupScope = Ours.GroupScope.Global };
        var comparison = new Comparison($"GroupScope assignment {value}");
        comparison.Check("setter", Error(Record.Exception(() => expected.GroupScope = (Ms.GroupScope)value)),
            Error(Record.Exception(() => actual.GroupScope = (Ours.GroupScope)value)));
        comparison.Check("retained scope", (int?)expected.GroupScope, (int?)actual.GroupScope);
        // No invalid value reaches the directory. A subsequent valid assignment
        // also verifies recovery rather than leaving a failed operation unobserved.
        expected.GroupScope = Ms.GroupScope.Universal;
        actual.GroupScope = Ours.GroupScope.Universal;
        comparison.Check("recovery", (int?)expected.GroupScope, (int?)actual.GroupScope).Assert();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Unsaved_group_scope_and_security_have_independent_assignment_state(bool setScope, bool setSecurity)
    {
        using var expectedContext = MicrosoftContext();
        using var actualContext = OurContext();
        using var expected = new Ms.GroupPrincipal(expectedContext);
        using var actual = new Ours.GroupPrincipal(actualContext);
        Assert.Null(expected.GroupScope);
        Assert.Null(actual.GroupScope);
        Assert.Null(expected.IsSecurityGroup);
        Assert.Null(actual.IsSecurityGroup);
        if (setScope) { expected.GroupScope = Ms.GroupScope.Universal; actual.GroupScope = Ours.GroupScope.Universal; }
        if (setSecurity) { expected.IsSecurityGroup = false; actual.IsSecurityGroup = false; }
        new Comparison($"scope assigned={setScope}, security assigned={setSecurity}")
            .Check("GroupScope", (int?)expected.GroupScope, (int?)actual.GroupScope)
            .Check("IsSecurityGroup", expected.IsSecurityGroup, actual.IsSecurityGroup).Assert();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Staged_principal_scalar_is_independent_of_entry_cache_and_refresh(bool refresh)
    {
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expected, actual, expectedEntry, actualEntry) =>
        {
            Assert.True(expectedEntry.UsePropertyCache);
            Assert.True(actualEntry.UsePropertyCache);
            Assert.Null(expectedEntry.Properties["description"].Value);
            Assert.Null(actualEntry.Properties["description"].Value);
            expected.Description = actual.Description = "pending-principal-value";
            var comparison = new Comparison($"Principal setter / entry cache; refresh={refresh}")
                .Check("principal getter", expected.Description, actual.Description)
                .Check("raw entry before Save", expectedEntry.Properties["description"].Value, actualEntry.Properties["description"].Value);
            if (refresh) { expectedEntry.RefreshCache(); actualEntry.RefreshCache(); }
            comparison.Check("principal after optional refresh", expected.Description, actual.Description);
            expected.Save();
            actual.Save();
            using var expectedReloaded = Ms.UserPrincipal.FindByIdentity(expected.Context, Ms.IdentityType.DistinguishedName, expected.DistinguishedName!);
            using var actualReloaded = Ours.UserPrincipal.FindByIdentity(actual.Context, Ours.IdentityType.DistinguishedName, actual.DistinguishedName!);
            Assert.NotNull(expectedReloaded);
            Assert.NotNull(actualReloaded);
            Assert.Equal("pending-principal-value", expectedReloaded.Description);
            comparison.Check("persisted value from fresh lookup", expectedReloaded.Description, actualReloaded.Description).Assert();
        });
    }

    [Fact]
    public void Persisted_name_assignment_is_returned_before_save()
    {
        CompatibilityCachedLogonProjectionComparisonTests.WithSavedUsers((expected, actual, expectedEntry, actualEntry) =>
        {
            var expectedDn = expected.DistinguishedName;
            var actualDn = actual.DistinguishedName;
            const string pending = "pending-name-without-save";
            expected.Name = actual.Name = pending;
            // Keep this isolated from Rename/Save behavior. The fixture deletes
            // the original DNs through fresh bindings; these edits never commit.
            Assert.Equal(expectedDn, expected.DistinguishedName);
            Assert.Equal(actualDn, actual.DistinguishedName);
            Assert.Equal(pending, expected.Name);
            new Comparison("Persisted Name setter/getter")
                .Check("Name", expected.Name, actual.Name)
                .Check("ToString", expected.ToString(), actual.ToString()).Assert();
        });
    }
}
