using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Existing fixture setup/cleanup writes to AD; this method only queries.
// Execute only in a separately authorized disposable lab.
// Microsoft v9 FindResultEnumerator.MoveNext advances before the generic
// Current cast; ADEntriesSet projects a built-in principal on later Current.
// https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/FindResultEnumerator.cs
[Collection("differential")]
[Trait("Category", "CompatibilityCoverageLive")]
public sealed class CompatibilityCustomDateFinderComparisonTests(TestDataFixture data) : IClassFixture<TestDataFixture>
{
    [Theory]
    [InlineData(false)] // Protected generic finder with the built-in user type.
    [InlineData(true)]
    public void Expiration_finder_first_advance_matches_for_custom_user_type(bool customType)
    {
        using var expectedContext = new Ms.PrincipalContext(Ms.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.MicrosoftContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);
        using var actualContext = new Ours.PrincipalContext(Ours.ContextType.Domain,
            DifferentialSettings.ServerName, DifferentialSettings.UsersContainer,
            DifferentialSettings.OurContextOptions, DifferentialSettings.BindDn, DifferentialSettings.BindPassword);

        // Establish that the same public date finder really returns the known
        // seeded user. Extra matching users do not affect first-advance semantics.
        using (var expectedBaseline = Ms.UserPrincipal.FindByExpirationTime(expectedContext,
            data.UserExpirationTime, Ms.MatchType.Equals))
        {
            var found = false;
            foreach (var principal in expectedBaseline)
            {
                using (principal)
                    found |= string.Equals(data.UserDn, principal.DistinguishedName, StringComparison.OrdinalIgnoreCase);
            }
            Assert.True(found, "Microsoft public date finder must return the fixture user.");
        }
        using (var actualBaseline = Ours.UserPrincipal.FindByExpirationTime(actualContext,
            data.UserExpirationTime, Ours.MatchType.Equals))
        {
            var found = false;
            foreach (var principal in actualBaseline)
            {
                using (principal)
                    found |= string.Equals(data.UserDn, principal.DistinguishedName, StringComparison.OrdinalIgnoreCase);
            }
            Assert.True(found, "Clone public date finder must return the fixture user.");
        }

        var expected = Observe(() => MicrosoftUser.FirstAdvance(expectedContext, data.UserExpirationTime, customType));
        var actual = Observe(() => OurUser.FirstAdvance(actualContext, data.UserExpirationTime, customType));
        Assert.Equal("returned True", expected);
        Assert.Equal(expected, actual);
    }

    // No custom Current access: Microsoft can advance to a native row even
    // when its later generic Current cast would reject the built-in wrapper.
    [Ms.DirectoryObjectClass("user")]
    public sealed class MicrosoftUser(Ms.PrincipalContext context) : Ms.UserPrincipal(context)
    {
        internal static bool FirstAdvance(Ms.PrincipalContext context, DateTime time, bool custom) =>
            custom ? Advance<MicrosoftUser>(context, time) : Advance<Ms.UserPrincipal>(context, time);

        private static bool Advance<T>(Ms.PrincipalContext context, DateTime time)
        {
            using var results = FindByExpirationTime<T>(context, time, Ms.MatchType.Equals);
            using var cursor = results.GetEnumerator();
            return cursor.MoveNext();
        }
    }

    [Ours.DirectoryObjectClass("user")]
    public sealed class OurUser(Ours.PrincipalContext context) : Ours.UserPrincipal(context)
    {
        internal static bool FirstAdvance(Ours.PrincipalContext context, DateTime time, bool custom) =>
            custom ? Advance<OurUser>(context, time) : Advance<Ours.UserPrincipal>(context, time);

        private static bool Advance<T>(Ours.PrincipalContext context, DateTime time)
        {
            using var results = FindByExpirationTime<T>(context, time, Ours.MatchType.Equals);
            using var cursor = results.GetEnumerator();
            return cursor.MoveNext();
        }
    }

    private static string Observe(Func<bool> action)
    {
        try { return $"returned {action()}"; }
        catch (Exception error) { return $"threw {error.GetType().Name}"; }
    }
}
