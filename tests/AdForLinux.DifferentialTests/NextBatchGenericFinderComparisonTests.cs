using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

[Trait("Category", "CompatibilityNextBatchOffline")]
public sealed class NextBatchGenericFinderComparisonTests
{
    public static IEnumerable<object[]> Cases =>
        from method in new[] { "Lockout", "Logon", "Expiration", "BadPassword", "PasswordSet" }
        from subtype in new[] { "object", "principal", "group", "user" }
        select new object[] { method, subtype };

    // A normal subclass exposes the protected generic API. No instance, context,
    // reflection, or directory is needed: both checks precede any store access.
    [Theory]
    [MemberData(nameof(Cases))]
    public void Generic_finder_validates_subtype_before_null_context(string method, string subtype)
    {
        var expected = Record.Exception(() => MicrosoftFinder.Invoke(method, subtype));
        var actual = Record.Exception(() => OurFinder.Invoke(method, subtype));
        Assert.NotNull(expected);
        if (subtype == "user") Assert.IsType<ArgumentNullException>(expected); // valid subtype control
        else Assert.IsType<ArgumentException>(expected);
        Assert.Equal((expected.GetType().Name, (expected as ArgumentException)?.ParamName),
            (actual?.GetType().Name, (actual as ArgumentException)?.ParamName));
    }

    private sealed class MicrosoftFinder : Ms.AuthenticablePrincipal
    {
        private MicrosoftFinder() : base(null!) { }
        internal static void Invoke(string method, string subtype)
        {
            switch (subtype)
            {
                case "object": Run<object>(method); break;
                case "principal": Run<Ms.Principal>(method); break;
                case "group": Run<Ms.GroupPrincipal>(method); break;
                case "user": Run<Ms.UserPrincipal>(method); break;
                default: throw new ArgumentOutOfRangeException(nameof(subtype));
            }
        }
        private static void Run<T>(string method)
        {
            var date = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            using var result = method switch
            {
                "Lockout" => FindByLockoutTime<T>(null!, date, Ms.MatchType.Equals),
                "Logon" => FindByLogonTime<T>(null!, date, Ms.MatchType.Equals),
                "Expiration" => FindByExpirationTime<T>(null!, date, Ms.MatchType.Equals),
                "BadPassword" => FindByBadPasswordAttempt<T>(null!, date, Ms.MatchType.Equals),
                "PasswordSet" => FindByPasswordSetTime<T>(null!, date, Ms.MatchType.Equals),
                _ => throw new ArgumentOutOfRangeException(nameof(method)),
            };
        }
    }

    private sealed class OurFinder : Ours.AuthenticablePrincipal
    {
        private OurFinder() : base(null!) { }
        internal static void Invoke(string method, string subtype)
        {
            switch (subtype)
            {
                case "object": Run<object>(method); break;
                case "principal": Run<Ours.Principal>(method); break;
                case "group": Run<Ours.GroupPrincipal>(method); break;
                case "user": Run<Ours.UserPrincipal>(method); break;
                default: throw new ArgumentOutOfRangeException(nameof(subtype));
            }
        }
        private static void Run<T>(string method)
        {
            var date = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            using var result = method switch
            {
                "Lockout" => FindByLockoutTime<T>(null!, date, Ours.MatchType.Equals),
                "Logon" => FindByLogonTime<T>(null!, date, Ours.MatchType.Equals),
                "Expiration" => FindByExpirationTime<T>(null!, date, Ours.MatchType.Equals),
                "BadPassword" => FindByBadPasswordAttempt<T>(null!, date, Ours.MatchType.Equals),
                "PasswordSet" => FindByPasswordSetTime<T>(null!, date, Ours.MatchType.Equals),
                _ => throw new ArgumentOutOfRangeException(nameof(method)),
            };
        }
    }
}
