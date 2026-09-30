using System.Collections;
using Xunit;
using Ms = System.DirectoryServices.AccountManagement;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

// Exercise the supported subclass API through normal protected constructors.
// No reflection, PrincipalContext, directory connection, or private state edits.
public sealed class AdvancedFilterExtensionComparisonTests
{
    private sealed class MicrosoftPrincipal : Ms.Principal
    {
        public object[] Read(string name) => ExtensionGet(name);
        public void Write(string name, object value) => ExtensionSet(name, value);
    }

    private sealed class OurPrincipal : Ours.Principal
    {
        public object?[] Read(string name) => ExtensionGet(name);
        public void Write(string name, object value) => ExtensionSet(name, value);
    }

    private sealed class MicrosoftFilters(Ms.Principal principal) : Ms.AdvancedFilters(principal)
    {
        public void Set(string? name, object? value, Type? type) =>
            AdvancedFilterSet(name!, value!, type!, Ms.MatchType.Equals);
    }

    private sealed class OurFilters(Ours.Principal principal) : Ours.AdvancedFilters(principal)
    {
        public void Set(string? name, object? value, Type? type) =>
            AdvancedFilterSet(name!, value!, type!, Ours.MatchType.Equals);
    }

    [Theory]
    [InlineData("null-name")]
    [InlineData("empty-name")]
    [InlineData("null-value")]
    [InlineData("null-type")]
    [InlineData("empty-array")]
    [InlineData("empty-bytes")]
    [InlineData("empty-list")]
    [InlineData("nested-array")]
    [InlineData("scalar")]
    [InlineData("array")]
    [InlineData("bytes")]
    public void Custom_filter_argument_acceptance_matches_microsoft(string kind)
    {
        using var microsoftPrincipal = new MicrosoftPrincipal();
        using var ourPrincipal = new OurPrincipal();
        var microsoft = new MicrosoftFilters(microsoftPrincipal);
        var ours = new OurFilters(ourPrincipal);
        var name = kind == "null-name" ? null : kind == "empty-name" ? "" : "description";
        var type = kind == "null-type" ? null : typeof(string);

        var expected = Record.Exception(() => microsoft.Set(name, Value(kind), type));
        var actual = Record.Exception(() => ours.Set(name, Value(kind), type));
        // A subsequent valid assignment must still work after rejection.
        var expectedRecovery = Record.Exception(() => microsoft.Set("description", "valid", typeof(string)));
        var actualRecovery = Record.Exception(() => ours.Set("description", "valid", typeof(string)));

        Assert.Equal(new[] { Describe(expected), Describe(expectedRecovery) },
            new[] { Describe(actual), Describe(actualRecovery) });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Custom_filter_replaces_extension_cache_state_like_microsoft(bool existingValue)
    {
        using var microsoft = new MicrosoftPrincipal();
        using var ours = new OurPrincipal();
        if (existingValue)
        {
            microsoft.Write("description", "original");
            ours.Write("description", "original");
        }

        new MicrosoftFilters(microsoft).Set("description", "criterion", typeof(string));
        new OurFilters(ours).Set("description", "criterion", typeof(string));

        // Microsoft marks this cache entry as a filter, so ExtensionGet returns
        // null even when an ordinary extension value previously occupied it.
        Assert.Equal(microsoft.Read("description"), ours.Read("description"));
    }

    [Theory]
    [InlineData("LastBadPasswordAttempt")]
    [InlineData("AccountExpirationDate")]
    [InlineData("AccountLockoutTime")]
    [InlineData("BadLogonCount")]
    [InlineData("LastLogonTime")]
    [InlineData("LastPasswordSetTime")]
    [InlineData("Custom")]
    public void Retained_filters_can_be_configured_after_principal_disposal_like_microsoft(string method)
    {
        using var microsoftPrincipal = new MicrosoftPrincipal();
        using var ourPrincipal = new OurPrincipal();
        var microsoft = new MicrosoftFilters(microsoftPrincipal);
        var ours = new OurFilters(ourPrincipal);
        var date = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Action expectedAction = method switch
        {
            "LastBadPasswordAttempt" => () => microsoft.LastBadPasswordAttempt(date, Ms.MatchType.Equals),
            "AccountExpirationDate" => () => microsoft.AccountExpirationDate(date, Ms.MatchType.Equals),
            "AccountLockoutTime" => () => microsoft.AccountLockoutTime(date, Ms.MatchType.Equals),
            "BadLogonCount" => () => microsoft.BadLogonCount(3, Ms.MatchType.Equals),
            "LastLogonTime" => () => microsoft.LastLogonTime(date, Ms.MatchType.Equals),
            "LastPasswordSetTime" => () => microsoft.LastPasswordSetTime(date, Ms.MatchType.Equals),
            "Custom" => () => microsoft.Set("description", "criterion", typeof(string)),
            _ => throw new ArgumentOutOfRangeException(nameof(method)),
        };
        Action actualAction = method switch
        {
            "LastBadPasswordAttempt" => () => ours.LastBadPasswordAttempt(date, Ours.MatchType.Equals),
            "AccountExpirationDate" => () => ours.AccountExpirationDate(date, Ours.MatchType.Equals),
            "AccountLockoutTime" => () => ours.AccountLockoutTime(date, Ours.MatchType.Equals),
            "BadLogonCount" => () => ours.BadLogonCount(3, Ours.MatchType.Equals),
            "LastLogonTime" => () => ours.LastLogonTime(date, Ours.MatchType.Equals),
            "LastPasswordSetTime" => () => ours.LastPasswordSetTime(date, Ours.MatchType.Equals),
            "Custom" => () => ours.Set("description", "criterion", typeof(string)),
            _ => throw new ArgumentOutOfRangeException(nameof(method)),
        };

        // Establish that both operations work on the same instances before disposal.
        Assert.Null(Record.Exception(expectedAction));
        Assert.Null(Record.Exception(actualAction));
        microsoftPrincipal.Dispose();
        ourPrincipal.Dispose();

        Assert.Equal(Describe(Record.Exception(expectedAction)), Describe(Record.Exception(actualAction)));
    }

    private static object? Value(string kind) => kind switch
    {
        "null-value" => null,
        "empty-array" => Array.Empty<object>(),
        "empty-bytes" => Array.Empty<byte>(),
        "empty-list" => new ArrayList(),
        "nested-array" => new object[] { new object[] { "nested" } },
        "array" => new object[] { "one", "two" },
        "bytes" => new byte[] { 1, 2 },
        _ => "criterion",
    };

    private static string Describe(Exception? error) => error is null
        ? "accepted"
        : $"{error.GetType().FullName}; ParamName={(error as ArgumentException)?.ParamName ?? "<null>"}";
}
