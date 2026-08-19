using System.Reflection;
using System.Runtime.CompilerServices;
using Xunit;
using MsDirectory = System.DirectoryServices;
using Ms = System.DirectoryServices.AccountManagement;
using OursDirectory = AdForLinux.DirectoryServices;
using Ours = AdForLinux.DirectoryServices.AccountManagement;

namespace AdForLinux.DifferentialTests;

public class LifecycleComparisonTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Disposed_directory_entry_bind_members_match(bool usePropertyCache)
    {
        var microsoft = new MsDirectory.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.MicrosoftAuthenticationTypes);
        var ours = new OursDirectory.DirectoryEntry(
            DifferentialSettings.PathFor(DifferentialSettings.BaseDn),
            DifferentialSettings.BindDn,
            DifferentialSettings.BindPassword,
            DifferentialSettings.OurAuthenticationTypes);

        microsoft.UsePropertyCache = usePropertyCache;
        ours.UsePropertyCache = usePropertyCache;
        _ = microsoft.Properties["distinguishedName"].Value;
        _ = ours.Properties["distinguishedName"].Value;

        microsoft.Dispose();
        ours.Dispose();

        (string Name, Action Microsoft, Action Ours)[] members =
        {
            (nameof(microsoft.RefreshCache), microsoft.RefreshCache, ours.RefreshCache),
            ("RefreshCache(string[])", () => microsoft.RefreshCache(Array.Empty<string>()),
             () => ours.RefreshCache(Array.Empty<string>())),
            (nameof(microsoft.Properties), () => _ = microsoft.Properties["distinguishedName"].Value,
             () => _ = ours.Properties["distinguishedName"].Value),
            (nameof(microsoft.Name), () => _ = microsoft.Name, () => _ = ours.Name),
            (nameof(microsoft.SchemaClassName), () => _ = microsoft.SchemaClassName, () => _ = ours.SchemaClassName),
            (nameof(microsoft.Guid), () => _ = microsoft.Guid, () => _ = ours.Guid),
            (nameof(microsoft.NativeGuid), () => _ = microsoft.NativeGuid, () => _ = ours.NativeGuid),
            (nameof(microsoft.NativeObject), () => _ = microsoft.NativeObject, () => _ = ours.NativeObject),
            (nameof(microsoft.Parent), () => _ = microsoft.Parent, () => _ = ours.Parent),
            (nameof(microsoft.SchemaEntry), () => _ = microsoft.SchemaEntry, () => _ = ours.SchemaEntry),
            (nameof(microsoft.Options), () => _ = microsoft.Options, () => _ = ours.Options),
            ("Children.Add", () => microsoft.Children.Add("CN=issue-74-child", "user"),
             () => ours.Children.Add("CN=issue-74-child", "user")),
            ("Children.GetEnumerator", () => microsoft.Children.GetEnumerator().MoveNext(),
             () => ours.Children.GetEnumerator().MoveNext()),
            (nameof(microsoft.DeleteTree), microsoft.DeleteTree, ours.DeleteTree),
            (nameof(microsoft.Rename), () => microsoft.Rename("CN=issue-74-renamed"),
             () => ours.Rename("CN=issue-74-renamed")),
        };

        AssertMatchingDisposedExceptions(members);
        Assert.Equal(microsoft.Path, ours.Path);
        Assert.Equal(microsoft.Username, ours.Username);
        Assert.Equal(microsoft.UsePropertyCache, ours.UsePropertyCache);

        microsoft.Dispose();
        ours.Dispose();
    }

    [Fact]
    public void Disposed_context_members_match_without_a_directory_connection()
    {
        var microsoft = UninitializedDisposed<Ms.PrincipalContext>("_disposed");
        var ours = new Ours.PrincipalContext(
            Ours.ContextType.Domain, "dc.example.test", "DC=example,DC=test");
        ours.Dispose();

        (Action Microsoft, Action Ours)[] members =
        {
            (() => _ = microsoft.ContextType, () => _ = ours.ContextType),
            (() => _ = microsoft.Name, () => _ = ours.Name),
            (() => _ = microsoft.Container, () => _ = ours.Container),
            (() => _ = microsoft.UserName, () => _ = ours.UserName),
            (() => _ = microsoft.Options, () => _ = ours.Options),
            (() => _ = microsoft.ConnectedServer, () => _ = ours.ConnectedServer),
            (() => microsoft.ValidateCredentials("user", "password"),
             () => ours.ValidateCredentials("user", "password")),
        };

        AssertMatchingDisposedExceptions(members);
    }

    [Fact]
    public void Disposed_principal_members_match_without_a_directory_connection()
    {
        var microsoft = UninitializedDisposed<Ms.UserPrincipal>("_disposed", typeof(Ms.Principal));
        using var context = new Ours.PrincipalContext(
            Ours.ContextType.Domain, "dc.example.test", "DC=example,DC=test");
        var ours = new Ours.UserPrincipal(context);
        ours.Dispose();

        (Action Microsoft, Action Ours)[] members =
        {
            (() => _ = microsoft.Context, () => _ = ours.Context),
            (() => _ = microsoft.ContextType, () => _ = ours.ContextType),
            (() => _ = microsoft.DistinguishedName, () => _ = ours.DistinguishedName),
            (() => _ = microsoft.Name, () => _ = ours.Name),
            (() => _ = microsoft.GivenName, () => _ = ours.GivenName),
            (() => microsoft.SetPassword(null!), () => ours.SetPassword(null!)),
        };

        AssertMatchingDisposedExceptions(members);
    }

    [Fact]
    public void Disposing_a_context_does_not_dispose_its_principal()
    {
        var microsoftContext = UninitializedDisposed<Ms.PrincipalContext>("_disposed");
        var microsoftUser = (Ms.UserPrincipal)RuntimeHelpers.GetUninitializedObject(typeof(Ms.UserPrincipal));
        typeof(Ms.Principal).GetField("_ctx", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(microsoftUser, microsoftContext);

        var ourContext = new Ours.PrincipalContext(
            Ours.ContextType.Domain, "dc.example.test", "DC=example,DC=test");
        using var ourUser = new Ours.UserPrincipal(ourContext);
        ourContext.Dispose();

        Assert.Same(microsoftContext, microsoftUser.Context);
        Assert.Same(ourContext, ourUser.Context);
        AssertMatchingDisposedException(
            () => _ = microsoftUser.Name,
            () => _ = ourUser.Name);
        AssertMatchingDisposedException(
            () => _ = microsoftUser.ContextType,
            () => _ = ourUser.ContextType);
    }

    [Fact]
    public void Search_result_and_enumerator_disposal_match_for_empty_results()
    {
        var microsoft = CreateMicrosoftEmptyResult();
        var ours = CreateOurEmptyResult();
        var microsoftEnumerator = microsoft.GetEnumerator();
        var ourEnumerator = ours.GetEnumerator();

        microsoft.Dispose();
        ours.Dispose();

        AssertMatchingDisposedException(
            () => microsoft.GetEnumerator(),
            () => ours.GetEnumerator());
        Assert.Equal(microsoftEnumerator.MoveNext(), ourEnumerator.MoveNext());

        microsoftEnumerator.Dispose();
        ourEnumerator.Dispose();
        AssertMatchingDisposedException(
            () => microsoftEnumerator.MoveNext(),
            () => ourEnumerator.MoveNext());
    }

    private static T UninitializedDisposed<T>(string fieldName, Type? declaringType = null)
        where T : class
    {
        var instance = (T)RuntimeHelpers.GetUninitializedObject(typeof(T));
        (declaringType ?? typeof(T)).GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(instance, true);
        return instance;
    }

    private static Ms.PrincipalSearchResult<Ms.Principal> CreateMicrosoftEmptyResult()
    {
        var assembly = typeof(Ms.Principal).Assembly;
        var resultSetType = assembly.GetType(
            "System.DirectoryServices.AccountManagement.ResultSet", throwOnError: true)!;
        var emptySetType = assembly.GetType(
            "System.DirectoryServices.AccountManagement.EmptySet", throwOnError: true)!;
        var emptySet = Activator.CreateInstance(emptySetType, nonPublic: true)!;
        var constructor = typeof(Ms.PrincipalSearchResult<Ms.Principal>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[] { resultSetType },
            modifiers: null)!;
        return (Ms.PrincipalSearchResult<Ms.Principal>)constructor.Invoke(new[] { emptySet });
    }

    private static Ours.PrincipalSearchResult<Ours.Principal> CreateOurEmptyResult()
    {
        var constructor = typeof(Ours.PrincipalSearchResult<Ours.Principal>).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            new[] { typeof(IReadOnlyList<Ours.Principal>) },
            modifiers: null)!;
        return (Ours.PrincipalSearchResult<Ours.Principal>)constructor.Invoke(
            new object[] { Array.Empty<Ours.Principal>() });
    }

    private static void AssertMatchingDisposedExceptions(
        IEnumerable<(Action Microsoft, Action Ours)> members)
    {
        foreach (var (microsoft, ours) in members)
        {
            AssertMatchingDisposedException(microsoft, ours);
        }
    }

    private static void AssertMatchingDisposedExceptions(
        IEnumerable<(string Name, Action Microsoft, Action Ours)> members)
    {
        var differences = new List<string>();
        foreach (var (name, microsoft, ours) in members)
        {
            var microsoftException = Record.Exception(microsoft);
            var ourException = Record.Exception(ours);
            if (microsoftException?.GetType() != typeof(ObjectDisposedException)
                || ourException?.GetType() != typeof(ObjectDisposedException))
            {
                differences.Add(
                    $"{name}: Microsoft={microsoftException?.GetType().Name ?? "no exception"}, " +
                    $"ours={ourException?.GetType().Name ?? "no exception"}");
                continue;
            }

            var typedMicrosoftException = (ObjectDisposedException)microsoftException!;
            var typedOurException = (ObjectDisposedException)ourException!;
            if (!string.Equals(
                    typedMicrosoftException.ObjectName,
                    typedOurException.ObjectName,
                    StringComparison.Ordinal))
            {
                differences.Add(
                    $"{name}: Microsoft object name='{typedMicrosoftException.ObjectName}', " +
                    $"ours='{typedOurException.ObjectName}'");
            }
        }

        Assert.True(differences.Count == 0, string.Join(Environment.NewLine, differences));
    }

    private static void AssertMatchingDisposedException(Action microsoft, Action ours)
    {
        var microsoftException = Assert.IsType<ObjectDisposedException>(Record.Exception(microsoft));
        var ourException = Assert.IsType<ObjectDisposedException>(Record.Exception(ours));
        Assert.Equal(
            microsoftException.ObjectName?.Replace(
                "System.DirectoryServices.AccountManagement",
                "AdForLinux.DirectoryServices.AccountManagement",
                StringComparison.Ordinal),
            ourException.ObjectName);
    }
}
