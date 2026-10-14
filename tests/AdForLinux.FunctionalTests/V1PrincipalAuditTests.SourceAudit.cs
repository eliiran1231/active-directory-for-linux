using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using MatchType = AdForLinux.DirectoryServices.AccountManagement.MatchType;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Indexer_replacement_is_one_atomic_request_and_retained_wrapper_is_acknowledged(bool cached)
    {
        using var f = new Fixture();
        f.Server["description"] = ["A", "C"];
        var values = f.Entry.Properties["description"];
        f.Entry.UsePropertyCache = cached;
        values[0] = "B";
        if (cached) { Assert.Empty(f.Writes); f.Entry.CommitChanges(); }
        var request = Assert.Single(f.Writes);
        Assert.Equal(new[] { DirectoryAttributeOperation.Delete, DirectoryAttributeOperation.Add },
            request.Modifications.Cast<DirectoryAttributeModification>().Select(m => m.Operation));
        Assert.False(values.Changed);
        values.Add("D");
        if (cached) f.Entry.CommitChanges();
        Assert.Single(f.Writes[1].Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal(new object[] { "C", "B", "D" }, f.Server["description"]);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Rejected_replacement_retains_whole_intent_for_retry(bool cached)
    {
        using var f = new Fixture();
        f.Server["description"] = ["A", "C"];
        var values = f.Entry.Properties["description"];
        f.Entry.UsePropertyCache = cached;
        // Reproduce the old delete-success/add-failure path with a transport that
        // rejects any request containing Add, atomically like LDAP Modify.
        var transport = f.Entry.WriteRequestOverride!;
        f.Entry.WriteRequestOverride = request =>
            ((ModifyRequest)request).Modifications.Cast<DirectoryAttributeModification>()
                .Any(m => m.Operation == DirectoryAttributeOperation.Add)
                ? ResultCode.UnwillingToPerform : transport(request);
        if (cached) { values[0] = "B"; Assert.ThrowsAny<Exception>(() => f.Entry.CommitChanges()); }
        else Assert.ThrowsAny<Exception>(() => values[0] = "B");
        Assert.Equal(new object[] { "A", "C" }, f.Server["description"]);
        // CollectionBase rolls back its local slot when OnSetComplete throws;
        // the staged server intent remains retryable, like other failed writes.
        Assert.Equal(cached ? "B" : "A", values[0]);
        Assert.Equal(2, values.Changes.Count);
        f.Entry.WriteRequestOverride = transport;
        f.Entry.CommitChanges();
        Assert.Equal(new object[] { "C", "B" }, f.Server["description"]);
        Assert.False(values.Changed);
        Assert.Equal(new object[] { "C", "B" }, f.Entry.Properties["description"].Cast<object>());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Replacement_acknowledgment_does_not_erase_newer_edits(bool cached)
    {
        using var f = new Fixture();
        f.Server["description"] = ["A", "C"];
        var values = f.Entry.Properties["description"];
        f.Entry.UsePropertyCache = cached;
        f.AfterWrite = () => { f.Entry.UsePropertyCache = true; values.Add("D"); };
        if (cached) { values[0] = "B"; Assert.Throws<InvalidOperationException>(() => f.Entry.CommitChanges()); }
        else Assert.Throws<InvalidOperationException>(() => values[0] = "B");
        Assert.Equal(new object[] { "C", "B" }, f.Server["description"]);
        Assert.Equal(3, values.Changes.Count);
        Assert.Throws<InvalidOperationException>(() => f.Entry.CommitChanges());
        Assert.Throws<InvalidOperationException>(() => f.Entry.RefreshCache(["description"]));
        Assert.Single(f.Writes);
    }
}

public partial class V1PrincipalAuditTests
{
    [DirectoryObjectClass("customAccount")]
    private class AuditCustomUser(PrincipalContext context) : UserPrincipal(context);
    [DirectoryObjectClass("customComputer")]
    private class AuditCustomComputer(PrincipalContext context) : ComputerPrincipal(context);
    private class AuditUndeclaredUser(PrincipalContext context) : AuditCustomUser(context);
    [DirectoryObjectClass("literal*(class)")]
    private class AuditEscapedUser(PrincipalContext context) : UserPrincipal(context);

    public static IEnumerable<object[]> AuditDateFinders()
    {
        foreach (var method in new[] { "FindByLockoutTime", "FindByLogonTime", "FindByExpirationTime",
            "FindByBadPasswordAttempt", "FindByPasswordSetTime" })
        foreach (var type in new[] { typeof(AuditCustomUser), typeof(AuditCustomComputer),
            typeof(AuditUndeclaredUser), typeof(AuditEscapedUser), typeof(UserPrincipal),
            typeof(ComputerPrincipal), typeof(AuthenticablePrincipal) })
            yield return [method, type];
    }

    [Theory]
    [MemberData(nameof(AuditDateFinders))]
    public void Generic_date_finders_use_declared_custom_class(string methodName, Type type)
    {
        using var context = new PrincipalContext(ContextType.Domain, "offline.invalid", "DC=example,DC=test");
        var filters = new List<string>();
        context.DateFinderSearchOverride = searcher =>
        {
            filters.Add(searcher.Filter);
            return new SearchResultCollection(Array.Empty<SearchResult>());
        };
        var method = typeof(AuthenticablePrincipal).GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .Single(m => m.Name == methodName && m.IsGenericMethodDefinition).MakeGenericMethod(type);
        object? Invoke() => method.Invoke(null, [context, new DateTime(2024, 1, 1), MatchType.GreaterThan]);
        if (type == typeof(AuditUndeclaredUser))
        {
            Assert.IsType<InvalidOperationException>(Assert.Throws<TargetInvocationException>(() => Invoke()).InnerException);
            Assert.Empty(filters);
            return;
        }
        using var result = (IDisposable)Invoke()!;
        var expected = type == typeof(AuditCustomUser) ? "(objectClass=customAccount)"
            : type == typeof(AuditCustomComputer) ? "(objectClass=customComputer)"
            : type == typeof(AuditEscapedUser) ? @"(objectClass=literal\2a\28class\29)"
            : type == typeof(UserPrincipal) ? "(objectCategory=person)(objectClass=user)"
            : type == typeof(ComputerPrincipal) ? "(objectCategory=computer)"
            : "(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))";
        Assert.StartsWith("(&" + expected, Assert.Single(filters));
    }

    [Theory]
    [InlineData("A")] [InlineData("a")] [InlineData("B")]
    public void Indexer_does_not_infer_schema_equality_or_suppress_append(string replacement)
    {
        using var f = new Fixture();
        f.Server["description"] = ["A", "B"];
        var values = f.Entry.Properties["description"];
        values[0] = replacement;
        f.Entry.CommitChanges();
        var modifications = Assert.Single(f.Writes).Modifications;
        Assert.Equal(2, modifications.Count);
        Assert.Equal("A", modifications[0][0]);
        Assert.Equal(replacement, modifications[1][0]);
    }
}

public partial class V1PrincipalAuditTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Existing_duplicate_rejection_cannot_commit_only_the_delete(bool cached)
    {
        using var f = new Fixture();
        f.Server["description"] = ["A", "B"];
        var values = f.Entry.Properties["description"];
        f.Entry.UsePropertyCache = cached;
        var attempts = new List<ModifyRequest>();
        f.Entry.WriteRequestOverride = request =>
        {
            var modify = (ModifyRequest)request;
            attempts.Add(modify);
            var proposed = f.Server["description"].ToList();
            foreach (DirectoryAttributeModification change in modify.Modifications)
            foreach (var value in change.Cast<object>())
            {
                if (change.Operation == DirectoryAttributeOperation.Delete) proposed.Remove(value);
                else if (proposed.Contains(value)) return ResultCode.AttributeOrValueExists;
                else proposed.Add(value);
            }
            f.Server["description"] = proposed.ToArray();
            return ResultCode.Success;
        };
        if (cached) { values[0] = "B"; Assert.ThrowsAny<Exception>(() => f.Entry.CommitChanges()); }
        else Assert.ThrowsAny<Exception>(() => values[0] = "B");
        Assert.Equal(2, Assert.Single(attempts).Modifications.Count);
        Assert.Equal(new object[] { "A", "B" }, f.Server["description"]);
        Assert.Equal(2, values.Changes.Count);
        Assert.ThrowsAny<Exception>(() => f.Entry.CommitChanges());
        Assert.Equal(2, attempts.Count);
        Assert.Equal(new object[] { "A", "B" }, f.Server["description"]);
    }

    [Fact]
    public void Ordinary_persisted_Name_Save_attempts_cn_modify_and_preserves_rejected_intent()
    {
        using var f = new Fixture();
        f.Server["name"] = ["item"];
        f.Server["cn"] = ["item"];
        using var user = f.Attach(new UserPrincipal(f.Context));
        var requests = new List<DirectoryRequest>();
        f.Entry.WriteRequestOverride = request => { requests.Add(request); return ResultCode.NotAllowedOnRdn; };
        user.Name = "renamed";
        Assert.Empty(requests);
        Assert.ThrowsAny<Exception>(() => user.Save());
        var request = Assert.IsType<ModifyRequest>(Assert.Single(requests));
        var modification = Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal("cn", modification.Name);
        Assert.Equal(DirectoryAttributeOperation.Replace, modification.Operation);
        Assert.Equal("renamed", modification[0]);
        Assert.Equal("CN=item,DC=example,DC=test", request.DistinguishedName);
        Assert.Equal("renamed", user.Name);
        Assert.Equal("CN=item,DC=example,DC=test", user.DistinguishedName);
    }
}
