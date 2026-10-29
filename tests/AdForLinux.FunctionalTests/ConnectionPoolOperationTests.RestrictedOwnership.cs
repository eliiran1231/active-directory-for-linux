using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using System.DirectoryServices.Protocols;

namespace AdForLinux.FunctionalTests;

public partial class ConnectionPoolOperationTests
{
    private sealed class RestrictedOwner : IDisposable
    {
        internal int Disposals;
        public void Dispose() => Disposals++;
    }

    [Fact]
    public void Restricted_group_keeps_sibling_alive_until_final_member_release()
    {
        var owner = new RestrictedOwner();
        var first = new RecordingTransport(); var second = new RecordingTransport();
        var sessions = LdapRestrictedOperation.Wrap([first, second], owner, RestrictedRecipe().Options());
        sessions[0].Dispose(); sessions[0].Dispose();
        Assert.Equal(0, owner.Disposals);
        Assert.Throws<ObjectDisposedException>(() => sessions[0].ExecuteTransport(value => value.Timeout));
        Assert.Same(second, sessions[1].ExecuteTransport(value => value));
        Assert.Equal(0, owner.Disposals);
        sessions[1].Dispose(); sessions[1].Dispose();
        Assert.Equal(1, owner.Disposals);
        Assert.Equal(0, first.Disposals); Assert.Equal(0, second.Disposals); // owner owns the worker, never individual proxies
    }

    [Fact]
    public void Restricted_group_failure_retires_all_members_once_without_replay()
    {
        var owner = new RestrictedOwner();
        var first = new RecordingTransport(); var second = new RecordingTransport();
        var sessions = LdapRestrictedOperation.Wrap([first, second], owner, RestrictedRecipe().Options());
        var attempts = 0;
        Assert.Throws<IOException>(() => sessions[0].ExecuteTransport<int>(_ =>
        { attempts++; throw new IOException("Interrupted controlled operation."); }));
        Assert.Equal(1, attempts); Assert.Equal(1, owner.Disposals);
        Assert.Throws<ObjectDisposedException>(() => sessions[1].ExecuteTransport(value => value.Timeout));
        sessions[0].Dispose(); sessions[1].Dispose();
        Assert.Equal(1, owner.Disposals);
    }

    [Fact]
    public void Restricted_pair_and_referral_policy_fail_before_guard_or_source_access()
    {
        var profile = RestrictedRecipe(); var options = profile.Options();
        Assert.Throws<PlatformNotSupportedException>(() => LdapConnectionProvider.AcquirePair(options,
            RestrictedRecipe().Options(), () => TimeSpan.FromSeconds(1), default));
        Assert.Throws<PlatformNotSupportedException>(() => LdapConnectionProvider.AcquirePair(options,
            new LdapConnectionOptions { Host = profile.ServiceHost }, () => TimeSpan.FromSeconds(1), default));
        Assert.Throws<PlatformNotSupportedException>(() => LdapConnectionProvider.AcquireBatch(options, 1,
            referrals: ReferralChasingOption.All));
        Assert.Throws<PlatformNotSupportedException>(() => LdapConnectionProvider.AcquireBatch(options, 3));
        Assert.Equal((0, 0, 0), LdapRestrictedOperation.Snapshot);
    }
    [Theory]
    [InlineData("success")]
    [InlineData("size-limit")]
    [InlineData("schema-error")]
    [InlineData("schema-cancel")]
    [InlineData("late-client-timeout")]
    public void Restricted_buffered_page_materializes_with_atomic_sibling_before_group_retirement(string outcome)
    {
        var profile = RestrictedRecipe();
        using var root = profile.CreateDirectoryEntry("DC=example");
        var clock = new ConversationClock(); var counts = new List<int>();
        var owners = new List<RestrictedOwner>();
        var query = new ConversationTransport([]);
        query.Events = new([new LdapSearchEvent.Entry(TransportRow("CN=kept,DC=example", new() { ["number"] = ["42"] })),
            new LdapSearchEvent.PageEnd(Envelope(ResultCode.Success), true)]);
        query.OnRead = () => { if (query.Reads == 2 && outcome != "size-limit") clock.Ticks += TimeSpan.FromSeconds(30).Ticks; };
        if (outcome == "late-client-timeout") query.OnCleanup = () => clock.Ticks += TimeSpan.FromSeconds(40).Ticks;
        var schemaReads = 0; LdapConnectionProvider.Session[]? admittedPair = null;
        root.OperationSessionFactory = (options, count, referrals, fresh, minimum) =>
        {
            Assert.All(owners, prior => Assert.Equal(1, prior.Disposals)); // no nested admission
            counts.Add(count); var owner = new RestrictedOwner(); owners.Add(owner);
            if (count == 1) return LdapRestrictedOperation.Wrap([new ConversationTransport([])], owner, options);
            Assert.Equal(2, count);
            var schema = new RecordingTransport { Reply = command =>
            {
                Assert.Equal(0, owner.Disposals); schemaReads++;
                if (outcome == "schema-error") throw new IOException("original schema error");
                if (outcome == "schema-cancel") throw new OperationCanceledException("original schema cancellation");
                var row = command.BaseDn == ""
                    ? TransportRow("", new() { ["schemaNamingContext"] = ["CN=schema"] })
                    : TransportRow("CN=number,CN=schema", new() { ["lDAPDisplayName"] = ["number"], ["attributeSyntax"] = ["2.5.5.9"], ["oMSyntax"] = ["2"] });
                return new(ResultCode.Success, "", null, [row], [], [], []);
            } };
            return admittedPair = LdapRestrictedOperation.Wrap([query, schema], owner, options);
        };
        using var searcher = new AdForLinux.DirectoryServices.DirectorySearcher(root)
        { PageSize = 1, CacheResults = true, ServerTimeLimit = outcome == "size-limit" ? TimeSpan.FromSeconds(-1) : TimeSpan.FromSeconds(30),
            SizeLimit = outcome == "size-limit" ? 1 : 0,
            ClientTimeout = TimeSpan.FromSeconds(60), TimeProvider = clock, ReferralChasing = ReferralChasingOption.None };
        var error = Record.Exception(() =>
        {
            using var results = searcher.FindAll();
            var result = Assert.Single(results.Cast<SearchResult>());
            Assert.Equal(42, Assert.IsType<int>(result.Properties["number"][0]));
        });
        if (outcome is "success" or "size-limit") { Assert.Null(error); Assert.Equal(2, schemaReads); }
        else if (outcome == "late-client-timeout") Assert.IsType<TimeoutException>(error);
        else if (outcome == "schema-error") Assert.Equal("original schema error", Assert.IsType<IOException>(error).Message);
        else Assert.Equal("original schema cancellation", Assert.IsType<OperationCanceledException>(error).Message);
        Assert.Equal(new[] { 1, 2 }, counts); Assert.All(owners, owner => Assert.Equal(1, owner.Disposals));
        Assert.Equal(0, query.Pages); Assert.NotNull(admittedPair);
        Assert.Throws<ObjectDisposedException>(() => admittedPair![1].ExecuteTransport(value => value.Timeout));
    }

}
