using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;

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
}
