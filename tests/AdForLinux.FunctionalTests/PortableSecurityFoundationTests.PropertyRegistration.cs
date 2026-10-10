using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public async Task Entry_cache_off_registration_survives_concurrent_commit_rejection()
    {
        using var fixture = new EntryWriteFixture(); var entry = fixture.Entry;
        entry.UsePropertyCache = false;
        entry.ObjectSecurity.SetOwner(new AdForLinux.Security.Principal.SecurityIdentifier(SecurityDescriptorFixtures.U2, 0));
        var late = entry.Properties["description"];
        using var paused = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        entry.BeforePropertyRegistration = _ => { paused.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10))); };
        var edit = Task.Run(() => Record.Exception(() => late.Value = "late"));
        try
        {
            Assert.True(paused.Wait(TimeSpan.FromSeconds(10)));
            entry.WriteRequestOverride = request =>
            {
                fixture.Writes.Add(request); release.Set();
                Assert.True(edit.Wait(TimeSpan.FromSeconds(10)));
                Assert.IsType<InvalidOperationException>(edit.Result);
                return ResultCode.Success;
            };
            Assert.Throws<InvalidOperationException>(entry.CommitChanges);
            Assert.True(late.Changed); Assert.Equal("late", late.Value);
            Assert.Single(fixture.Writes);
        }
        finally { release.Set(); await edit.WaitAsync(TimeSpan.FromSeconds(10)); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_retained_wrapper_registration_survives_cache_reload_failure(bool cacheOff)
    {
        using var fixture = new EntryWriteFixture(); var entry = fixture.Entry;
        entry.UsePropertyCache = !cacheOff;
        var retained = entry.Properties["description"];
        _ = entry.ObjectSecurity; entry.CommitChanges();
        entry.PropertyReadOverride = (_, _) => throw new TimeoutException("controlled cache reload");
        Assert.Throws<TimeoutException>(() => retained.Value = "still pending");
        entry.CommitChanges();
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        var change = Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal("description", change.Name); Assert.Equal("still pending", change[0]);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Entry_retained_wrapper_reload_keeps_io_unlocked_and_never_republishes_after_commit(bool cacheOff)
    {
        using var fixture = new EntryWriteFixture(); var entry = fixture.Entry;
        entry.UsePropertyCache = !cacheOff;
        var retained = entry.Properties["description"];
        _ = entry.ObjectSecurity; entry.CommitChanges();
        entry.PropertyReadOverride = (_, _) =>
        {
            // The edit must already be registered before this read, and the peer
            // commit must be able to capture it without waiting for a held gate.
            var commit = Task.Run(entry.CommitChanges);
            Assert.True(commit.Wait(TimeSpan.FromSeconds(10)));
            return new PropertyCollection();
        };
        Assert.Throws<InvalidOperationException>(() => retained.Value = "included before reload");
        var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
        Assert.Equal("included before reload", Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>())[0]);
        Assert.False(retained.Changed);
    }

    [Theory]
    [InlineData("commit")] [InlineData("refresh")] [InlineData("partial-refresh")]
    public async Task Entry_registration_during_request_cannot_be_acknowledged_as_snapshot_state(string operation)
    {
        using var fixture = new EntryWriteFixture();
        var entry = fixture.Entry;
        var original = entry.Properties["description"];
        original.Value = "already pending";
        var late = entry.Properties["displayName"];
        using var beforeRegistration = new ManualResetEventSlim();
        using var register = new ManualResetEventSlim();
        entry.BeforePropertyRegistration = property =>
        {
            if (!ReferenceEquals(property, late)) return;
            beforeRegistration.Set();
            Assert.True(register.Wait(TimeSpan.FromSeconds(10)));
        };
        var edit = Task.Run(() => late.Value = "not in request snapshot");
        void CompleteRegistration()
        {
            register.Set();
            Assert.True(edit.Wait(TimeSpan.FromSeconds(10)));
        }
        try
        {
            Assert.True(beforeRegistration.Wait(TimeSpan.FromSeconds(10)));
            if (operation == "commit")
            {
                entry.WriteRequestOverride = request =>
                {
                    fixture.Writes.Add(request);
                    var modify = Assert.IsType<ModifyRequest>(request);
                    Assert.Equal("description", Assert.Single(modify.Modifications.Cast<DirectoryAttributeModification>()).Name);
                    CompleteRegistration();
                    return ResultCode.Success;
                };
                Assert.Throws<InvalidOperationException>(entry.CommitChanges);
                // The accepted first request is not safe to replay automatically.
                Assert.Throws<InvalidOperationException>(entry.CommitChanges);
                Assert.Single(fixture.Writes);
            }
            else
            {
                entry.PropertyReadOverride = (_, _) => { CompleteRegistration(); return new PropertyCollection(); };
                Assert.Throws<InvalidOperationException>(() =>
                {
                    if (operation == "refresh") entry.RefreshCache();
                    else entry.RefreshCache(new[] { "description", "displayName" });
                });
                entry.CommitChanges();
                var request = Assert.IsType<ModifyRequest>(Assert.Single(fixture.Writes));
                Assert.Equal(new[] { "description", "displayName" },
                    request.Modifications.Cast<DirectoryAttributeModification>().Select(m => m.Name).Order());
            }
            Assert.Equal("not in request snapshot", late.Value);
            if (operation == "commit")
            {
                Assert.True(late.Changed); Assert.True(original.Changed);
                Assert.Same(late, entry.Properties["displayName"]);
            }
        }
        finally { register.Set(); await edit.WaitAsync(TimeSpan.FromSeconds(10)); }
    }
}
