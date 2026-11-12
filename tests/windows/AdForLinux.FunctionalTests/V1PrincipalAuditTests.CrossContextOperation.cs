using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;
using Phase = AdForLinux.DirectoryServices.AccountManagement.Principal.CrossContextExecutor.Phase;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Fact]
    public void Private_operation_retains_both_sessions_and_one_decreasing_budget_through_publication()
    {
        var f = new ExecutorFixture(); var clock = new SaveClock();
        try
        {
            f.User.Description = "after";
            f.Proof.AfterOpen = _ => clock.Elapsed += TimeSpan.FromSeconds(3);
            f.Proof.AfterRead = _ => clock.Elapsed += TimeSpan.FromSeconds(1);
            var operation = f.Create(clock);
            Assert.Equal(TimeSpan.FromSeconds(30), Assert.Single(f.Proof.OpenTimeouts));
            Assert.Equal(TimeSpan.FromSeconds(27), f.ControlledOpenTimeout);
            Assert.Equal(1, f.Proof.Opens); Assert.Equal(1, f.TransportOpens);
            Assert.Equal(0, f.Proof.Closes); Assert.Equal(0, f.TransportCloses);
            clock.Elapsed += TimeSpan.FromSeconds(5);
            f.AfterSend = _ => clock.Elapsed += TimeSpan.FromSeconds(2);
            f.AfterReconcileRead = _ => clock.Elapsed += TimeSpan.FromSeconds(1);
            operation.Execute();
            Assert.Equal(Phase.Published, operation.State);
            Assert.Equal(10, f.RequestTimeouts.Count);
            Assert.Equal(TimeSpan.FromSeconds(15), f.RequestTimeouts[4]);
            Assert.Equal(TimeSpan.FromSeconds(13), f.RequestTimeouts[5]);
            Assert.Equal(TimeSpan.FromSeconds(8), f.RequestTimeouts[^1]);
            Assert.True(f.RequestTimeouts.Zip(f.RequestTimeouts.Skip(1)).All(p => p.First >= p.Second));
            Assert.Equal(1, f.Proof.Opens); Assert.Equal(1, f.TransportOpens);
            Assert.Equal(0, f.Proof.Closes); Assert.Equal(0, f.TransportCloses);
            operation.Dispose(); operation.Dispose();
            Assert.Equal(1, f.Proof.Closes); Assert.Equal(1, f.TransportCloses);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_operation_expiry_before_send_preserves_unsent_intent_and_can_abandon()
    {
        var f = new ExecutorFixture(); var clock = new SaveClock();
        try
        {
            f.User.Description = "after"; var operation = f.Create(clock);
            clock.Elapsed = TimeSpan.FromSeconds(30);
            Assert.Throws<TimeoutException>(() => operation.Execute());
            Assert.Equal(Phase.Prepared, operation.State); Assert.Equal(0, f.Sends); Assert.Equal(0, f.Reads);
            operation.Dispose();
            Assert.Equal(Phase.Abandoned, operation.State);
            Assert.Equal("after", f.User.Description); Assert.Same(f.Proof.Source, f.User.Context);
            Assert.Equal(1, f.Proof.Closes); Assert.Equal(1, f.TransportCloses); Assert.Equal(0, f.Proof.Writes);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Private_operation_expiry_after_possible_delivery_never_retries_or_publishes(bool lostResponse)
    {
        var f = new ExecutorFixture { Fault = lostResponse ? "lost-after-move" : "" }; var clock = new SaveClock();
        try
        {
            f.User.Description = "after"; using var operation = f.Create(clock);
            f.AfterSend = _ => clock.Elapsed = TimeSpan.FromSeconds(30);
            Assert.Throws<TimeoutException>(() => operation.Execute());
            Assert.Equal(lostResponse ? Phase.Uncertain : Phase.MoveAcknowledged, operation.State);
            Assert.Equal(1, f.Sends); Assert.Equal(0, f.Reads);
            Assert.Throws<InvalidOperationException>(() => operation.Execute());
            Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
            Assert.Contains("source.invalid", f.Proof.Entry.Path); Assert.Equal(0, f.Proof.Writes);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void Private_operation_expiry_during_reconciliation_retains_quarantine(int read)
    {
        var f = new ExecutorFixture(); var clock = new SaveClock();
        try
        {
            f.User.Description = "after"; using var operation = f.Create(clock);
            f.AfterReconcileRead = index => { if (index == read) clock.Elapsed = TimeSpan.FromSeconds(30); };
            Assert.Throws<TimeoutException>(() => operation.Execute());
            Assert.Equal(Phase.ModifyAcknowledged, operation.State);
            Assert.Throws<TimeoutException>(() => operation.Reconcile());
            Assert.Equal(2, f.Sends); Assert.Equal(read, f.Reads);
            Assert.Contains("source.invalid", f.Proof.Entry.Path);
            Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_operation_checks_deadline_after_source_cleanup_before_atomic_publication()
    {
        var f = new ExecutorFixture(); var clock = new SaveClock();
        try
        {
            typeof(DirectoryEntry).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.Proof.Entry, SaveReadConnection.Create(_ => throw new Exception("unexpected source request"),
                    () => clock.Elapsed = TimeSpan.FromSeconds(30)));
            using var operation = f.Create(clock);
            Assert.Throws<TimeoutException>(() => operation.Execute());
            Assert.Equal(Phase.Verified, operation.State); Assert.Equal(4, f.Reads);
            Assert.Contains("source.invalid", f.Proof.Entry.Path);
            Assert.Throws<TimeoutException>(() => operation.Reconcile()); Assert.Equal(4, f.Reads);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData("open")] [InlineData("preflight")]
    public void Private_operation_expired_preflight_closes_both_sessions_without_sending(string stage)
    {
        var f = new ExecutorFixture(); var clock = new SaveClock();
        try
        {
            f.User.Description = "after";
            if (stage == "open") f.AfterControlledOpen = () => clock.Elapsed = TimeSpan.FromSeconds(30);
            else f.Proof.AfterRead = index => { if (index == 7) clock.Elapsed = TimeSpan.FromSeconds(30); };
            Assert.Throws<TimeoutException>(() => f.Create(clock));
            Assert.Equal(stage == "open" ? 0 : 7, f.Proof.Reads.Count);
            Assert.Equal(1, f.Proof.Closes); Assert.Equal(1, f.TransportCloses);
            Assert.Equal(0, f.Sends); Assert.Equal("after", f.User.Description);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData("source")] [InlineData("destination")] [InlineData("entry")] [InlineData("edit")]
    public void Private_operation_rechecks_stale_owners_and_frozen_edits_at_final_read(string owner)
    {
        var f = new ExecutorFixture();
        try
        {
            f.User.Description = "after"; using var operation = f.Create();
            f.AfterReconcileRead = index =>
            {
                if (index != 4) return;
                if (owner == "source") f.Proof.Source.IdentityLifetime.Invalidate();
                else if (owner == "destination") f.Proof.Destination.IdentityLifetime.Invalidate();
                else if (owner == "entry") f.Proof.Entry.IdentityLifetime.Invalidate();
                else ((Dictionary<string, object?>)typeof(Principal).GetField("_pending", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .GetValue(f.User)!)["description"] = "changed behind reservation";
            };
            Assert.Throws<InvalidOperationException>(() => operation.Execute());
            Assert.Equal(Phase.ModifyAcknowledged, operation.State);
            Assert.Equal(2, f.Sends); Assert.Equal(4, f.Reads);
            Assert.Contains("source.invalid", f.Proof.Entry.Path); Assert.Equal(0, f.Proof.Writes);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData("source", false)] [InlineData("destination", false)] [InlineData("entry", false)]
    [InlineData("source", true)] [InlineData("destination", true)] [InlineData("entry", true)]
    public void Private_operation_rejects_owner_rebinding_or_disposal_before_send(string owner, bool dispose)
    {
        var f = new ExecutorFixture();
        try
        {
            var operation = f.Create();
            if (owner == "source") { if (dispose) f.Proof.Source.Dispose(); else f.Proof.Source.IdentityLifetime.Invalidate(); }
            else if (owner == "destination") { if (dispose) f.Proof.Destination.Dispose(); else f.Proof.Destination.IdentityLifetime.Invalidate(); }
            else { if (dispose) f.Proof.Entry.Dispose(); else f.Proof.Entry.IdentityLifetime.Invalidate(); }
            Assert.ThrowsAny<InvalidOperationException>(() => operation.Execute());
            Assert.Equal(0, f.Sends); Assert.Equal(0, f.Reads); Assert.Equal(Phase.Prepared, operation.State);
            Assert.ThrowsAny<InvalidOperationException>(() => operation.Dispose());
            Assert.Equal(1, f.TransportCloses); Assert.Equal(1, f.Proof.Closes);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Private_operation_publication_revokes_configuration_call_already_in_progress(bool mutual)
    {
        var f = new ExecutorFixture();
        using var admitted = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        Task? call = null;
        try
        {
            var options = f.Proof.Entry.Options;
            f.Proof.Entry.BeforeConfigurationConnection = () =>
            { admitted.Set(); Assert.True(resume.Wait(TimeSpan.FromSeconds(10))); };
            call = Task.Run(() => Assert.Throws<InvalidOperationException>(() =>
            { if (mutual) options.IsMutuallyAuthenticated(); else options.GetCurrentServerName(); }));
            Assert.True(admitted.Wait(TimeSpan.FromSeconds(10)));
            using var operation = f.Create(); operation.Execute();
            Assert.Equal(Phase.Published, operation.State);
            resume.Set(); await call;
            Assert.Equal(0, f.Proof.Writes);
            Assert.Null(typeof(DirectoryEntry).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(f.Proof.Entry));
        }
        finally { resume.Set(); if (call is not null) await call; f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Private_operation_handles_property_registration_crossing_reservation_and_publication(bool enumerated)
    {
        var f = new ExecutorFixture();
        using var registering = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        Task<Exception?>? edit = null;
        try
        {
            var iterator = f.Proof.Entry.Properties.GetEnumerator(); Assert.True(iterator.MoveNext());
            var property = enumerated ? (PropertyValueCollection)iterator.Current : f.Proof.Entry.Properties["objectGUID"];
            f.Proof.Entry.BeforePropertyRegistration = _ =>
            { registering.Set(); Assert.True(resume.Wait(TimeSpan.FromSeconds(10))); };
            edit = Task.Run<Exception?>(() => Record.Exception(() => property.Value = Guid.NewGuid().ToByteArray()));
            Assert.True(registering.Wait(TimeSpan.FromSeconds(10)));
            if (enumerated)
            {
                using var operation = f.Create(); operation.Execute();
                Assert.Equal(Phase.Published, operation.State);
            }
            else
            {
                Assert.ThrowsAny<InvalidOperationException>(() => f.Create());
                Assert.Equal(0, f.Sends); Assert.Equal(0, f.TransportOpens);
            }
            resume.Set(); var failure = await edit;
            if (enumerated) Assert.IsType<InvalidOperationException>(failure);
            Assert.Equal(0, f.Proof.Writes);
        }
        finally { resume.Set(); if (edit is not null) await edit; f.Cleanup(); }
    }

    [Fact]
    public async Task Private_operation_revokes_an_inflight_old_lazy_property_loader()
    {
        var f = new ExecutorFixture();
        using var loading = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        Task? read = null;
        try
        {
            f.Proof.Entry.Close();
            var oldProperties = f.Proof.Entry.Properties;
            f.Proof.Entry.RefreshCache();
            var originalRead = f.Proof.Entry.PropertyReadOverride!;
            var requests = 0;
            f.Proof.Entry.PropertyReadOverride = (names, all) =>
            {
                requests++; loading.Set(); Assert.True(resume.Wait(TimeSpan.FromSeconds(10)));
                return originalRead(names, all);
            };
            read = Task.Run(() => Assert.Throws<InvalidOperationException>(() => _ = oldProperties.Count));
            Assert.True(loading.Wait(TimeSpan.FromSeconds(10)));
            using var operation = f.Create(); operation.Execute();
            Assert.Equal(Phase.Published, operation.State);
            resume.Set(); await read;
            Assert.Throws<InvalidOperationException>(() => _ = oldProperties.Count);
            Assert.Equal(1, requests); Assert.Equal(0, f.Proof.Writes);
        }
        finally { resume.Set(); if (read is not null) await read; f.Cleanup(); }
    }

    [Fact]
    public void Private_operation_requires_explicit_container_without_opening_extra_sessions()
    {
        var f = new ExecutorFixture();
        try
        {
            typeof(PrincipalContext).GetField("_container", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.Proof.Destination, null);
            Assert.Throws<NotSupportedException>(() => f.Create());
            Assert.Equal(0, f.Proof.Opens); Assert.Equal(0, f.TransportOpens); Assert.Equal(0, f.Sends);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_operation_disposal_attempts_both_session_closes_when_destination_cleanup_fails()
    {
        var f = new ExecutorFixture { FailClose = true };
        try
        {
            f.User.Description = "after"; var operation = f.Create();
            Assert.Throws<InvalidOperationException>(() => operation.Dispose());
            Assert.Equal(Phase.Abandoned, operation.State);
            Assert.Equal(1, f.TransportCloses); Assert.Equal(1, f.Proof.Closes);
            operation.Dispose();
            Assert.Equal("after", f.User.Description); Assert.Equal(0, f.Sends);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Production_preflight_session_cannot_admit_a_write()
    {
        using var f = new CrossContextFixture();
        using var operation = new CrossContextSaveOperation(f.Source, f.Destination, f.Entry, f.ObjectGuid);
        _ = operation.Prepare(CrossContextFixture.DomainDn, null);
        var admitted = false;
        Assert.Throws<NotSupportedException>(() => operation.SendWrite(
            new System.DirectoryServices.Protocols.ModifyRequest("<GUID=" + f.ObjectGuid + ">"), () => admitted = true));
        Assert.False(admitted); Assert.Equal(0, f.Writes); Assert.Equal(7, f.Reads.Count);
    }
}
