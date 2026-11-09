using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using AdForLinux.DirectoryServices.Ldap;
using Xunit;
using Phase = AdForLinux.DirectoryServices.AccountManagement.Principal.CrossContextExecutor.Phase;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    private sealed class ExecutorFixture : IDisposable, ICrossContextExecutorTransport
    {
        internal readonly CrossContextFixture Proof = new();
        internal readonly UserPrincipal User;
        internal string Fault = "", Dn = CrossContextFixture.ItemDn, Description = "before";
        internal int Sends, Reads, TransportCloses, TransportOpens;
        internal readonly List<TimeSpan> RequestTimeouts = [];
        internal Action<int>? AfterReconcileRead;
        internal TimeSpan ControlledOpenTimeout;
        internal Action? AfterControlledOpen;
        internal bool FailClose;
        internal Action<int>? AfterSend;
        internal ExecutorFixture()
        {
            User = new UserPrincipal(Proof.Source);
            typeof(Principal).GetMethod("AttachExisting", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(User, [Proof.Source, Proof.Entry]);
        }
        internal Principal.CrossContextExecutor Create(TimeProvider? clock = null) => User.CreatePrivateCrossContextExecutor(Proof.Destination, options =>
        {
            Assert.Equal("destination.invalid", options.Host);
            Assert.Equal("destination-reader", options.BindDn); Assert.Equal("destination-test-value", options.BindPassword);
            TransportOpens++; ControlledOpenTimeout = options.Timeout; AfterControlledOpen?.Invoke(); return this;
        }, clock);
        public DirectoryResponse Send(DirectoryRequest request, TimeSpan remaining)
        {
            Assert.True(remaining > TimeSpan.Zero);
            RequestTimeouts.Add(remaining);
            if (request is SearchRequest preflight && Proof.Reads.Count < 7)
                return Proof.Read(true, preflight);
            if (request is ModifyDNRequest move)
            {
                Sends++;
                Assert.Equal($"<GUID={Proof.ObjectGuid:D}>", move.DistinguishedName);
                Assert.Equal($"<GUID={Proof.ContainerGuid:D}>", move.NewParentDistinguishedName);
                if (Fault == "reject-move") return SaveResponse("", [], 0, ResultCode.InsufficientAccessRights, false, false);
                if (Fault != "lost-before-move") Dn = move.NewName + "," + CrossContextFixture.DomainDn;
                AfterSend?.Invoke(Sends);
                if (Fault is "lost-before-move" or "lost-after-move") throw new TimeoutException("move response lost");
            }
            else if (request is ModifyRequest modify)
            {
                Sends++;
                Assert.Equal($"<GUID={Proof.ObjectGuid:D}>", modify.DistinguishedName);
                var change = Assert.Single(modify.Modifications.Cast<DirectoryAttributeModification>());
                Assert.Equal("description", change.Name); Assert.Equal(DirectoryAttributeOperation.Replace, change.Operation);
                if (Fault == "reject-modify") return SaveResponse("", [], 0, ResultCode.InsufficientAccessRights, false, false);
                if (Fault != "lost-before-modify") Description = (string)change[0];
                AfterSend?.Invoke(Sends);
                if (Fault is "lost-before-modify" or "lost-after-modify") throw new TimeoutException("modify response lost");
            }
            else
            {
                var search = Assert.IsType<SearchRequest>(request); Reads++;
                var isRoot = search.DistinguishedName.Length == 0;
                var isDomain = (string)search.Filter == "(objectClass=domainDNS)";
                var isContainer = ((string)search.Filter).Contains(LdapFilter.EscapeBytes(Proof.ContainerGuid.ToByteArray()));
                var containerDn = Proof.Fault == "same-container" ? "OU=source," + CrossContextFixture.DomainDn : CrossContextFixture.DomainDn;
                var rowDn = isDomain ? CrossContextFixture.DomainDn : isContainer ? containerDn : Dn;
                var rowGuid = isDomain ? Proof.DomainGuid : isContainer ? Proof.ContainerGuid : Proof.ObjectGuid;
                if ((Fault == "wrong-guid" && !isDomain && !isContainer) || (Fault == "wrong-domain" && isDomain)
                    || (Fault == "wrong-container-guid" && isContainer)) rowGuid = Guid.NewGuid();
                if (!isRoot && !isDomain)
                {
                    Assert.Equal(CrossContextFixture.DomainDn, search.DistinguishedName);
                    var control = Assert.Single(search.Controls.Cast<DirectoryControl>());
                    Assert.Equal(AdIdentityLookup.DomainScopeControl, control.Type); Assert.True(control.IsCritical);
                }
                Dictionary<string, object[]> values = isRoot ? new()
                {
                    ["defaultNamingContext"] = [CrossContextFixture.DomainDn],
                    ["configurationNamingContext"] = ["CN=Configuration," + CrossContextFixture.DomainDn],
                    ["namingContexts"] = [CrossContextFixture.DomainDn, "CN=Configuration," + CrossContextFixture.DomainDn],
                    ["supportedControl"] = [AdIdentityLookup.DomainScopeControl]
                } : new()
                {
                    ["objectGUID"] = [rowGuid.ToByteArray()],
                    ["objectSid"] = [CrossContextFixture.SidBytes(Fault == "wrong-sid" ? "S-1-5-21-500-501-502-503" : isDomain ? Proof.DomainSid : Proof.ObjectSid)],
                    ["distinguishedName"] = [rowDn],
                    ["description"] = [Description]
                };
                var response = SaveResponse(isRoot ? "" : rowDn, values,
                    Fault == "missing" ? 0 : Fault == "multiple" ? 2 : 1,
                    Fault == "partial" ? ResultCode.SizeLimitExceeded : ResultCode.Success, false, Fault == "reference");
                AfterReconcileRead?.Invoke(Reads);
                return response;
            }
            return SaveResponse("", [], 0, ResultCode.Success, false, false);
        }
        void IDisposable.Dispose()
        {
            TransportCloses++;
            if (FailClose) throw new InvalidOperationException("controlled close failed");
        }
        internal void Cleanup() { User.Dispose(); Proof.Dispose(); }
    }

    [Fact]
    public void Private_executor_publishes_destination_on_same_wrapper_and_revokes_old_authority()
    {
        var f = new ExecutorFixture();
        try
        {
            f.User.Name = "pending, name"; f.User.Description = "after";
            var entry = f.Proof.Entry; var properties = entry.Properties; var guid = properties["objectGUID"];
            var options = entry.Options; var resolver = DirectoryIdentityResolver.ForEntry(entry);
            using var operation = f.Create();
            Assert.Throws<InvalidOperationException>(() => f.User.Description = "late");
            operation.Execute();
            Assert.Equal(Phase.Published, operation.State); Assert.Equal(2, f.Sends);
            Assert.Same(entry, f.User.GetUnderlyingObject()); Assert.Same(f.Proof.Destination, f.User.Context);
            Assert.Contains("destination.invalid", entry.Path); Assert.Equal("destination-reader", entry.Username);
            Assert.Equal(@"CN=pending\, name," + CrossContextFixture.DomainDn, entry.DistinguishedName);
            Assert.Empty(f.User.StagedValues); Assert.Equal(0, f.Proof.Writes);
            Assert.Throws<InvalidOperationException>(() => guid.Value = Guid.NewGuid().ToByteArray());
            Assert.Throws<InvalidOperationException>(() => guid.Add(Guid.NewGuid().ToByteArray()));
            Assert.Throws<InvalidOperationException>(() => guid.Clear());
            Assert.Equal(0, f.Proof.Writes);
            Assert.Throws<InvalidOperationException>(() => _ = properties.Count);
            Assert.Throws<InvalidOperationException>(() => options.PageSize = 10);
            Assert.Throws<InvalidOperationException>(() => resolver.Checked(() => true));
            Assert.Throws<InvalidOperationException>(() => operation.Execute());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_revokes_retained_configuration_before_destination_io()
    {
        var f = new ExecutorFixture();
        try
        {
            var entry = f.Proof.Entry;
            var retained = entry.Options;
            using var operation = f.Create();
            operation.Execute();
            Assert.Equal(Phase.Published, operation.State);
            var connectionField = typeof(DirectoryEntry).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!;
            Assert.Null(connectionField.GetValue(entry));
            Assert.Contains("revoked", Assert.Throws<InvalidOperationException>(() => retained.GetCurrentServerName()).Message);
            Assert.Contains("revoked", Assert.Throws<InvalidOperationException>(() => retained.IsMutuallyAuthenticated()).Message);
            Assert.Null(connectionField.GetValue(entry));
            var requests = 0;
            entry.SetControlledRetainedConnections(SaveReadConnection.Create(_ =>
                {
                    requests++;
                    return SaveResponse("", new() { ["dnsHostName"] = ["destination.invalid"] },
                        1, ResultCode.Success, false, false);
                }, () => { }));
            Assert.Throws<InvalidOperationException>(() => retained.GetCurrentServerName());
            Assert.Throws<InvalidOperationException>(() => retained.IsMutuallyAuthenticated());
            Assert.Equal(0, requests);
            Assert.Equal("destination.invalid", entry.Options.GetCurrentServerName());
            Assert.Equal(1, requests);
            Assert.Throws<PlatformNotSupportedException>(() => entry.Options.IsMutuallyAuthenticated());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public async Task Private_executor_admits_only_one_execute_while_still_prepared()
    {
        var f = new ExecutorFixture { Fault = "lost-before-move" };
        try
        {
            using var operation = f.Create();
            var ownerGate = typeof(Principal).GetField("_crossContextGate", BindingFlags.Instance | BindingFlags.NonPublic)!
                .GetValue(f.User)!;
            var admission = operation.GetType().GetField("operationActive", BindingFlags.Instance | BindingFlags.NonPublic)!;
            Task active;
            lock (ownerGate)
            {
                active = Task.Run(() => Assert.Throws<TimeoutException>(() => operation.Execute()));
                Assert.True(SpinWait.SpinUntil(() => (int)admission.GetValue(operation)! == 1, TimeSpan.FromSeconds(10)));
                Assert.Equal(Phase.Prepared, operation.State);
                Assert.Contains("active", Assert.Throws<InvalidOperationException>(() => operation.Execute()).Message);
                Assert.Equal(0, f.Sends);
            }
            await active;
            Assert.Equal(1, f.Sends); Assert.Equal(0, f.Reads);
            Assert.Equal(Phase.Uncertain, operation.State);
            Assert.Throws<InvalidOperationException>(() => operation.Execute());
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData("execute")]
    [InlineData("reconcile")]
    [InlineData("dispose")]
    public async Task Private_executor_rejects_overlapping_operations_without_replay_or_publication(string overlapping)
    {
        var f = new ExecutorFixture { Fault = "lost-after-move" };
        using var sent = new ManualResetEventSlim();
        using var resume = new ManualResetEventSlim();
        Task? active = null;
        Principal.CrossContextExecutor? operation = null;
        try
        {
            f.AfterSend = _ =>
            {
                sent.Set();
                Assert.True(resume.Wait(TimeSpan.FromSeconds(10)));
            };
            operation = f.Create();
            active = Task.Run(() => Assert.Throws<TimeoutException>(() => operation.Execute()));
            Assert.True(sent.Wait(TimeSpan.FromSeconds(10)));
            Action overlap = overlapping switch
            {
                "execute" => operation.Execute,
                "reconcile" => operation.Reconcile,
                _ => operation.Dispose
            };
            Assert.Contains("active", Assert.Throws<InvalidOperationException>(overlap).Message);
            Assert.Equal(1, f.Sends); Assert.Equal(0, f.Reads); Assert.Equal(0, f.TransportCloses);
            Assert.Equal(Phase.Uncertain, operation.State);
            resume.Set();
            await active;
            Assert.Equal(Phase.Uncertain, operation.State);
            Assert.Equal(1, f.Sends); Assert.Equal(0, f.Reads);
            Assert.Contains("source.invalid", f.Proof.Entry.Path);
            Assert.Throws<InvalidOperationException>(() => operation.Execute());
            operation.Dispose(); operation.Dispose();
            Assert.Equal(1, f.TransportCloses);
            Assert.Throws<ObjectDisposedException>(() => operation.Reconcile());
            Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
            Assert.Equal(0, f.Proof.Writes);
        }
        finally
        {
            resume.Set();
            if (active is not null) await active;
            operation?.Dispose();
            f.Cleanup();
        }
    }

    [Theory]
    [InlineData("reject-move", "Rejected", 1)]
    [InlineData("reject-modify", "MoveAcknowledged", 2)]
    [InlineData("lost-before-move", "Uncertain", 1)]
    [InlineData("lost-after-move", "Uncertain", 1)]
    [InlineData("lost-before-modify", "Uncertain", 2)]
    [InlineData("lost-after-modify", "Uncertain", 2)]
    public void Private_executor_classifies_outcomes_and_never_compensates_or_retries(string fault, string phase, int sends)
    {
        var f = new ExecutorFixture { Fault = fault };
        try
        {
            f.User.Description = "after";
            using var operation = f.Create();
            if (fault.StartsWith("reject")) Assert.Throws<DirectoryOperationException>(() => operation.Execute());
            else Assert.Throws<TimeoutException>(() => operation.Execute());
            Assert.Equal(phase, operation.State.ToString()); Assert.Equal(sends, f.Sends); Assert.Equal(0, f.Proof.Writes);
            Assert.Throws<InvalidOperationException>(() => operation.Execute());
            if (fault == "reject-move")
            {
                Assert.Same(f.Proof.Source, f.User.Context); Assert.Equal("after", f.User.Description);
                Assert.Equal(CrossContextFixture.ItemDn, f.Proof.Entry.DistinguishedName);
            }
            else
            {
                Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
                Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.RefreshCache());
                Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.Close());
                Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.Username = "escape");
                Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.Path = "LDAP://other.invalid/CN=escape");
                Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.Rename("CN=escape"));
                Assert.Throws<InvalidOperationException>(() => f.User.Save());
                operation.Dispose();
                Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
            }
            Assert.Equal(sends, f.Sends); Assert.Equal(0, f.Proof.Writes);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData("reference")] [InlineData("partial")] [InlineData("missing")]
    [InlineData("multiple")] [InlineData("wrong-guid")] [InlineData("wrong-domain")] [InlineData("wrong-sid")] [InlineData("wrong-container-guid")]
    public void Private_executor_incomplete_or_wrong_identity_readback_keeps_quarantine(string fault)
    {
        var f = new ExecutorFixture { Fault = fault };
        try
        {
            f.User.Description = "after"; using var operation = f.Create();
            Assert.Throws<InvalidOperationException>(() => operation.Execute());
            Assert.Equal(Phase.ModifyAcknowledged, operation.State); Assert.Equal(2, f.Sends);
            Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_reconciles_uncertain_modify_by_guid_without_resending()
    {
        var f = new ExecutorFixture { Fault = "lost-after-modify" };
        try
        {
            f.User.Description = "after"; using var operation = f.Create();
            Assert.Throws<TimeoutException>(() => operation.Execute());
            f.Fault = ""; operation.Reconcile();
            Assert.Equal(Phase.Published, operation.State); Assert.Equal(2, f.Sends);
            Assert.Same(f.Proof.Entry, f.User.GetUnderlyingObject()); Assert.Same(f.Proof.Destination, f.User.Context);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_does_not_acknowledge_unsent_scalar_after_uncertain_move()
    {
        var f = new ExecutorFixture { Fault = "lost-after-move" };
        try
        {
            f.User.Description = "after"; using var operation = f.Create();
            Assert.Throws<TimeoutException>(() => operation.Execute());
            f.Fault = ""; f.Description = "after";
            Assert.Throws<InvalidOperationException>(() => operation.Reconcile());
            Assert.Equal(1, f.Sends); Assert.Equal(0, f.Reads); Assert.Equal(Phase.Uncertain, operation.State);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Private_executor_owner_revocation_after_send_prevents_publication(bool entry)
    {
        var f = new ExecutorFixture();
        try
        {
            f.User.Description = "after";
            using var operation = f.Create();
            f.AfterSend = _ => { if (entry) f.Proof.Entry.Dispose(); else f.Proof.Destination.Dispose(); };
            Assert.Throws<ObjectDisposedException>(() => operation.Execute());
            Assert.Equal(Phase.MoveAcknowledged, operation.State); Assert.Equal(1, f.Sends);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_abandonment_before_send_preserves_pending_intent()
    {
        var f = new ExecutorFixture();
        try
        {
            f.User.Description = "after"; var operation = f.Create(); operation.Dispose();
            Assert.Equal(Phase.Abandoned, operation.State); Assert.Equal(0, f.Sends);
            Assert.Same(f.Proof.Source, f.User.Context); Assert.Equal("after", f.User.Description);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData("entry")] [InlineData("password")] [InlineData("null")] [InlineData("security")]
    public void Private_executor_refuses_unsupported_intent_before_open_or_write(string shape)
    {
        var f = new ExecutorFixture();
        try
        {
            if (shape == "entry") f.Proof.Entry.Properties["displayName"].Value = "direct";
            if (shape == "password") typeof(AuthenticablePrincipal).GetField("_passwordToSet", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.User, "not-sent");
            if (shape == "null") f.User.Description = null;
            if (shape == "security") typeof(DirectoryEntry).GetField("_objectSecurity", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.Proof.Entry, new ActiveDirectorySecurity());
            Assert.Throws<NotSupportedException>(() => f.Create());
            Assert.Equal(0, f.Sends); Assert.Equal(0, f.TransportCloses); Assert.Equal(0, f.Proof.Writes);
        }
        finally { f.Cleanup(); }
    }
    [Fact]
    public void Private_executor_same_container_scalar_save_rebinds_without_move()
    {
        var f = new ExecutorFixture();
        try
        {
            f.Proof.Fault = "same-container";
            typeof(PrincipalContext).GetField("_container", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.Proof.Destination, "OU=source," + CrossContextFixture.DomainDn);
            f.User.Description = "after"; using var operation = f.Create(); operation.Execute();
            Assert.Equal(1, f.Sends); Assert.Equal(Phase.Published, operation.State);
            Assert.Same(f.Proof.Entry, f.User.GetUnderlyingObject()); Assert.Same(f.Proof.Destination, f.User.Context);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_move_only_reconciliation_does_not_need_a_scalar_write()
    {
        var f = new ExecutorFixture { Fault = "lost-after-move" };
        try
        {
            using var operation = f.Create(); Assert.Throws<TimeoutException>(() => operation.Execute());
            f.Fault = ""; operation.Reconcile();
            Assert.Equal(1, f.Sends); Assert.Equal(Phase.Published, operation.State);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_source_cleanup_failure_blocks_publication()
    {
        var f = new ExecutorFixture();
        try
        {
            typeof(DirectoryEntry).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.Proof.Entry, SaveReadConnection.Create(_ => throw new Exception("must not send"),
                    () => throw new InvalidOperationException("cleanup failed")));
            f.User.Description = "after"; using var operation = f.Create();
            Assert.Throws<AggregateException>(() => operation.Execute());
            Assert.Equal(Phase.Verified, operation.State); Assert.Equal(2, f.Sends);
            Assert.Throws<InvalidOperationException>(() => operation.Reconcile());
            Assert.Equal(2, f.Sends);
            Assert.Contains("source.invalid", f.Proof.Entry.Path);
            Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_reserves_retained_property_mutators_without_changing_values()
    {
        var f = new ExecutorFixture();
        try
        {
            var property = f.Proof.Entry.Properties["objectGUID"];
            var before = ((byte[])property.Value!).ToArray();
            using var operation = f.Create();
            Assert.Throws<InvalidOperationException>(() => property.Value = new byte[16]);
            Assert.Throws<InvalidOperationException>(() => property.Add(new byte[16]));
            Assert.Throws<InvalidOperationException>(() => property.Clear());
            Assert.Equal(before, (byte[])property.Value!);
            operation.Execute(); Assert.Equal(Phase.Published, operation.State);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_detects_binary_cache_mutation_bypassing_setters_before_send()
    {
        var f = new ExecutorFixture();
        try
        {
            var bytes = (byte[])f.Proof.Entry.Properties["objectGUID"].Value!;
            var operation = f.Create(); bytes[0] ^= 1;
            Assert.Throws<InvalidOperationException>(() => operation.Execute()); Assert.Equal(0, f.Sends);
            Assert.Throws<InvalidOperationException>(() => operation.Dispose());
            Assert.Throws<InvalidOperationException>(() => f.Proof.Entry.CommitChanges());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Public_save_does_not_dispatch_private_executor()
    {
        var f = new ExecutorFixture();
        try
        {
            Assert.Equal(CrossContextSavePlan.ExecutionBoundary,
                Assert.Throws<PlatformNotSupportedException>(() => f.User.Save(f.Proof.Destination)).Message);
            Assert.Equal(0, f.Sends); Assert.Equal(0, f.Proof.Writes);
        }
        finally { f.Cleanup(); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Private_executor_failed_open_or_revocation_during_open_releases_unsent_reservation(bool revoke)
    {
        var f = new ExecutorFixture();
        try
        {
            f.User.Description = "after";
            Assert.Throws<InvalidOperationException>(() => f.User.CreatePrivateCrossContextExecutor(f.Proof.Destination, _ =>
            {
                if (!revoke) throw new InvalidOperationException("open failure");
                f.Proof.Destination.IdentityLifetime.Invalidate(); return f;
            }));
            Assert.Equal(0, f.Sends); Assert.Equal(revoke ? 1 : 0, f.TransportCloses);
            Assert.Equal("after", f.User.Description); Assert.Same(f.Proof.Source, f.User.Context);
            Assert.Same(f.Proof.Entry, f.User.GetUnderlyingObject());
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Private_executor_revokes_enumerated_and_pre_refresh_property_wrappers()
    {
        var f = new ExecutorFixture();
        try
        {
            var beforeRefresh = f.Proof.Entry.Properties["objectGUID"];
            var enumeration = f.Proof.Entry.Properties.GetEnumerator(); Assert.True(enumeration.MoveNext());
            var enumerated = Assert.IsType<PropertyValueCollection>(enumeration.Value);
            f.Proof.Entry.RefreshCache();
            using var operation = f.Create(); operation.Execute();
            Assert.Throws<InvalidOperationException>(() => beforeRefresh.Add(new byte[16]));
            Assert.Throws<InvalidOperationException>(() => enumerated.Add("must not reach destination"));
            Assert.Throws<InvalidOperationException>(() => ((PropertyValueCollection)enumeration.Value).Value = "blocked");
            Assert.Equal(0, f.Proof.Writes); Assert.Same(f.Proof.Entry, f.User.GetUnderlyingObject());
        }
        finally { f.Cleanup(); }
    }

}
