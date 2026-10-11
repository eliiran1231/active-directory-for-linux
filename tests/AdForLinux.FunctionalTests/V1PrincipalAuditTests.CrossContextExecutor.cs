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
        internal int Sends, Reads, TransportCloses;
        internal Action<int>? AfterSend;
        internal ExecutorFixture()
        {
            User = new UserPrincipal(Proof.Source);
            typeof(Principal).GetMethod("AttachExisting", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(User, [Proof.Source, Proof.Entry]);
        }
        internal Principal.CrossContextExecutor Create() => User.CreatePrivateCrossContextExecutor(Proof.Destination, options =>
        {
            Assert.Equal("destination.invalid", options.Host);
            Assert.Equal("destination-reader", options.BindDn); Assert.Equal("destination-test-value", options.BindPassword);
            return this;
        });
        public DirectoryResponse Send(DirectoryRequest request)
        {
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
                    ["objectGUID"] = [((Fault == "wrong-guid" && !isDomain) || (Fault == "wrong-domain" && isDomain) ? Guid.NewGuid() : isDomain ? Proof.DomainGuid : Proof.ObjectGuid).ToByteArray()],
                    ["objectSid"] = [CrossContextFixture.SidBytes(Fault == "wrong-sid" ? "S-1-5-21-500-501-502-503" : isDomain ? Proof.DomainSid : Proof.ObjectSid)],
                    ["distinguishedName"] = [isDomain ? CrossContextFixture.DomainDn : Dn],
                    ["description"] = [Description]
                };
                return SaveResponse(isRoot ? "" : isDomain ? CrossContextFixture.DomainDn : Dn, values,
                    Fault == "missing" ? 0 : Fault == "multiple" ? 2 : 1,
                    Fault == "partial" ? ResultCode.SizeLimitExceeded : ResultCode.Success, false, Fault == "reference");
            }
            return SaveResponse("", [], 0, ResultCode.Success, false, false);
        }
        void IDisposable.Dispose() => TransportCloses++;
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
    [InlineData("multiple")] [InlineData("wrong-guid")] [InlineData("wrong-domain")] [InlineData("wrong-sid")]
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
