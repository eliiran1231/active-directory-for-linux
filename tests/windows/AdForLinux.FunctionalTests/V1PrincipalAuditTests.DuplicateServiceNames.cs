using System.DirectoryServices.Protocols;
using System.Reflection;
using AdForLinux.DirectoryServices;
using AdForLinux.DirectoryServices.AccountManagement;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class V1PrincipalAuditTests
{
    [Fact]
    public void Duplicate_persisted_service_name_is_canonical_after_save_and_removal()
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames;
        names.Add("HOST/old"); Assert.Equal(2, names.Count); // Public list semantics.
        computer.Save();
        Assert.Equal(new[] { "HOST/old" }, names);
        Assert.Equal(new object[] { "HOST/old" }, f.Server["servicePrincipalName"]);
        Assert.Empty(f.Writes);
        names.Remove("HOST/old"); computer.Save(); computer.Save();
        Assert.Empty(names); Assert.Empty(f.Server["servicePrincipalName"]);
        Assert.Single(f.Writes);
    }

    private sealed class CreationComputer(PrincipalContext context) : ComputerPrincipal(context)
    {
        internal void PrepareInsert() => base.OnBeforeSave();
        internal void AcknowledgeInsert() => base.OnAfterSave();
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Skipped_service_name_write_requires_fresh_evidence_before_acknowledgement(bool unrelatedWrite)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames; names.Add("HOST/old");
        f.Server["servicePrincipalName"] = []; // The cached duplicate is not proof.
        if (unrelatedWrite) computer.Description = "pending";
        Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Equal(2, names.Count); Assert.Empty(f.Writes);
        f.Server["servicePrincipalName"] = ["HOST/old"];
        computer.Save(); Assert.Equal(new[] { "HOST/old" }, names);
        Assert.Equal(unrelatedWrite ? 1 : 0, f.Writes.Count);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Skipped_service_name_write_rejects_incomplete_transport_readback(bool partialCode)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames; names.Add("HOST/old");
        using var connection = InstallRawRead(f, () => partialCode
            ? RawResponseWithStatus(ResultCode.SizeLimitExceeded, [], ("servicePrincipalName", ["HOST/old"]))
            : RawResponse(("servicePrincipalName;range=0-0", ["HOST/old"])));
        Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Equal(2, names.Count); Assert.Empty(f.Writes); Assert.Equal(1, connection.ObjectReads);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Duplicate_acknowledgement_preserves_later_set_intent(bool removeBoth)
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames; names.Add("HOST/new"); names.Add("HOST/new");
        f.BeforeWrite = () =>
        {
            f.BeforeWrite = null; names.Remove("HOST/new");
            if (removeBoth) names.Remove("HOST/new");
        };
        computer.Save(); computer.Save();
        Assert.Equal(removeBoth ? new[] { "HOST/old" } : new[] { "HOST/old", "HOST/new" }, names);
        Assert.Equal(names.Cast<object>(), f.Server["servicePrincipalName"]);
        Assert.Equal(removeBoth ? 2 : 1, f.Writes.Count);
    }

    [Fact]
    public void Rejected_duplicate_insert_keeps_list_and_intent_for_retry()
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames; names.Add("HOST/new"); names.Add("HOST/new");
        f.Fail = true; Assert.ThrowsAny<Exception>(() => computer.Save()); Assert.Equal(3, names.Count);
        f.Fail = false; computer.Save(); Assert.Equal(new[] { "HOST/old", "HOST/new" }, names);
        names.Remove("HOST/new"); computer.Save(); Assert.Equal(new object[] { "HOST/old" }, f.Server["servicePrincipalName"]);
    }

    [Fact]
    public void Duplicate_no_op_cannot_acknowledge_a_conflicting_direct_entry_delete()
    {
        using var f = new Fixture(); using var computer = f.Attach(new ComputerPrincipal(f.Context));
        var names = computer.ServicePrincipalNames; names.Add("HOST/old");
        f.Entry.Properties["servicePrincipalName"].Remove("HOST/old");
        Assert.Throws<InvalidOperationException>(() => computer.Save());
        Assert.Empty(f.Writes); Assert.Equal(2, names.Count);
        Assert.True(f.Entry.Properties["servicePrincipalName"].Changed);
        Assert.Equal(new object[] { "HOST/old" }, f.Server["servicePrincipalName"]);
        names.Clear(); computer.Save(); // Explicitly resolve the conflicting intents.
        Assert.Empty(names); Assert.Empty(f.Server["servicePrincipalName"]); Assert.Single(f.Writes);
    }

    [Fact]
    public void Duplicate_initial_service_names_acknowledge_the_actual_add_values()
    {
        using var f = new Fixture(); using var computer = new CreationComputer(f.Context);
        var names = computer.ServicePrincipalNames;
        names.Add("HOST/new"); names.Add("HOST/new"); Assert.Equal(2, names.Count);
        computer.PrepareInsert();
        var pending = (Dictionary<string, object?>)typeof(Principal)
            .GetField("_pending", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(computer)!;
        // Exercise the real creation staging, Add planner and completion hook,
        // substituting only the directory transport/fixture attachment.
        using var parent = new DirectoryEntry("LDAP://offline.invalid/DC=example,DC=test");
        using var child = parent.Children.Add("CN=item", "computer");
        child.Properties["servicePrincipalName"].Value = pending["servicePrincipalName"];
        child.WriteRequestOverride = request =>
        {
            var add = Assert.IsType<AddRequest>(request);
            f.Server["servicePrincipalName"] = add.Attributes.Cast<DirectoryAttribute>()
                .Single(a => a.Name == "servicePrincipalName").Cast<object>().ToArray();
            return ResultCode.Success;
        };
        child.CommitChanges(); f.Attach(computer); pending.Clear(); computer.AcknowledgeInsert();
        Assert.Equal(new[] { "HOST/new" }, names);
        Assert.Equal(new object[] { "HOST/new" }, f.Server["servicePrincipalName"]);
        names.Remove("HOST/new"); computer.Save();
        Assert.Empty(names); Assert.Empty(f.Server["servicePrincipalName"]);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void Unchanged_name_in_same_container_does_not_submit_modify_dn(bool scalar)
    {
        var f = new ExecutorFixture();
        try
        {
            f.Proof.Fault = "same-container";
            typeof(PrincipalContext).GetField("_container", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.Proof.Destination, "OU=source," + CrossContextFixture.DomainDn);
            f.User.Name = "item"; if (scalar) f.User.Description = "after";
            using var operation = f.Create(); operation.Execute();
            Assert.Equal(scalar ? 1 : 0, f.Sends);
            Assert.Equal(Principal.CrossContextExecutor.Phase.Published, operation.State);
            Assert.Same(f.Proof.Entry, f.User.GetUnderlyingObject());
            Assert.Same(f.Proof.Destination, f.User.Context);
        }
        finally { f.Cleanup(); }
    }

    [Fact]
    public void Changed_name_in_same_container_still_submits_modify_dn()
    {
        var f = new ExecutorFixture();
        try
        {
            f.Proof.Fault = "same-container";
            var container = "OU=source," + CrossContextFixture.DomainDn;
            typeof(PrincipalContext).GetField("_container", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(f.Proof.Destination, container);
            f.User.Name = "renamed";
            f.AfterSend = _ => f.Dn = "CN=renamed," + container;
            using var operation = f.Create(); operation.Execute();
            Assert.Equal(1, f.Sends); Assert.Equal(Principal.CrossContextExecutor.Phase.Published, operation.State);
            Assert.Equal("CN=renamed," + container, f.Proof.Entry.DistinguishedName);
        }
        finally { f.Cleanup(); }
    }
}
