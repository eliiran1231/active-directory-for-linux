using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices.MicrosoftInterop;
using AdForLinux.Tests.Shared;
using Xunit;
using D = AdForLinux.DirectoryServices;
using P = AdForLinux.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

namespace AdForLinux.MicrosoftInterop.Tests;

public class IdenticalEntryInteropTests
{
    [WindowsTheory]
    [InlineData(false,false)] [InlineData(false,true)]
    [InlineData(true,false)] [InlineData(true,true)]
    public void Public_entry_identical_assignment_keeps_sessions_current_until_real_ACL_edit(bool audit,bool priorOwner)
    {
        using var fixture = new OfflineEntry(audit);
        var source = fixture.Entry.ObjectSecurity;Assert.Equal(fixture.Raw,source.CaptureSnapshot().GetRawBinaryForm());
        if (priorOwner) source.SetOwner(new P.SecurityIdentifier(U2,0));
        var before = source.CaptureSnapshot();
        using var noOp = source.ExportForEdit();
        using var failed = source.ExportForEdit();
        using var stale = source.ExportForEdit();
        var supplied = before.GetRawBinaryForm();var saved = (byte[])supplied.Clone();
        source.SetSecurityDescriptorBinaryForm(supplied,AccessControlSections.All);
        Assert.Equal(saved,supplied);
        Assert.Equal(before.GetRawBinaryForm(),source.CaptureSnapshot().GetRawBinaryForm());
        Assert.Equal(priorOwner ? D.SecurityMasks.Owner : D.SecurityMasks.None,source.CaptureSnapshot().PendingWriteSections);
        Assert.Equal(D.SecurityMasks.None,noOp.ApplyTo(source));
        Assert.Throws<InvalidOperationException>(() => noOp.ApplyTo(source));

        var nativeBefore = failed.Object.GetSecurityDescriptorBinaryForm();
        failed.Object.SetAuditRuleProtection(!failed.Object.AreAuditRulesProtected,true);
        var beforeFailure = source.CaptureSnapshot();
        Assert.Throws<NotSupportedException>(() => failed.ApplyTo(source));
        AssertSnapshot(beforeFailure,source.CaptureSnapshot());Assert.NotNull(failed.Object);Assert.NotNull(failed.Snapshot);
        failed.Object.SetSecurityDescriptorBinaryForm(nativeBefore);
        Assert.Equal(D.SecurityMasks.None,failed.ApplyTo(source)); // Failed application neither consumed nor invalidated it.

        IdenticalAssignmentCases.EditAcl(source,audit);
        var after = source.CaptureSnapshot();
        Assert.NotEqual(beforeFailure.GetRawBinaryForm(),after.GetRawBinaryForm());
        var expected = IdenticalAssignmentCases.Target(audit) | (priorOwner ? D.SecurityMasks.Owner : D.SecurityMasks.None);
        Assert.Equal(expected,after.PendingWriteSections);
        Assert.Throws<InvalidOperationException>(() => stale.ApplyTo(source));
        AssertSnapshot(after,source.CaptureSnapshot());Assert.NotNull(stale.Object);Assert.NotNull(stale.Snapshot);
        fixture.Entry.CommitChanges();
        AssertWrite(Assert.Single(fixture.Writes),expected,after.GetRawBinaryForm());
    }

    [WindowsTheory]
    [InlineData(false)] [InlineData(true)]
    public void Public_entry_noop_commit_after_identical_assignment_revokes_old_edit_attachment(bool audit)
    {
        using var fixture = new OfflineEntry(audit);var source = fixture.Entry.ObjectSecurity;
        using var edit = source.ExportForEdit();var before = source.CaptureSnapshot();
        source.SetSecurityDescriptorBinaryForm(before.GetRawBinaryForm(),AccessControlSections.All);
        Assert.Equal(D.SecurityMasks.None,source.CaptureSnapshot().PendingWriteSections);
        fixture.Entry.CommitChanges();Assert.Empty(fixture.Writes);
        var after = source.CaptureSnapshot();
        Assert.ThrowsAny<InvalidOperationException>(() => edit.ApplyTo(source));
        AssertSnapshot(after,source.CaptureSnapshot());Assert.NotNull(edit.Object);
        var fresh = fixture.Entry.ObjectSecurity;Assert.NotSame(source,fresh);
        Assert.Equal(before.GetRawBinaryForm(),fresh.CaptureSnapshot().GetRawBinaryForm());
        using var current = fresh.ExportForEdit();Assert.Equal(D.SecurityMasks.None,current.ApplyTo(fresh));
        Assert.Empty(fixture.Writes);
    }

    private static void AssertSnapshot(SecurityDescriptorSnapshot before,SecurityDescriptorSnapshot after)
    {
        Assert.Equal(before.GetRawBinaryForm(),after.GetRawBinaryForm());
        Assert.Equal(before.GetOriginalBinaryForm(),after.GetOriginalBinaryForm());
        Assert.Equal(before.GetObservableBinaryForm(),after.GetObservableBinaryForm());
        Assert.Equal(before.PendingWriteSections,after.PendingWriteSections);Assert.Equal(before.RetrievedSections,after.RetrievedSections);
    }
    private static void AssertWrite(ModifyRequest request,D.SecurityMasks mask,byte[] raw)
    {
        Assert.Equal("CN=item,DC=example,DC=com",request.DistinguishedName);
        var modification = Assert.Single(request.Modifications.Cast<DirectoryAttributeModification>());
        Assert.Equal("nTSecurityDescriptor",modification.Name);Assert.Equal(DirectoryAttributeOperation.Replace,modification.Operation);
        Assert.Equal(raw,Assert.IsType<byte[]>(Assert.Single(modification.Cast<object>())));
        Assert.Equal((System.DirectoryServices.Protocols.SecurityMasks)(int)mask,
            Assert.IsType<SecurityDescriptorFlagControl>(Assert.Single(request.Controls.Cast<DirectoryControl>())).SecurityMasks);
    }
    private sealed class OfflineEntry : IDisposable
    {
        internal readonly D.DirectoryEntry Entry = new("LDAP://dc.example/CN=item,DC=example,DC=com");
        internal byte[] Raw;
        internal readonly List<ModifyRequest> Writes = new();
        internal OfflineEntry(bool audit)
        {
            Raw = IdenticalAssignmentCases.Baseline(audit);Entry.Options.SecurityMasks = IdenticalAssignmentCases.All;
            // This assembly intentionally has no core friend access. Reflection only
            // installs the existing fake transport/read hooks; all operations under test
            // use the public DirectoryEntry and MicrosoftInterop APIs. No new product hook.
            Hook("SecurityReadOverride",(Func<D.SecurityMasks,byte[]>)(mask =>
            {Assert.Equal(IdenticalAssignmentCases.All,mask);return (byte[])Raw.Clone();}));
            Hook("PropertyReadOverride",(Func<string[],bool,D.PropertyCollection>)((_,_) => (D.PropertyCollection)Activator.CreateInstance(typeof(D.PropertyCollection),
                BindingFlags.Instance | BindingFlags.NonPublic,binder:null,args:new object?[] {null,null},culture:null)!));
            Hook("WriteRequestOverride",(Func<DirectoryRequest,ResultCode>)(request =>
            {
                var modify = Assert.IsType<ModifyRequest>(request);Writes.Add(modify);
                var attribute = Assert.Single(modify.Modifications.Cast<DirectoryAttributeModification>());
                Assert.Equal("nTSecurityDescriptor",attribute.Name);Raw = (byte[])Assert.IsType<byte[]>(attribute[0]).Clone();
                return ResultCode.Success;
            }));
        }
        private void Hook(string name,Delegate value)
        {
            var property = typeof(D.DirectoryEntry).GetProperty(name,BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(property);property.SetValue(Entry,value);
        }
        public void Dispose() => Entry.Dispose();
    }
}
