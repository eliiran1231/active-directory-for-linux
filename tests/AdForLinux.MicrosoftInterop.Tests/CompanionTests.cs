using System.Reflection;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using AdForLinux.DirectoryServices.MicrosoftInterop;
using Xunit;
using D = AdForLinux.DirectoryServices;
using P = AdForLinux.Security.Principal;
using A = AdForLinux.Security.AccessControl;
using M = System.DirectoryServices;
using MP = System.Security.Principal;
using static AdForLinux.FunctionalTests.SecurityDescriptorFixtures;

[assembly: SupportedOSPlatform("windows")]

namespace AdForLinux.MicrosoftInterop.Tests;

public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute() { if (!OperatingSystem.IsWindows()) Skip = "Actual Microsoft objects require Windows."; }
}
public sealed class WindowsTheoryAttribute : TheoryAttribute
{
    public WindowsTheoryAttribute() { if (!OperatingSystem.IsWindows()) Skip = "Actual Microsoft objects require Windows."; }
}

public class CompanionTests
{
    private const D.SecurityMasks All = (D.SecurityMasks)15;
    [Fact]
    public void Public_surface_is_the_approved_three_type_Windows_companion()
    {
        var assembly = typeof(MicrosoftConversions).Assembly;
        Assert.Equal("AdForLinux.DirectoryServices.MicrosoftInterop", assembly.GetName().Name);
        Assert.Equal(new[] { nameof(MicrosoftConversions), nameof(MicrosoftSecurityEdit), nameof(SecurityDescriptorSnapshot) },
            assembly.GetExportedTypes().Select(t => t.Name).OrderBy(n => n));
        Assert.All(assembly.GetExportedTypes(), type =>
        {
            Assert.Equal("AdForLinux.DirectoryServices.MicrosoftInterop", type.Namespace);
            Assert.Equal("windows", type.GetCustomAttribute<SupportedOSPlatformAttribute>()!.PlatformName);
        });
        Assert.Equal(18, typeof(MicrosoftConversions).GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly).Length);
    }
    private static D.ActiveDirectorySecurity Portable()
    {
        var result = new D.ActiveDirectorySecurity();
        result.SetOwner(new P.SecurityIdentifier(U1, 0));
        result.SetGroup(new P.SecurityIdentifier(U1, 0));
        return result;
    }

    [Fact]
    public void Snapshot_arrays_are_defensive_and_freeze_original_pending_and_observable_data()
    {
        var source = Portable();
        var snapshot = source.CaptureSnapshot();
        Assert.Equal(All, snapshot.RetrievedSections);
        Assert.Equal(D.SecurityMasks.Owner | D.SecurityMasks.Group, snapshot.PendingWriteSections);
        var raw = snapshot.GetRawBinaryForm(); var original = snapshot.GetOriginalBinaryForm();
        var observable = snapshot.GetObservableBinaryForm();
        Assert.NotEqual(raw, original);
        Array.Clear(snapshot.GetRawBinaryForm()); Array.Clear(snapshot.GetOriginalBinaryForm());
        Array.Clear(snapshot.GetObservableBinaryForm());
        source.SetOwner(new P.SecurityIdentifier(U2, 0));
        Assert.Equal(raw, snapshot.GetRawBinaryForm());
        Assert.Equal(original, snapshot.GetOriginalBinaryForm());
        Assert.Equal(observable, snapshot.GetObservableBinaryForm());
        Assert.Empty(typeof(SecurityDescriptorSnapshot).GetConstructors());
        Assert.All(typeof(SecurityDescriptorSnapshot).GetProperties(), p => Assert.Null(p.SetMethod));
        Assert.False(typeof(IDisposable).IsAssignableFrom(typeof(SecurityDescriptorSnapshot)));
        Assert.Empty(typeof(MicrosoftSecurityEdit).GetConstructors());
    }

    [Fact]
    public void Public_null_arguments_are_rejected_before_platform_construction()
    {
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectorySecurity)null!).CaptureSnapshot());
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectorySecurity)null!).ExportForEdit());
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectorySecurity)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((M.ActiveDirectorySecurity)null!).ToPortableObject(All));
        Assert.Throws<ArgumentNullException>(() => ((P.IdentityReference)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((MP.IdentityReference)null!).ToPortableObject());
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectoryAccessRule)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((M.ActiveDirectoryAccessRule)null!).ToPortableObject());
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectoryAuditRule)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((M.ActiveDirectoryAuditRule)null!).ToPortableObject());
        Assert.Throws<ArgumentNullException>(() => ((P.IdentityReferenceCollection)null!).ToMicrosoftObjects());
        Assert.Throws<ArgumentNullException>(() => ((MP.IdentityReferenceCollection)null!).ToPortableObjects());
        Assert.Throws<ArgumentNullException>(() => ((A.AuthorizationRuleCollection)null!).ToMicrosoftObjects());
        Assert.Throws<ArgumentNullException>(() => ((AuthorizationRuleCollection)null!).ToPortableObjects());
    }

    [Fact]
    public void Native_boundaries_fail_explicitly_on_non_Windows()
    {
        if (OperatingSystem.IsWindows()) return;
        var source = Portable();
        Assert.Throws<PlatformNotSupportedException>(() => source.ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => source.ExportForEdit());
        Assert.Throws<PlatformNotSupportedException>(() => source.CaptureSnapshot().ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => new P.SecurityIdentifier(U1, 0).ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => new P.NTAccount("EXAMPLE\\unknown").ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => new D.ActiveDirectoryAccessRule(new P.SecurityIdentifier(U1, 0), D.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow).ToMicrosoftObject());
    }

    [WindowsFact]
    public void Independent_copies_and_snapshots_never_edit_the_source_or_each_other()
    {
        var source = Portable(); var before = source.CaptureSnapshot();
        var snapshot = source.CaptureSnapshot();
        var first = snapshot.ToMicrosoftObject(); var second = source.ToMicrosoftObject();
        Assert.NotSame(first, second);
        Assert.Equal(first.GetSecurityDescriptorBinaryForm(), second.GetSecurityDescriptorBinaryForm());
        first.SetOwner(new MP.SecurityIdentifier(U2, 0));
        Assert.Equal(before.GetRawBinaryForm(), source.CaptureSnapshot().GetRawBinaryForm());
        Assert.Equal(second.GetSecurityDescriptorBinaryForm(), snapshot.ToMicrosoftObject().GetSecurityDescriptorBinaryForm());
        var imported = first.ToPortableObject(All);
        Assert.Equal(first.GetSecurityDescriptorBinaryForm(), imported.GetSecurityDescriptorBinaryForm());
        Assert.Equal(D.SecurityMasks.None, imported.CaptureSnapshot().PendingWriteSections);
        Assert.Throws<NotSupportedException>(() => imported.GetOwner(typeof(P.NTAccount)));
        imported.SetGroup(new P.SecurityIdentifier(U2, 0));
        Assert.Equal(new MP.SecurityIdentifier(U1, 0), first.GetGroup(typeof(MP.SecurityIdentifier)));
    }

    [WindowsTheory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(4)] [InlineData(8)] [InlineData(7)] [InlineData(15)]
    public void Import_preserves_explicit_coverage_and_partial_exports_refuse(int mask)
    {
        var native = Portable().ToMicrosoftObject();
        var source = native.ToPortableObject((D.SecurityMasks)mask);
        var snapshot = source.CaptureSnapshot();
        Assert.Equal((D.SecurityMasks)mask, snapshot.RetrievedSections);
        Assert.Equal(D.SecurityMasks.None, snapshot.PendingWriteSections);
        if (mask == 15) Assert.Equal(native.GetSecurityDescriptorBinaryForm(), snapshot.ToMicrosoftObject().GetSecurityDescriptorBinaryForm());
        else
        {
            Assert.Throws<NotSupportedException>(() => snapshot.ToMicrosoftObject());
            Assert.Throws<NotSupportedException>(() => source.ToMicrosoftObject());
            Assert.Throws<NotSupportedException>(() => source.ExportForEdit());
        }
        Assert.Throws<ArgumentOutOfRangeException>(() => native.ToPortableObject((D.SecurityMasks)16));
    }

    [WindowsTheory]
    [InlineData(false)] [InlineData(true)]
    public void Successful_apply_consumes_session_even_for_noop_and_disposal_only_releases_references(bool change)
    {
        var source = Portable();
        var edit = source.ExportForEdit(); var snapshot = edit.Snapshot; var native = edit.Object;
        Assert.Throws<ArgumentNullException>(() => edit.ApplyTo(null!));
        if (change) native.SetOwner(new MP.SecurityIdentifier(U2, 0));
        Assert.Equal(change ? D.SecurityMasks.Owner : D.SecurityMasks.None, edit.ApplyTo(source));
        Assert.Throws<InvalidOperationException>(() => edit.ApplyTo(source));
        Assert.Same(native, edit.Object); Assert.Same(snapshot, edit.Snapshot);
        var expected = source.CaptureSnapshot().GetRawBinaryForm();
        native.SetGroup(new MP.SecurityIdentifier(U2, 0));
        edit.Dispose(); edit.Dispose();
        Assert.Throws<ObjectDisposedException>(() => edit.Object);
        Assert.Throws<ObjectDisposedException>(() => edit.Snapshot);
        Assert.Throws<ObjectDisposedException>(() => edit.ApplyTo(source));
        Assert.Equal(expected, source.CaptureSnapshot().GetRawBinaryForm());
        Assert.NotEmpty(native.GetSecurityDescriptorBinaryForm());
        Assert.NotEmpty(snapshot.ToMicrosoftObject().GetSecurityDescriptorBinaryForm());
    }

    [WindowsFact]
    public void Disposing_unapplied_edits_never_saves_or_changes_source()
    {
        var source = Portable(); var before = source.CaptureSnapshot().GetRawBinaryForm();
        using (var edit = source.ExportForEdit()) edit.Object.SetOwner(new MP.SecurityIdentifier(U2, 0));
        Assert.Equal(before, source.CaptureSnapshot().GetRawBinaryForm());
        source.SetOwner(new P.SecurityIdentifier(U2, 0)); // Source remains usable.
    }

    [WindowsFact]
    public void Edit_and_snapshot_do_not_keep_the_source_wrapper_alive()
    {
        var (source, edit) = DetachedSession();
        using (edit)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            Assert.False(source.IsAlive);
            Assert.NotEmpty(edit.Object.GetSecurityDescriptorBinaryForm());
            Assert.NotEmpty(edit.Snapshot.GetRawBinaryForm());
        }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static (WeakReference, MicrosoftSecurityEdit) DetachedSession()
    {
        var source = Portable();
        return (new WeakReference(source), source.ExportForEdit());
    }

    [WindowsFact]
    public void Failed_apply_is_atomic_and_retryable_but_stale_and_unrelated_sources_refuse()
    {
        var source = Portable(); var before = source.CaptureSnapshot().GetRawBinaryForm();
        using var edit = source.ExportForEdit();
        edit.Object.SetAccessRuleProtection(true, false);
        edit.Object.SetOwner(new MP.SecurityIdentifier(U2, 0));
        Assert.Throws<NotSupportedException>(() => edit.ApplyTo(source));
        Assert.Equal(before, source.CaptureSnapshot().GetRawBinaryForm());
        Assert.Throws<InvalidOperationException>(() => edit.ApplyTo(Portable()));
        edit.Object.SetAccessRuleProtection(false, true);
        Assert.Equal(D.SecurityMasks.Owner, edit.ApplyTo(source));
        using var stale = source.ExportForEdit();
        source.SetGroup(new P.SecurityIdentifier(U2, 0));
        Assert.Throws<InvalidOperationException>(() => stale.ApplyTo(source)); // Even no-op checks generation.
        Assert.Throws<InvalidOperationException>(() => stale.ApplyTo(source));
    }

    [WindowsFact]
    public void Compiled_copy_and_local_edit_examples_use_actual_Microsoft_objects()
    {
        var source = Portable();
        Assert.IsType<M.ActiveDirectorySecurity>(AdForLinux.Examples.MicrosoftInteropUsage.IndependentCopy(source));
        Assert.Equal(D.SecurityMasks.Dacl, AdForLinux.Examples.MicrosoftInteropUsage.ApplyLocalEdit(source));
        Assert.Single(source.GetAccessRules(true, false, typeof(P.SecurityIdentifier)).Cast<A.AuthorizationRule>());
    }

    [WindowsFact]
    public void Unsupported_raw_layout_refuses_without_modifying_portable_data()
    {
        // Binary import retains the raw source separately from its observable view.
        var native = new M.ActiveDirectorySecurity();
        native.SetSecurityDescriptorBinaryForm(Build(U1, U1, Acl(4)));
        var source = native.ToPortableObject(All);
        // Unsupported control changes during edit-back must not replace that raw source.
        using var edit = source.ExportForEdit();
        var before = source.CaptureSnapshot().GetRawBinaryForm();
        edit.Object.SetAuditRuleProtection(true, false);
        Assert.Throws<NotSupportedException>(() => edit.ApplyTo(source));
        Assert.Equal(before, source.CaptureSnapshot().GetRawBinaryForm());
    }
}
