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
    public void Public_surface_is_the_export_only_two_type_Windows_companion()
    {
        var assembly = typeof(MicrosoftConversions).Assembly;
        Assert.Equal("AdForLinux.DirectoryServices.MicrosoftInterop", assembly.GetName().Name);
        Assert.Equal(new[] { nameof(MicrosoftConversions), nameof(SecurityDescriptorSnapshot) },
            assembly.GetExportedTypes().Select(t => t.Name).OrderBy(n => n));
        Assert.All(assembly.GetExportedTypes(), type =>
        {
            Assert.Equal("AdForLinux.DirectoryServices.MicrosoftInterop", type.Namespace);
            Assert.Equal("windows", type.GetCustomAttribute<SupportedOSPlatformAttribute>()!.PlatformName);
        });
        var methods = typeof(MicrosoftConversions).GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly);
        static string Shape(string name, Type input, Type result) => $"{name}:{input.FullName}->{result.FullName}";
        var expected = new[] {
            Shape("ToMicrosoftObject",typeof(P.SecurityIdentifier),typeof(MP.SecurityIdentifier)),
            Shape("ToMicrosoftObject",typeof(P.NTAccount),typeof(MP.NTAccount)),
            Shape("ToMicrosoftObject",typeof(P.IdentityReference),typeof(MP.IdentityReference)),
            Shape("ToMicrosoftObject",typeof(D.ActiveDirectoryAccessRule),typeof(M.ActiveDirectoryAccessRule)),
            Shape("ToMicrosoftObject",typeof(D.ActiveDirectoryAuditRule),typeof(M.ActiveDirectoryAuditRule)),
            Shape("ToMicrosoftObjects",typeof(P.IdentityReferenceCollection),typeof(IReadOnlyList<MP.IdentityReference>)),
            Shape("ToMicrosoftObjects",typeof(A.AuthorizationRuleCollection),typeof(IReadOnlyList<AuthorizationRule>)),
            Shape("ToMicrosoftObject",typeof(D.ActiveDirectorySecurity),typeof(M.ActiveDirectorySecurity)),
            Shape("CaptureSnapshot",typeof(D.ActiveDirectorySecurity),typeof(SecurityDescriptorSnapshot)) };
        Assert.Equal(expected.OrderBy(x=>x),methods.Select(m=>Shape(m.Name,Assert.Single(m.GetParameters()).ParameterType,m.ReturnType)).OrderBy(x=>x));
        Assert.All(methods, m => Assert.True(m.IsDefined(typeof(System.Runtime.CompilerServices.ExtensionAttribute))));
        Assert.Null(assembly.GetType("AdForLinux.DirectoryServices.MicrosoftInterop.MicrosoftSecurityEdit"));
        Assert.Equal(new[] { "PendingWriteSections", "RetrievedSections" },
            typeof(SecurityDescriptorSnapshot).GetProperties().Select(p => p.Name).OrderBy(n => n));
        var snapshotMethods = typeof(SecurityDescriptorSnapshot).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName).ToArray();
        Assert.Equal(new[] { "GetObservableBinaryForm", "GetOriginalBinaryForm", "GetRawBinaryForm", "ToMicrosoftObject" },
            snapshotMethods.Select(m => m.Name).OrderBy(n => n));
        Assert.All(snapshotMethods, m =>
        {
            Assert.Empty(m.GetParameters());
            Assert.Equal(m.Name == "ToMicrosoftObject" ? typeof(M.ActiveDirectorySecurity) : typeof(byte[]), m.ReturnType);
        });
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
    }

    [Fact]
    public void Public_null_arguments_are_rejected_before_platform_construction()
    {
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectorySecurity)null!).CaptureSnapshot());
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectorySecurity)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((P.IdentityReference)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectoryAccessRule)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((D.ActiveDirectoryAuditRule)null!).ToMicrosoftObject());
        Assert.Throws<ArgumentNullException>(() => ((P.IdentityReferenceCollection)null!).ToMicrosoftObjects());
        Assert.Throws<ArgumentNullException>(() => ((A.AuthorizationRuleCollection)null!).ToMicrosoftObjects());
    }

    [Fact]
    public void Native_boundaries_fail_explicitly_on_non_Windows()
    {
        if (OperatingSystem.IsWindows()) return;
        var source = Portable();
        Assert.Throws<PlatformNotSupportedException>(() => source.ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => source.CaptureSnapshot().ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => new P.SecurityIdentifier(U1, 0).ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => new P.NTAccount("EXAMPLE\\unknown").ToMicrosoftObject());
        Assert.Throws<PlatformNotSupportedException>(() => new D.ActiveDirectoryAccessRule(new P.SecurityIdentifier(U1, 0), D.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow).ToMicrosoftObject());
    }

    [WindowsTheory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public void Export_refuses_unverified_raw_data_without_changing_existing_intent(int variant)
    {
        var raw = variant switch
        {
            0 => Build(U1,U1,Acl(4,Ace(9,0,16,U1,new byte[] {1,2,3,4}))),
            1 => Build(U1,U1,Acl(4,Ace(0,0x20,16,U1))),
            2 => Build(U1,U1,Acl(4),AclWithTail(4,new byte[] {1,2,3,4},Ace(2,0x40,16,U1))),
            3 => Build(U1,U1,Acl(4),tail:new byte[] {1,2,3,4}),
            4 => Build(U1,U1,Acl(4),extraControl:0x40),
            _ => Build(U1,U1,Acl(4),sbz1:7)
        };
        using var entry = ReviewCorrectionTests.ReadEntry(raw,All);
        var source = entry.ObjectSecurity;
        source.SetOwner(new P.SecurityIdentifier(U2,0));
        var before = source.CaptureSnapshot();
        foreach (var export in new Func<M.ActiveDirectorySecurity>[] { source.ToMicrosoftObject, before.ToMicrosoftObject })
        {
            var error = Record.Exception(() => export());
            Assert.True(error is InvalidOperationException or NotSupportedException);
            var after = source.CaptureSnapshot();
            Assert.Equal(before.GetRawBinaryForm(),after.GetRawBinaryForm());
            Assert.Equal(before.GetOriginalBinaryForm(),after.GetOriginalBinaryForm());
            Assert.Equal(before.GetObservableBinaryForm(),after.GetObservableBinaryForm());
            Assert.Equal(before.PendingWriteSections,after.PendingWriteSections);
            Assert.Equal(D.SecurityMasks.Owner,after.PendingWriteSections);
        }
    }

    [WindowsFact]
    public void Export_and_snapshot_do_not_keep_the_source_wrapper_alive()
    {
        var (weak, snapshot, exported) = DetachedCopies();
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        Assert.False(weak.IsAlive);
        Assert.NotEmpty(snapshot.ToMicrosoftObject().GetSecurityDescriptorBinaryForm());
        Assert.NotEmpty(exported.GetSecurityDescriptorBinaryForm());
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static (WeakReference, SecurityDescriptorSnapshot, M.ActiveDirectorySecurity) DetachedCopies()
    {
        var source = Portable();
        return (new WeakReference(source),source.CaptureSnapshot(),source.ToMicrosoftObject());
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
        source.SetGroup(new P.SecurityIdentifier(U2, 0));
        Assert.Equal(new MP.SecurityIdentifier(U1, 0), first.GetGroup(typeof(MP.SecurityIdentifier)));

    }

    [WindowsTheory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(4)] [InlineData(8)] [InlineData(7)] [InlineData(15)]
    public void Portable_read_coverage_is_preserved_and_partial_exports_refuse(int mask)
    {
        using var entry = ReviewCorrectionTests.ReadEntry(Build(U1,U1,Acl(4),Acl(4)), (D.SecurityMasks)mask);
        var source = entry.ObjectSecurity;
        if (mask == 0) mask = (int)(D.SecurityMasks.Owner | D.SecurityMasks.Group | D.SecurityMasks.Dacl);
        var snapshot = source.CaptureSnapshot();
        Assert.Equal((D.SecurityMasks)mask, snapshot.RetrievedSections);
        Assert.Equal(D.SecurityMasks.None, snapshot.PendingWriteSections);
        if (mask == 15) Assert.Equal(source.ToMicrosoftObject().GetSecurityDescriptorBinaryForm(), snapshot.ToMicrosoftObject().GetSecurityDescriptorBinaryForm());
        else
        {
            Assert.Throws<NotSupportedException>(() => snapshot.ToMicrosoftObject());
            Assert.Throws<NotSupportedException>(() => source.ToMicrosoftObject());
        }
    }

    [WindowsFact]
    public void Compiled_export_examples_use_independent_Microsoft_objects()
    {
        var source = Portable();
        Assert.IsType<M.ActiveDirectorySecurity>(AdForLinux.Examples.MicrosoftInteropUsage.IndependentCopy(source));
        var before = source.CaptureSnapshot();
        var native = AdForLinux.Examples.MicrosoftInteropUsage.EditIndependentCopy(source);
        Assert.Single(native.GetAccessRules(true,false,typeof(MP.SecurityIdentifier)).Cast<AuthorizationRule>());
        Assert.Equal(before.GetRawBinaryForm(),source.CaptureSnapshot().GetRawBinaryForm());
        Assert.Equal(before.PendingWriteSections,source.CaptureSnapshot().PendingWriteSections);
    }

}
