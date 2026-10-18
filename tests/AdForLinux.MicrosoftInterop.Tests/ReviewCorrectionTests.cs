using AdForLinux.DirectoryServices.MicrosoftInterop;
using AdForLinux.Tests.Shared;
using Xunit;
using System.Reflection;
using D = AdForLinux.DirectoryServices;
using M = System.DirectoryServices;
using MP = System.Security.Principal;

namespace AdForLinux.MicrosoftInterop.Tests;

public class ReviewCorrectionTests
{
    public static IEnumerable<object[]> CoverageCases() => DetachedCoverageCases.Matrix();

    [Theory]
    [MemberData(nameof(CoverageCases))]
    public void Public_entry_snapshot_reports_all_accepted_intent_without_promoting_coverage(int mask, string operation, int required)
    {
        using var entry = ReadEntry(DetachedCoverageCases.Baseline(), (D.SecurityMasks)mask);
        var source = entry.ObjectSecurity;
        // DirectoryEntry interprets None as its ordinary owner/group/DACL default.
        if (mask == 0) mask = (int)(D.SecurityMasks.Owner | D.SecurityMasks.Group | D.SecurityMasks.Dacl);
        var before = source.CaptureSnapshot();
        // Entry-owned descriptors enforce retrieved coverage for every mutation route.
        if ((required & ~mask) != 0)
        {
            Assert.Throws<InvalidOperationException>(() => DetachedCoverageCases.Apply(source, operation));
            Assert.Equal(before.GetRawBinaryForm(), source.CaptureSnapshot().GetRawBinaryForm());
            Assert.Equal(D.SecurityMasks.None, source.CaptureSnapshot().PendingWriteSections);
        }
        else
        {
            DetachedCoverageCases.Apply(source, operation);
            Assert.Equal((D.SecurityMasks)required, source.CaptureSnapshot().PendingWriteSections);
        }
        Assert.Equal((D.SecurityMasks)mask, source.CaptureSnapshot().RetrievedSections);
        Assert.Equal(D.SecurityMasks.None, before.PendingWriteSections);
        Assert.Equal(before.GetOriginalBinaryForm(), source.CaptureSnapshot().GetOriginalBinaryForm());
        if (mask != 15 && OperatingSystem.IsWindows())
        {
            Assert.Throws<NotSupportedException>(() => source.CaptureSnapshot().ToMicrosoftObject());
            Assert.Throws<NotSupportedException>(() => source.ToMicrosoftObject());
        }
    }

    public static IEnumerable<object[]> RevocationCases()
    {
        foreach (var change in new[] { "close", "dispose", "path", "username", "password" })
            foreach (var edited in new[] { false, true }) yield return new object[] { change, edited };
    }

    [WindowsTheory]
    [MemberData(nameof(RevocationCases))]
    public void Exported_data_stays_independent_after_entry_revocation(string change, bool edited)
    {
        // Public entry loading borrows a revocable context; the existing fake read hook prevents I/O.
        using var entry = new D.DirectoryEntry("LDAP://dc.example/CN=item,DC=example,DC=com");
        entry.Options.SecurityMasks = (D.SecurityMasks)15;
        typeof(D.DirectoryEntry).GetProperty("SecurityReadOverride", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(entry, (Func<D.SecurityMasks, byte[]>)(_ => DetachedCoverageCases.Baseline()));
        var source = entry.ObjectSecurity;
        var exported = source.ToMicrosoftObject();
        var snapshot = source.CaptureSnapshot();
        if (edited) exported.SetOwner(new MP.SecurityIdentifier("S-1-5-21-1-2-3-1002"));
        var before = source.CaptureSnapshot();
        switch (change)
        {
            case "close": entry.Close(); break;
            case "dispose": entry.Dispose(); break;
            case "path": entry.Path = "LDAP://dc.example/CN=other,DC=example,DC=com"; break;
            case "username": entry.Username = "EXAMPLE\\other"; break;
            default: entry.Password = "changed-test-only"; break;
        }
        Assert.Equal(before.GetRawBinaryForm(), source.CaptureSnapshot().GetRawBinaryForm());
        Assert.Equal(before.PendingWriteSections, source.CaptureSnapshot().PendingWriteSections);
        Assert.NotEmpty(exported.GetSecurityDescriptorBinaryForm());
        Assert.NotEmpty(snapshot.ToMicrosoftObject().GetSecurityDescriptorBinaryForm());
        exported.SetGroup(new MP.SecurityIdentifier("S-1-1-0"));
        Assert.Equal(before.GetRawBinaryForm(), source.CaptureSnapshot().GetRawBinaryForm());
    }
    internal static D.DirectoryEntry ReadEntry(byte[] raw, D.SecurityMasks mask)
    {
        var entry = new D.DirectoryEntry("LDAP://unused.example/DC=example,DC=com");
        entry.Options.SecurityMasks = mask;
        typeof(D.DirectoryEntry).GetProperty("SecurityReadOverride", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(entry, (Func<D.SecurityMasks,byte[]>)(_ => (byte[])raw.Clone()));
        return entry;
    }
}
