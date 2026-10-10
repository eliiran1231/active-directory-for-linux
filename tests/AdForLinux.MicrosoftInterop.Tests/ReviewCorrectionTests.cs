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

    [WindowsTheory]
    [MemberData(nameof(CoverageCases))]
    public void Public_import_snapshot_reports_all_accepted_intent_without_promoting_coverage(int mask, string operation, int required)
    {
        var native = new M.ActiveDirectorySecurity();
        native.SetSecurityDescriptorBinaryForm(DetachedCoverageCases.Baseline());
        var source = native.ToPortableObject((D.SecurityMasks)mask);
        var before = source.CaptureSnapshot();
        if ((operation.StartsWith("typed-add-") || operation.StartsWith("modify-")) && (required & ~mask) != 0)
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
        if (mask != 15)
        {
            Assert.Throws<NotSupportedException>(() => source.CaptureSnapshot().ToMicrosoftObject());
            Assert.Throws<NotSupportedException>(() => source.ExportForEdit());
        }
    }

    public static IEnumerable<object[]> RevocationCases()
    {
        foreach (var change in new[] { "close", "dispose", "path", "username", "password" })
            foreach (var edited in new[] { false, true }) yield return new object[] { change, edited };
    }

    [WindowsTheory]
    [MemberData(nameof(RevocationCases))]
    public void Public_ApplyTo_checks_entry_revocation_without_lookup_or_persistence(string change, bool edited)
    {
        // Public entry loading borrows a revocable context; the existing fake read hook prevents I/O.
        using var entry = new D.DirectoryEntry("LDAP://dc.example/CN=item,DC=example,DC=com");
        entry.Options.SecurityMasks = (D.SecurityMasks)15;
        typeof(D.DirectoryEntry).GetProperty("SecurityReadOverride", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(entry, (Func<D.SecurityMasks, byte[]>)(_ => DetachedCoverageCases.Baseline()));
        var source = entry.ObjectSecurity;
        using var session = source.ExportForEdit();
        if (edited) session.Object.SetOwner(new MP.SecurityIdentifier("S-1-5-21-1-2-3-1002"));
        var before = source.CaptureSnapshot();
        switch (change)
        {
            case "close": entry.Close(); break;
            case "dispose": entry.Dispose(); break;
            case "path": entry.Path = "LDAP://dc.example/CN=other,DC=example,DC=com"; break;
            case "username": entry.Username = "EXAMPLE\\other"; break;
            default: entry.Password = "changed-test-only"; break;
        }
        Assert.ThrowsAny<InvalidOperationException>(() => session.ApplyTo(source));
        Assert.Equal(before.GetRawBinaryForm(), source.CaptureSnapshot().GetRawBinaryForm());
        Assert.Equal(before.PendingWriteSections, source.CaptureSnapshot().PendingWriteSections);
        Assert.NotNull(session.Object); Assert.NotNull(session.Snapshot); // Failure did not consume/dispose it.
        if (change != "dispose")
        {
            // Credential changes retain the stale managed wrapper, and every binding
            // reset restores the default mask (without SACL). Explicitly reacquire a
            // complete entry-owned descriptor through the public lifecycle.
            entry.Close();
            entry.Options.SecurityMasks = (D.SecurityMasks)15;
            var rebound = entry.ObjectSecurity;
            Assert.NotSame(source, rebound);
            Assert.Throws<InvalidOperationException>(() => session.ApplyTo(source)); // Old attachment stays stale.
            Assert.Throws<InvalidOperationException>(() => session.ApplyTo(rebound));
            using var fresh = rebound.ExportForEdit();
            Assert.Equal(D.SecurityMasks.None, fresh.ApplyTo(rebound));
        }
    }
}
