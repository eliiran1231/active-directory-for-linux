using System.Runtime.Versioning;
using A = AdForLinux.Security.AccessControl;
using M = System.DirectoryServices;

namespace AdForLinux.DirectoryServices.MicrosoftInterop;

/// <summary>Immutable descriptor data and coverage, without identity or persistence authority.</summary>
[SupportedOSPlatform("windows")]
public sealed class SecurityDescriptorSnapshot
{
    private readonly A.InteropSnapshot snapshot;
    internal SecurityDescriptorSnapshot(A.InteropSnapshot snapshot) => this.snapshot = snapshot;

    /// <summary>Explicitly known coverage, never promoted from stored bytes or subsequent edits.</summary>
    public SecurityMasks RetrievedSections => snapshot.Retrieved;
    /// <summary>All accepted local pending edits, independently of coverage. This is not write authorization.</summary>
    public SecurityMasks PendingWriteSections => snapshot.Pending;
    public byte[] GetRawBinaryForm() => snapshot.Raw;
    public byte[] GetOriginalBinaryForm() => snapshot.Original;
    public byte[] GetObservableBinaryForm() => snapshot.Observable;

    /// <summary>Returns a new independent Microsoft object; refuses incomplete or lossy conversion.</summary>
    public M.ActiveDirectorySecurity ToMicrosoftObject()
    {
        MicrosoftConversions.RequireWindows();
        return A.ObjectSecurity.ExportInteropSnapshot(snapshot, MicrosoftConversions.ConstructSecurity,
            value => value.GetSecurityDescriptorBinaryForm()).Value;
    }
}
