using System.Runtime.Versioning;
using A = AdForLinux.Security.AccessControl;
using M = System.DirectoryServices;

namespace AdForLinux.DirectoryServices.MicrosoftInterop;

/// <summary>A detached Microsoft edit with one successful, explicit local application.</summary>
/// <remarks>Not thread-safe. Synchronize editing, application and disposal. Never sends LDAP.</remarks>
[SupportedOSPlatform("windows")]
public sealed class MicrosoftSecurityEdit : IDisposable
{
    private M.ActiveDirectorySecurity? value;
    private SecurityDescriptorSnapshot? snapshot;
    private A.InteropBaseline? provenance;
    private bool consumed;

    internal MicrosoftSecurityEdit(M.ActiveDirectorySecurity value, A.InteropBaseline provenance)
    {
        this.value = value;
        this.provenance = provenance;
        snapshot = new(provenance.Snapshot);
    }

    public M.ActiveDirectorySecurity Object { get { ThrowIfDisposed(); return value!; } }
    public SecurityDescriptorSnapshot Snapshot { get { ThrowIfDisposed(); return snapshot!; } }

    /// <summary>Atomically applies to the originating wrapper. A success, including no-op, consumes the session.</summary>
    /// <remarks>A failed apply may be retried only while the source provenance remains current.</remarks>
    public SecurityMasks ApplyTo(ActiveDirectorySecurity source)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(source);
        if (consumed) throw new InvalidOperationException("The edit session has already been applied.");
        MicrosoftConversions.RequireWindows();
        var changed = source.ReconcileInterop(provenance!, value!.GetSecurityDescriptorBinaryForm());
        consumed = true;
        return changed;
    }

    /// <summary>Releases managed references only; never saves, applies, or closes a directory connection.</summary>
    public void Dispose() { value = null; snapshot = null; provenance = null; }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(value is null, this);
}
