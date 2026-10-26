using System.Runtime.InteropServices;
using AdForLinux.DirectoryServices.Ldap;

// Only this isolated demo supplies recording operations. The system binding API
// retains its permanent live-access guard and the native pre-auth gate remains0.
sealed class RecordingBindingApi : NativeLdapBindingBackend.ISourceBindingApi
{
    private readonly ResolveCall resolve;
    private readonly ResolveFromCall resolveFrom;
    private readonly BindCall bind;
    private readonly CloseCall closeAuthority, closeSession;
    internal Action? AfterBind;
    internal RecordingBindingApi(IntPtr library)
    {
        resolveFrom = Marshal.GetDelegateForFunctionPointer<ResolveFromCall>(NativeLibrary.GetExport(library, "adfl_test_resolve_from"));
        resolve = Marshal.GetDelegateForFunctionPointer<ResolveCall>(NativeLibrary.GetExport(library, "adfl_test_resolve"));
        bind = Marshal.GetDelegateForFunctionPointer<BindCall>(NativeLibrary.GetExport(library, "adfl_authority_bind"));
        closeAuthority = Marshal.GetDelegateForFunctionPointer<CloseCall>(NativeLibrary.GetExport(library, "adfl_authority_close"));
        closeSession = Marshal.GetDelegateForFunctionPointer<CloseCall>(NativeLibrary.GetExport(library, "adfl_session_close"));
    }
    public int Resolve(ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority)
        { NativeLdapBindingBackend.EnsureAbi(); return resolve(ref profile, cancelled, state, out authority); }
    public int ResolveFrom(ref NativeLdapBindingBackend.Profile profile, ref NativeLdapBindingBackend.CredentialSource source,
        NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority)
    { NativeLdapBindingBackend.EnsureAbi(); return resolveFrom(ref profile, ref source, cancelled, state, out authority); }
    public int Bind(NativeLdapBindingBackend.AuthorityHandle authority, ref NativeLdapBindingBackend.Profile profile,
        NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session)
    {
        NativeLdapBindingBackend.EnsureAbi();
        var result = bind(authority, ref profile, cancelled, state, out session);
        try { if (result == 0) AfterBind?.Invoke(); return result; }
        catch { if (session != IntPtr.Zero) closeSession(ref session); throw; }
    }
    public void CloseAuthority(ref IntPtr authority) => closeAuthority(ref authority);
    public void CloseSession(ref IntPtr session) => closeSession(ref session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ResolveCall(ref NativeLdapBindingBackend.Profile profile,
        NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ResolveFromCall(ref NativeLdapBindingBackend.Profile profile,
        ref NativeLdapBindingBackend.CredentialSource source, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr authority);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindCall(NativeLdapBindingBackend.AuthorityHandle authority,
        ref NativeLdapBindingBackend.Profile profile, NativeLdapBindingBackend.Cancelled cancelled, IntPtr state, out IntPtr session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void CloseCall(ref IntPtr value);
}
