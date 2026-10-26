using System.Runtime.InteropServices;

namespace AdForLinux.DirectoryServices.Ldap;

internal static partial class NativeLdapBindingBackend
{
    internal static void EnsureAbi()
    {
        try { ValidateAbi(NativeAbiVersion()); }
        catch (EntryPointNotFoundException error)
        { throw new PlatformNotSupportedException("The native LDAP library does not expose the required controls ABI.", error); }
    }
    internal static void ValidateAbi(uint version)
    {
        if (version != 2) throw new PlatformNotSupportedException("The native LDAP library has an incompatible ABI; no operation was dispatched.");
    }
    [DllImport(Library, EntryPoint = "adfl_native_abi_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint NativeAbiVersion();

    [StructLayout(LayoutKind.Sequential)] private struct NativeControl
    {
        public IntPtr Oid;
        public uint Critical;
        public NativeBytes Value;
        public uint HasValue;
    }
    private sealed class ControlPointers : IDisposable
    {
        private readonly List<IntPtr> allocations = [];
        internal IntPtr Pointer { get; }
        internal UIntPtr Count { get; }
        private IntPtr Allocate(int bytes)
        { var value = Marshal.AllocHGlobal(Math.Max(1, bytes)); allocations.Add(value); return value; }
        internal ControlPointers(LdapTransportControl[] controls)
        {
            try
            {
                Count = (UIntPtr)controls.Length;
                if (controls.Length == 0) return;
                var size = Marshal.SizeOf<NativeControl>();
                Pointer = Allocate(checked(size * controls.Length));
                for (var i = 0; i < controls.Length; i++)
                {
                    var control = LdapControlCodec.Snapshot(controls[i]);
                    if (string.IsNullOrEmpty(control.Oid) || control.Oid.Contains('\0')) throw new ArgumentException("Invalid LDAP control OID.");
                    var oidBytes = System.Text.Encoding.UTF8.GetBytes(control.Oid + "\0");
                    var oid = Allocate(oidBytes.Length); Marshal.Copy(oidBytes, 0, oid, oidBytes.Length);
                    var value = control.HasValue ? Allocate(control.Value.Length) : IntPtr.Zero;
                    if (control.Value.Length != 0) Marshal.Copy(control.Value, 0, value, control.Value.Length);
                    Marshal.StructureToPtr(new NativeControl { Oid = oid, Critical = control.Critical ? 1u : 0u,
                        Value = new NativeBytes { Data = value, Length = (UIntPtr)control.Value.Length },
                        HasValue = control.HasValue ? 1u : 0u }, IntPtr.Add(Pointer, i * size), false);
                }
            }
            catch { Dispose(); throw; }
        }
        public void Dispose() { foreach (var value in allocations) Marshal.FreeHGlobal(value); allocations.Clear(); }
    }
}
