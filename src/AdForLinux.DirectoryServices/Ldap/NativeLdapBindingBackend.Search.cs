using System.DirectoryServices.Protocols;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace AdForLinux.DirectoryServices.Ldap;

internal static partial class NativeLdapBindingBackend
{
    internal sealed partial class BoundSession(SessionHandle handle, TimeSpan timeout) : ILdapConversationTransport, IDisposable
    {
        private readonly SessionHandle ownedHandle = handle;
        public LdapTransportCapabilities Capabilities => LdapTransportCapabilities.Search |
            LdapTransportCapabilities.StreamingSearch | LdapTransportCapabilities.PagedSearch | LdapTransportCapabilities.Modify |
            LdapTransportCapabilities.Add | LdapTransportCapabilities.Delete | LdapTransportCapabilities.ModifyDn | LdapTransportCapabilities.SearchControls | LdapTransportCapabilities.MutationControls;
        public TimeSpan Timeout => timeout;
        public string? ConnectedHost => null; // a requested alias is not an observed DC
        public LdapSearchResult Search(LdapSearchCommand command, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (command.Timeout <= TimeSpan.Zero || command.Timeout > TimeSpan.FromHours(1))
                throw new PlatformNotSupportedException("The native transport supports request deadlines above zero and at most one hour.");
            var budget = new PreparationBudget(command.Timeout);
            EnsureAbi();
            command = LdapRequestDispatcher.Prepare(this, command);
            if (command.BaseDn.Contains('\0') || command.Filter.Contains('\0') || command.Attributes.Any(a => a.Contains('\0')))
                throw new ArgumentException("Native LDAP request strings cannot contain NUL.");
            using var attributes = new AttributePointers(command.Attributes);
            using var controls = new ControlPointers(command.Controls ?? []);
            var request = new SearchProfile
            {
                BaseDn = command.BaseDn, Filter = command.Filter, Attributes = attributes.Pointer,
                Scope = (int)command.Scope, TimeoutMilliseconds = budget.RemainingMilliseconds(),
                Controls = controls.Pointer, ControlCount = controls.Count,
                SizeLimit = checked((uint)command.SizeLimit), TypesOnly = command.TypesOnly ? 1u : 0u,
            };
            var result = new NativeSearchResultBuilder();
            Exception? conversionError = null;
            ResultEvent emit = (_, kind, name, bytes, length, number) =>
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested(); budget.Check();
                    result.Accept(kind, Marshal.PtrToStringUTF8(name), Copy(bytes, length), number);
                    return 0;
                }
                catch (Exception error) { conversionError = error; return 1; }
            };
            Cancelled check = _ => cancellationToken.IsCancellationRequested || budget.Expired ? 1 : 0;
            var status = NativeSearch(ownedHandle, ref request, check, IntPtr.Zero, emit, IntPtr.Zero);
            if (conversionError is not null) ExceptionDispatchInfo.Capture(conversionError).Throw();
            if (status != 0) ThrowWithBudget(status, cancellationToken, budget);
            return result.Complete();
        }
        internal static byte[] Copy(IntPtr source, UIntPtr length)
        {
            var count = checked((int)length.ToUInt64());
            if (count != 0 && source == IntPtr.Zero) throw new InvalidOperationException("Native result has a null value buffer.");
            var bytes = new byte[count];
            if (count != 0) Marshal.Copy(source, bytes, 0, count);
            return bytes;
        }
        public void Dispose() => ownedHandle.Dispose();
    }

    private sealed class AttributePointers : IDisposable
    {
        private readonly List<IntPtr> values = [];
        internal IntPtr Pointer { get; private set; }
        internal AttributePointers(string[] attributes)
        {
            try
            {
                Pointer = Marshal.AllocHGlobal(checked((attributes.Length + 1) * IntPtr.Size));
                for (var i = 0; i < attributes.Length; i++)
                {
                    var value = Marshal.StringToCoTaskMemUTF8(attributes[i]); values.Add(value);
                    Marshal.WriteIntPtr(Pointer, i * IntPtr.Size, value);
                }
                Marshal.WriteIntPtr(Pointer, attributes.Length * IntPtr.Size, IntPtr.Zero);
            }
            catch { Dispose(); throw; }
        }
        public void Dispose()
        {
            foreach (var value in values) Marshal.FreeCoTaskMem(value);
            values.Clear();
            if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; }
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SearchProfile
    {
        [MarshalAs(UnmanagedType.LPUTF8Str)] public string BaseDn;
        [MarshalAs(UnmanagedType.LPUTF8Str)] public string Filter;
        public IntPtr Attributes;
        public int Scope;
        public uint TimeoutMilliseconds, SizeLimit, TypesOnly;
        public IntPtr Controls; public UIntPtr ControlCount;
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ResultEvent(IntPtr state, int kind, IntPtr name, IntPtr bytes, UIntPtr length, int number);
    [DllImport(Library, EntryPoint = "adfl_session_search", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeSearch(SessionHandle session, ref SearchProfile request,
        Cancelled cancelled, IntPtr cancelState, ResultEvent emit, IntPtr emitState);
}

// This parser is also exercised without native code. The C driver exercises the
// actual native emit/free lifecycle separately. Neither test acquires credentials.
internal sealed class NativeSearchResultBuilder
{
    private readonly List<LdapTransportEntry> entries = [];
    private readonly List<LdapTransportReference> references = [];
    private readonly List<string> referrals = [];
    private readonly List<LdapTransportControl> controls = [];
    private string? dn, attribute, matched, diagnostic;
    private Dictionary<string, byte[][]>? attributes;
    private List<LdapTransportControl>? entryControls, referenceControls;
    private List<byte[]>? values;
    private List<string>? urls;
    private ResultCode? code;
    internal void Accept(int kind, string? name, byte[] bytes, int number)
    {
        static string Required(string? value) => value ?? throw new InvalidOperationException("Native result omitted a required name.");
        void Require(bool condition) { if (!condition) throw new InvalidOperationException("Native result events are out of sequence."); }
        LdapTransportControl control()
        {
            Require((number & ~3) == 0 && ((number & 2) != 0 || bytes.Length == 0));
            return new(Required(name), bytes, (number & 1) != 0, (number & 2) != 0);
        }
        if (code is not null && kind <= 10)
            throw new InvalidOperationException("Native payload appeared after the final result code.");
        switch (kind)
        {
            case 1: Require(attributes is null && urls is null); dn = Required(name); attributes = new(StringComparer.OrdinalIgnoreCase); entryControls = []; break;
            case 2: Require(attributes is not null && values is null); attribute = Required(name); values = []; break;
            case 3: Require(values is not null); values!.Add(bytes); break;
            case 4: Require(attributes is not null && values is not null); attributes!.Add(attribute!, values!.ToArray()); values = null; attribute = null; break;
            case 5: Require(entryControls is not null && values is null); entryControls!.Add(control()); break;
            case 6: Require(attributes is not null && values is null); entries.Add(new(dn!, attributes!, entryControls!.ToArray())); attributes = null; entryControls = null; dn = null; break;
            case 7: Require(attributes is null && urls is null); urls = []; referenceControls = []; break;
            case 8: Require(urls is not null); urls!.Add(Required(name)); break;
            case 9: Require(referenceControls is not null); referenceControls!.Add(control()); break;
            case 10: Require(urls is not null); references.Add(new(urls!.ToArray(), referenceControls!.ToArray())); urls = null; referenceControls = null; break;
            case 11: Require(code is null && attributes is null && urls is null); code = (ResultCode)number; break;
            case 12: Require(code is not null); matched = name; break;
            case 13: Require(code is not null); diagnostic = name; break;
            case 14: Require(code is not null); referrals.Add(Required(name)); break;
            case 15: Require(code is not null); controls.Add(control()); break;
            default: throw new InvalidOperationException("Unknown native result event.");
        }
    }
    internal LdapSearchEvent CompleteEvent(int messageKind, bool hasMore)
    {
        if (attributes is not null || values is not null || urls is not null)
            throw new InvalidOperationException("Native streaming message is incomplete.");
        return messageKind switch
        {
            1 when code is null && entries.Count == 1 && references.Count == 0 && !hasMore => new LdapSearchEvent.Entry(entries[0]),
            2 when code is null && entries.Count == 0 && references.Count == 1 && !hasMore => new LdapSearchEvent.Reference(references[0]),
            3 when entries.Count == 0 && references.Count == 0 => CompletePage(hasMore),
            _ => throw new InvalidOperationException("Native streaming message has an inconsistent kind or payload.")
        };
    }
    private LdapSearchEvent.PageEnd CompletePage(bool hasMore)
    {
        var result = Complete();
        return new(new(result.Code, result.MatchedDn, result.Diagnostic, result.Referrals, result.Controls), hasMore);
    }

    internal LdapSearchResult Complete()
    {
        if (code is null || attributes is not null || values is not null || urls is not null)
            throw new InvalidOperationException("Native result is incomplete.");
        return new(code.Value, matched, diagnostic, entries.ToArray(), references.ToArray(), referrals.ToArray(), controls.ToArray());
    }
}
