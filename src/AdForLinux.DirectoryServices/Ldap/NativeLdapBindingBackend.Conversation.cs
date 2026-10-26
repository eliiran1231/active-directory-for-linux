using System.DirectoryServices.Protocols;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AdForLinux.DirectoryServices.Ldap;

internal static partial class NativeLdapBindingBackend
{
    internal sealed partial class BoundSession
    {
        // ValueTask does not imply a background thread. These bounded native polls
        // run synchronously; cancellation is checked by C while awaiting a message.
        public ValueTask<ILdapSearchCursor> OpenSearchAsync(LdapSearchCommand command, int pageSize, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(command);
            var budget = new PreparationBudget(command.Timeout);
            command = LdapRequestDispatcher.Prepare(this, command);
            if (pageSize < 0) throw new ArgumentOutOfRangeException(nameof(pageSize));
            using var attributes = new AttributePointers(command.Attributes);
            var request = new SearchProfile
            {
                BaseDn = command.BaseDn, Filter = command.Filter, Attributes = attributes.Pointer,
                Scope = (int)command.Scope, TimeoutMilliseconds = budget.RemainingMilliseconds(),
                SizeLimit = checked((uint)command.SizeLimit), TypesOnly = command.TypesOnly ? 1u : 0u
            };
            Cancelled check = _ => cancellationToken.IsCancellationRequested || budget.Expired ? 1 : 0;
            var status = NativeCursorOpen(ownedHandle, ref request, checked((uint)pageSize), check, IntPtr.Zero, out var pointer);
            var cursor = new CursorHandle(pointer);
            if (status != 0 || cursor.IsInvalid)
            {
                cursor.Dispose();
                if (status != 0) ThrowWithBudget(status, cancellationToken, budget);
                throw new InvalidOperationException("Native cursor open returned no cursor.");
            }
            return ValueTask.FromResult<ILdapSearchCursor>(new NativeCursor(cursor));
        }

        public ValueTask<LdapResultEnvelope> ModifyAsync(LdapModifyCommand command, LdapSubmission submission, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(command);
            var budget = new PreparationBudget(command.Timeout);
            if (command.Controls.Length != 0) throw new PlatformNotSupportedException("Native modify controls are not implemented.");
            if (command.DistinguishedName.Contains('\0')) throw new ArgumentException("Native LDAP strings cannot contain NUL.");
            using var changes = new ModificationPointers(command.Changes);
            var request = new ModifyProfile
            {
                Dn = command.DistinguishedName, Changes = changes.Pointer,
                ChangeCount = (UIntPtr)command.Changes.Length, TimeoutMilliseconds = budget.RemainingMilliseconds()
            };
            var builder = new NativeSearchResultBuilder();
            Exception? callbackError = null;
            Submitted beforeSend = _ =>
            {
                try { cancellationToken.ThrowIfCancellationRequested(); budget.Check(); submission.BeforeSend(); return 0; }
                catch (Exception error) { callbackError = error; return 1; }
            };
            // Once a complete response arrives, preserve its known outcome even
            // if cancellation races its conversion. Never reuse Search's emitter.
            ResultEvent emit = (_, kind, name, bytes, length, number) =>
            {
                try { builder.Accept(kind, Marshal.PtrToStringUTF8(name), Copy(bytes, length), number); return 0; }
                catch (Exception error) { callbackError = error; return 1; }
            };
            Cancelled check = _ => cancellationToken.IsCancellationRequested || budget.Expired ? 1 : 0;
            var status = NativeModify(ownedHandle, ref request, check, IntPtr.Zero,
                beforeSend, IntPtr.Zero, emit, IntPtr.Zero, out var disposition);
            if (callbackError is not null) ExceptionDispatchInfo.Capture(callbackError).Throw();
            if (status != 0) ThrowWithBudget(status, cancellationToken, budget);
            if (disposition != 2 || !submission.Started)
                throw new InvalidOperationException("Native modify returned no definitive submission outcome.");
            var result = builder.Complete();
            if (result.Entries.Length != 0 || result.References.Length != 0)
                throw new InvalidOperationException("Native modify returned a search payload.");
            return ValueTask.FromResult(new LdapResultEnvelope(result.Code, result.MatchedDn, result.Diagnostic, result.Referrals, result.Controls));
        }
    }

    private sealed class NativeCursor(CursorHandle handle) : ILdapSearchCursor
    {
        private readonly object gate = new();
        public ValueTask<LdapSearchEvent> ReadAsync(TimeSpan remaining, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var budget = new PreparationBudget(remaining);
            lock (gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var builder = new NativeSearchResultBuilder();
                Exception? callbackError = null;
                ResultEvent emit = (_, kind, name, bytes, length, number) =>
                {
                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        builder.Accept(kind, Marshal.PtrToStringUTF8(name), BoundSession.Copy(bytes, length), number);
                        return 0;
                    }
                    catch (Exception error) { callbackError = error; return 1; }
                };
                Cancelled check = _ => cancellationToken.IsCancellationRequested || budget.Expired ? 1 : 0;
                var status = NativeCursorRead(handle, budget.RemainingMilliseconds(), check, IntPtr.Zero, emit, IntPtr.Zero, out var kind, out var hasMore);
                if (callbackError is not null) ExceptionDispatchInfo.Capture(callbackError).Throw();
                if (status != 0) ThrowWithBudget(status, cancellationToken, budget);
                if (hasMore is not (0 or 1)) throw new InvalidOperationException("Native cursor returned an invalid continuation flag.");
                return ValueTask.FromResult(builder.CompleteEvent(kind, hasMore != 0));
            }
        }
        public ValueTask NextPageAsync(TimeSpan remaining, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var budget = new PreparationBudget(remaining);
            lock (gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Cancelled check = _ => cancellationToken.IsCancellationRequested || budget.Expired ? 1 : 0;
                var status = NativeCursorNext(handle, budget.RemainingMilliseconds(), check, IntPtr.Zero);
                if (status != 0) ThrowWithBudget(status, cancellationToken, budget);
                return ValueTask.CompletedTask;
            }
        }
        public ValueTask DisposeAsync() { lock (gate) { handle.Dispose(); return ValueTask.CompletedTask; } }
    }
    private sealed class CursorHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal CursorHandle(IntPtr value) : base(true) => SetHandle(value);
        protected override bool ReleaseHandle() { NativeCursorClose(ref handle); return true; }
    }

    private sealed class PreparationBudget
    {
        private readonly TimeSpan timeout;
        private readonly long started;
        internal PreparationBudget(TimeSpan timeout)
        {
            Milliseconds(timeout); // validate before any unmanaged allocation
            this.timeout = timeout;
            started = System.Diagnostics.Stopwatch.GetTimestamp();
        }
        private TimeSpan Remaining => timeout - System.Diagnostics.Stopwatch.GetElapsedTime(started);
        internal bool Expired => Remaining <= TimeSpan.Zero;
        internal void Check()
        {
            if (Expired) throw new TimeoutException("Native operation budget expired before submission.");
        }
        internal uint RemainingMilliseconds()
        {
            var remaining = Remaining;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("Native operation budget expired during preparation.");
            return Milliseconds(remaining);
        }
    }
    private static void ThrowWithBudget(int status, CancellationToken cancellationToken, PreparationBudget budget)
    {
        if (status == 3 && !cancellationToken.IsCancellationRequested && budget.Expired)
            throw new TimeoutException("Native operation budget expired without replay.");
        Throw(status, cancellationToken);
    }

    private static uint Milliseconds(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromHours(1))
            throw new PlatformNotSupportedException("Native operation budgets must be above zero and at most one hour.");
        return checked((uint)Math.Ceiling(timeout.TotalMilliseconds));
    }
    private sealed class ModificationPointers : IDisposable
    {
        private readonly List<IntPtr> allocations = [];
        internal IntPtr Pointer { get; private set; }
        private IntPtr Allocate(int length)
        {
            var value = Marshal.AllocHGlobal(Math.Max(1, length)); allocations.Add(value); return value;
        }
        private IntPtr Utf8(string value)
        {
            if (value.Contains('\0')) throw new ArgumentException("Native LDAP strings cannot contain NUL.");
            var bytes = System.Text.Encoding.UTF8.GetBytes(value + "\0");
            var pointer = Allocate(bytes.Length); Marshal.Copy(bytes, 0, pointer, bytes.Length); return pointer;
        }
        internal ModificationPointers(LdapAttributeChange[] changes)
        {
            try
            {
                if (changes.Length == 0) throw new ArgumentException("A modify command must include a change.");
                var changeSize = Marshal.SizeOf<NativeModification>();
                var valueSize = Marshal.SizeOf<NativeBytes>();
                Pointer = Allocate(checked(changes.Length * changeSize));
                for (var i = 0; i < changes.Length; i++)
                {
                    var change = changes[i];
                    var operation = change.Operation switch
                    {
                        DirectoryAttributeOperation.Add => 0, DirectoryAttributeOperation.Delete => 1,
                        DirectoryAttributeOperation.Replace => 2, _ => throw new ArgumentException("Unknown modification operation.")
                    };
                    var native = new NativeModification { Operation = operation, Attribute = Utf8(change.Name), ValueCount = (UIntPtr)change.Values.Length };
                    if (change.Values.Length != 0)
                    {
                        native.Values = Allocate(checked(change.Values.Length * valueSize));
                        for (var j = 0; j < change.Values.Length; j++)
                        {
                            var bytes = change.Values[j];
                            var value = new NativeBytes { Data = Allocate(bytes.Length), Length = (UIntPtr)bytes.Length };
                            if (bytes.Length != 0) Marshal.Copy(bytes, 0, value.Data, bytes.Length);
                            Marshal.StructureToPtr(value, native.Values + j * valueSize, false);
                        }
                    }
                    Marshal.StructureToPtr(native, Pointer + i * changeSize, false);
                }
            }
            catch { Dispose(); throw; }
        }
        public void Dispose()
        {
            for (var i = allocations.Count - 1; i >= 0; i--) Marshal.FreeHGlobal(allocations[i]);
            allocations.Clear(); Pointer = IntPtr.Zero;
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct NativeBytes { public IntPtr Data; public UIntPtr Length; }
    [StructLayout(LayoutKind.Sequential)] private struct NativeModification { public int Operation; public IntPtr Attribute, Values; public UIntPtr ValueCount; }
    [StructLayout(LayoutKind.Sequential)] private struct ModifyProfile
    {
        [MarshalAs(UnmanagedType.LPUTF8Str)] public string Dn;
        public IntPtr Changes;
        public UIntPtr ChangeCount;
        public uint TimeoutMilliseconds;
    }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Submitted(IntPtr state);
    [DllImport(Library, EntryPoint = "adfl_cursor_open", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeCursorOpen(SessionHandle session, ref SearchProfile request, uint pageSize, Cancelled cancelled, IntPtr state, out IntPtr cursor);
    [DllImport(Library, EntryPoint = "adfl_cursor_read", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeCursorRead(CursorHandle cursor, uint remaining, Cancelled cancelled, IntPtr cancelState, ResultEvent emit, IntPtr emitState, out int kind, out int hasMore);
    [DllImport(Library, EntryPoint = "adfl_cursor_next_page", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeCursorNext(CursorHandle cursor, uint remaining, Cancelled cancelled, IntPtr state);
    [DllImport(Library, EntryPoint = "adfl_cursor_close", CallingConvention = CallingConvention.Cdecl)]
    private static extern void NativeCursorClose(ref IntPtr cursor);
    [DllImport(Library, EntryPoint = "adfl_session_modify", CallingConvention = CallingConvention.Cdecl)]
    private static extern int NativeModify(SessionHandle session, ref ModifyProfile request, Cancelled cancelled, IntPtr cancelState,
        Submitted submitted, IntPtr submitState, ResultEvent emit, IntPtr emitState, out int disposition);
}
