using System.DirectoryServices.Protocols;
using AdForLinux.DirectoryServices.Ldap;

namespace AdForLinux.DirectoryServices;

public partial class DirectoryEntry
{
    internal sealed partial class ConnectionLease
    {
        internal LdapWriteOutcome SendWrite(DirectoryRequest request)
        {
            var outcome = ExecuteTransport(transport => LdapMutationDispatcher.Send(
                transport, request, () => Connection.SendRequestTracked(request), Invalidate));
            if (outcome.Disposition == LdapWriteDisposition.Indeterminate ||
                outcome.Result?.Code is ResultCode.Unavailable or ResultCode.ProtocolError)
                Invalidate();
            return outcome;
        }

        internal void SendWriteCompatible(DirectoryRequest request)
        {
            // Preserve the exact established Protocols path, including exception
            // translation, for immediate operations that do not retain a ledger.
            if (ExecuteTransport(transport => transport is ProtocolsLdapTransport))
            { Connection.SendRequestCompatible(request); return; }
            LdapMutationDispatcher.ThrowIfFailed(SendWrite(request));
        }
    }
}
