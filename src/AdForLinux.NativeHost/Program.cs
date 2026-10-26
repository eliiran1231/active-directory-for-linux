using System.Net.Sockets;
using Microsoft.Win32.SafeHandles;
using AdForLinux.DirectoryServices.Ldap;

// No test mode, credential arguments, shell, listener, or persistent broker.
// Establish process ownership before any possible native backend initialization.
if (!OperatingSystem.IsLinux() || args.Length != 1 || !Path.IsPathFullyQualified(args[0])) return 2;
try
{
    using var supervisor = new WorkerNative(args[0]);
    if (supervisor.SendIdentity(3) != 0) return 3;
    using var socket = new Socket(new SafeSocketHandle((IntPtr)3, ownsHandle: true));
    using var channel = new NetworkStream(socket, ownsSocket: false);
    // Audited production deployment admission is not yet available. The production
    // factory refuses before native credential resolution; it has no enable flag.
    await LdapWorkerHost.RunAsync(channel, CancellationToken.None);
    return 0;
}
catch { return 4; } // stderr is not a credential/exception logging channel
