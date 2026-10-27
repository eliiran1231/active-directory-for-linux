using System.Net.Sockets;
using Microsoft.Win32.SafeHandles;
using AdForLinux.DirectoryServices.Ldap;

// No test mode, credential arguments, shell, listener, or persistent broker.
// Establish process ownership before any possible native backend initialization.
if (!OperatingSystem.IsLinux() || args.Length is not (1 or 2) || !Path.IsPathFullyQualified(args[0])) return 2;
try
{
    using var deployment = args.Length == 2 ? LdapWorkerDeployment.Validate(args[1]) : null;
    if (deployment is not null)
    {
        OfflineTestGuard.RequireLiveAccess();
        if (Environment.GetEnvironmentVariable("LDAPNOINIT") != "1") return 2;
        deployment.RequireRestrictedComposition();
        var launch = deployment.CreateLaunch();
        if (launch.SupervisorLibrary != args[0] || launch.Arguments[0] != typeof(Program).Assembly.Location)
            return 2;
    }
    using var supervisor = new WorkerNative(args[0]);
    if (supervisor.SendIdentity(3) != 0) return 3;
    using var socket = new Socket(new SafeSocketHandle((IntPtr)3, ownsHandle: true));
    using var channel = new NetworkStream(socket, ownsSocket: false);
    if (deployment is null)
        await LdapWorkerHost.RunAsync(channel, CancellationToken.None); // legacy invocation remains refused
    else
        await LdapWorkerHost.RunAsync(channel, profile => LdapRestrictedWorkerHost.Create(deployment, profile));
    return 0;
}
catch { return 4; } // stderr is not a credential/exception logging channel
