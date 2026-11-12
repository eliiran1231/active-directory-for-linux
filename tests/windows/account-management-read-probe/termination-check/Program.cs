using System.Reflection;

if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ADFL_OFFLINE_TESTS")) || args.Length != 2) return 2;
if (args[1] == "exit-handler") AppDomain.CurrentDomain.ProcessExit += (_, _) => Thread.Sleep(Timeout.Infinite);
else if (args[1] == "stderr") Console.SetError(new BlockedWriter());
else return 2;
try
{
    // Load metadata only; never invoke the executable's admission/read path.
    var type = Assembly.LoadFrom(args[0]).GetType("AdForLinux.ReadProbe.ProbeProgram", throwOnError: true)!;
    type.GetMethod("Abort", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, ["synthetic-termination-check"]);
    return 2; // The emergency method must never return.
}
catch { return 2; }

sealed class BlockedWriter : TextWriter
{
    public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;
    public override void WriteLine(string? value) => Thread.Sleep(Timeout.Infinite);
}
