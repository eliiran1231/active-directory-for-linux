using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

// Compile/pure tests never call Windows job APIs. Worker starts behind an IPC
// barrier; only the supervisor releases it after job assignment and durable record.
public sealed class AdflProcessJob : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimit
    {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinimumWorking, MaximumWorking;
        public uint ActiveLimit;
        public UIntPtr Affinity;
        public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters
    { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimit
    { public BasicLimit Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob; }
    [StructLayout(LayoutKind.Sequential)] private struct Accounting
    { public long UserTime, KernelTime, PeriodUser, PeriodKernel; public uint Faults, Total, Active, Terminated; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle OpenJobObjectW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref ExtendedLimit limits, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int kind, out Accounting data, uint length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessInJob(IntPtr process, SafeFileHandle job, [MarshalAs(UnmanagedType.Bool)] out bool member);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    private readonly SafeFileHandle handle;
    public AdflProcessJob(string name)
    {
        ValidateName(name);
        handle = CreateJobObjectW(IntPtr.Zero, name);
        int error = Marshal.GetLastWin32Error();
        if (handle.IsInvalid || error == 183) { handle.Dispose(); throw new Win32Exception(error); }
        var limits = new ExtendedLimit { Basic = new BasicLimit { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE, no breakaway.
        if (!SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimit>()))
        { error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
    }
    private static void ValidateName(string name)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(name, @"^Local\\adfl-auth-[0-9a-f]{32}$"))
            throw new ArgumentException("Invalid owned job name.");
    }
    public void Assign(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.Handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    private static void Stop(SafeFileHandle job)
    {
        if (!TerminateJobObject(job, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var timer = Stopwatch.StartNew();
        while (true)
        {
            if (!QueryInformationJobObject(job, 1, out Accounting value, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (value.Active == 0) return;
            if (timer.ElapsedMilliseconds >= 10000) throw new TimeoutException("Job descendants not confirmed stopped.");
            System.Threading.Thread.Sleep(25);
        }
    }
    public void StopAndVerify() { Stop(handle); }
    public static void StopRecorded(string name)
    {
        ValidateName(name);
        using (SafeFileHandle job = OpenJobObjectW(0x0008 | 0x0004, false, name)) // TERMINATE | QUERY
        {
            if (job.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 2) return; // Named job destroyed: last handle closed and associated processes gone.
                throw new Win32Exception(error);
            }
            Stop(job);
        }
    }
    public static void VerifyCurrentMembership(string name)
    {
        ValidateName(name);
        using (SafeFileHandle job = OpenJobObjectW(0x0004, false, name))
        {
            if (job.IsInvalid || !IsProcessInJob(GetCurrentProcess(), job, out bool member) || !member)
                throw new InvalidOperationException("Worker is not in the owned containment job.");
        } // Child never retains a supervisor-job handle across the mutation barrier.
    }
    public void Dispose() { handle.Dispose(); }
    public static int ExtendedSize => Marshal.SizeOf<ExtendedLimit>();
    public static int AccountingSize => Marshal.SizeOf<Accounting>();
}

public static class AdflPrivateFrame
{
    public const int Maximum = 8192;
    public static async Task WriteAsync(Stream stream, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            if (bytes.Length == 0 || bytes.Length > Maximum) throw new InvalidDataException("Invalid frame length.");
            await stream.WriteAsync(BitConverter.GetBytes(bytes.Length));
            await stream.WriteAsync(bytes);
            await stream.FlushAsync();
        }
        finally { Array.Clear(bytes, 0, bytes.Length); }
    }
    public static async Task<string> ReadAsync(Stream stream)
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header);
        int size = BitConverter.ToInt32(header, 0);
        if (size <= 0 || size > Maximum) throw new InvalidDataException("Invalid frame length.");
        byte[] bytes = new byte[size];
        try { await stream.ReadExactlyAsync(bytes); return new UTF8Encoding(false, true).GetString(bytes); }
        finally { Array.Clear(bytes, 0, bytes.Length); }
    }
    public static string Read(Stream stream) => ReadAsync(stream).WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
    public static void Write(Stream stream, string value) => WriteAsync(stream, value).WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
}

public sealed class AdflBoundedCapture
{
    private readonly Task<string> output;
    private readonly Task<string> error;
    private static async Task<string> Read(StreamReader reader, Process process)
    {
        var result = new StringBuilder();
        char[] block = new char[1024];
        while (true)
        {
            int count = await reader.ReadAsync(block, 0, block.Length);
            if (count == 0) return result.ToString();
            if (result.Length + count > 65536)
            {
                try { process.Kill(true); } catch { }
                throw new InvalidDataException("Worker output exceeded limit.");
            }
            result.Append(block, 0, count);
        }
    }
    public AdflBoundedCapture(Process process)
    { output = Read(process.StandardOutput, process); error = Read(process.StandardError, process); }
    public string Result()
    {
        string text = output.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
        string errors = error.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
        if (errors.Length != 0) throw new InvalidDataException("Worker stderr withheld.");
        return text; // Caller must validate every field before writing any artifact.
    }
}
