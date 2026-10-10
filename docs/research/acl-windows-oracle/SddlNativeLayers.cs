using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Detached conversion only. Never creates tokens, changes security settings or contacts AD.
internal static class SddlNativeLayers
{
    internal static IEnumerable<SddlBoundaryInputs.Input> Inputs()
    {
        foreach (var input in SddlBoundaryInputs.Create().Take(76)) yield return input;
        foreach (var input in SddlBoundaryInputs.CreateSizeFollowup()) yield return input;
        foreach (var length in new[] { 32690, 32694, 32698, 32700, 32701, 32702, 32704, 32706, 32720, 32740, 32748 })
        foreach (var family in new[] { "FL", "XA", "RA-value", "RA-name" })
        foreach (var variant in new[] { "base", "numeric-sid", "numeric-rights", "spaces", "owner", "group" })
        {
            var value = new string('x', length);
            var sid = variant == "numeric-sid" ? "S-1-1-0" : "WD";
            var rights = family.StartsWith("RA") ? "" : variant == "numeric-rights" ? "0x10" : "RP";
            var expression = family switch
            {
                "RA-value" => $"(\"Name\",TS,0,\"{value}\")",
                "RA-name" => $"(\"{value}\",TS,0,\"v\")",
                _ => $"(@User.A == \"{value}\")"
            };
            if (variant == "spaces" && !family.StartsWith("RA")) expression = expression.Replace(" == ", "     ==     ");
            var section = family == "XA" ? "D" : "S";
            var type = family.StartsWith("RA") ? "RA" : family;
            var prefix = variant == "owner" ? "O:SY" : variant == "group" ? "G:BA" : "";
            var text = $"{prefix}{section}:({type};;{rights};;;{sid};{expression})";
            if (variant == "spaces" && family.StartsWith("RA")) text += "        ";
            yield return new($"spelling/{family}/{variant}/{length}", type, text);
        }
    }

    internal static void Write(string path, int index)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (index < 0) throw new ArgumentOutOfRangeException(nameof(index));
        var input = Inputs().ElementAt(index);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        Emit(new { Kind = "Attempt", Case = index, input.Label, input.Family, InputCodeUnits = input.Text.Length,
            InputUtf16Hex = SddlBoundaryInputs.Utf16Hex(input.Text), Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, AclAssembly = typeof(RawSecurityDescriptor).Assembly.FullName });
        // Capture the native return and last error before any subsequent P/Invoke.
        Marshal.SetLastPInvokeError(0);
        var success = ConvertStringSecurityDescriptorToSecurityDescriptorW(input.Text, 1, out var allocation, out var returnedSize);
        var lastError = Marshal.GetLastPInvokeError();
        byte[]? bytes = null; ulong? allocationSize = null; string? inspectionError = null;
        try
        {
            if (success)
            {
                if (allocation.IsInvalid) throw new InvalidOperationException("Native success returned no allocation.");
                allocationSize = (ulong)LocalSize(allocation);
                // Never trust a malformed output length as permission to read memory.
                if (returnedSize > 1024 * 1024 || returnedSize > allocationSize || allocationSize == 0)
                    throw new InvalidOperationException("Returned size exceeds the inspected allocation or the 1 MiB probe bound.");
                bytes = new byte[returnedSize];
                Marshal.Copy(allocation.DangerousGetHandle(), bytes, 0, bytes.Length);
            }
        }
        catch (Exception ex) { inspectionError = ex.ToString(); }
        finally { allocation.Dispose(); }
        Emit(new { Kind = "Native", Case = index, Success = success, LastError = lastError, ReturnedSize = returnedSize,
            AllocationSize = allocationSize, Hex = bytes is null ? null : Convert.ToHexString(bytes), InspectionError = inspectionError,
            LocalFreeSucceeded = allocation.FreeSucceeded });
        object? managedBinary = null;
        bool? unchanged = null;
        if (bytes is not null)
        {
            var before = (byte[])bytes.Clone();
            managedBinary = Capture(() => Describe(new RawSecurityDescriptor(bytes, 0)));
            unchanged = before.AsSpan().SequenceEqual(bytes);
        }
        Emit(new { Kind = "Managed", Case = index, BinaryConstructor = managedBinary, BinaryInputUnchanged = unchanged,
            StringConstructor = Capture(() => Describe(new RawSecurityDescriptor(input.Text))) });
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
    }

    private static object Describe(RawSecurityDescriptor descriptor)
    {
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        return new { Hex = Convert.ToHexString(bytes), descriptor.BinaryLength, Control = (int)descriptor.ControlFlags };
    }
    private static object Capture(Func<object> action)
    {
        object? result = null; string? type = null, parameter = null; int? code = null;
        try { result = action(); }
        catch (Exception ex) { type = ex.GetType().FullName; parameter = (ex as ArgumentException)?.ParamName; code = (ex as Win32Exception)?.NativeErrorCode; }
        return new { Outcome = result, ExceptionType = type, ParamName = parameter, NativeErrorCode = code };
    }

    private sealed class LocalAllocation : SafeHandleZeroOrMinusOneIsInvalid
    {
        public LocalAllocation() : base(true) { }
        internal bool? FreeSucceeded { get; private set; }
        protected override bool ReleaseHandle() { FreeSucceeded = LocalFree(handle) == IntPtr.Zero; return FreeSucceeded.Value; }
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out LocalAllocation descriptor, out uint size);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nuint LocalSize(LocalAllocation allocation);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr allocation);
}
