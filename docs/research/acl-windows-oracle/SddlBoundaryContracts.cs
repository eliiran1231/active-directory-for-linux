using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;

// OPT-IN research only. Local preparation does not constitute native evidence.
// Uses detached Microsoft descriptors; never performs directory or access-check work.
internal static class SddlBoundaryContracts
{
    internal static void Write(string path, int start, int count, bool sizeFollowup = false)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var inputs = (sizeFollowup ? SddlBoundaryInputs.CreateSizeFollowup() : SddlBoundaryInputs.Create()).ToArray();
        if (start < 0 || start >= inputs.Length) throw new ArgumentOutOfRangeException(nameof(start));
        if (count is < 1 or > 16) throw new ArgumentOutOfRangeException(nameof(count), "Use batches of at most 16 cases.");
        var end = Math.Min(inputs.Length, checked(start + count));
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        Emit(new { Kind = "Header", Schema = "sddl-boundary-v1", Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, AclAssembly = typeof(RawSecurityDescriptor).Assembly.FullName,
            MicrosoftAssembly = typeof(System.DirectoryServices.ActiveDirectorySecurity).Assembly.FullName,
            TotalCases = inputs.Length, Start = start, Count = end - start,
            Scope = "Detached string/binary representation only. No directory I/O, lookup, persistence, privilege changes or evaluation." });
        for (var index = start; index < end; index++)
        {
            var input = inputs[index];
            RawSecurityDescriptor? raw = null;
            var parse = Capture(() =>
            {
                var candidate = new RawSecurityDescriptor(input.Text);
                var bytes = Bytes(candidate);
                raw = candidate;
                return new { Hex = Convert.ToHexString(bytes), raw.BinaryLength, Control = (int)raw.ControlFlags };
            });
            // Separate parse and export outcomes: a successful import is not proof
            // that GetSddlForm accepts or preserves this descriptor's contents.
            object? format = null;
            bool? unchanged = null;
            if (raw is not null)
            {
                var before = Bytes(raw);
                format = Capture(() =>
                {
                    var text = raw.GetSddlForm(AccessControlSections.All);
                    return new { Utf16Hex = SddlBoundaryInputs.Utf16Hex(text), CodeUnits = text.Length };
                });
                unchanged = before.AsSpan().SequenceEqual(Bytes(raw));
            }
            Emit(new { Kind = "Observation", Case = index, input.Label, input.Family,
                InputUtf16Hex = SddlBoundaryInputs.Utf16Hex(input.Text), InputCodeUnits = input.Text.Length,
                Parse = parse, FormatAll = format, BinaryUnchangedByFormat = unchanged });
        }
        void Emit(object value)
        {
            var json = JsonSerializer.Serialize(value); output.WriteLine(json);
            Console.WriteLine("SDDL_BOUNDARY_JSONL=" + json);
        }
    }

    private static object Capture(Func<object> action)
    {
        object? result = null; string? type = null, parameter = null; int? code = null;
        try { result = action(); }
        catch (Exception ex)
        {
            type = ex.GetType().FullName; parameter = (ex as ArgumentException)?.ParamName;
            code = (ex as System.ComponentModel.Win32Exception)?.NativeErrorCode;
        }
        return new { Outcome = result, ExceptionType = type, ParamName = parameter, NativeErrorCode = code };
    }

    private static byte[] Bytes(RawSecurityDescriptor raw)
    {
        var bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0); return bytes;
    }
}
