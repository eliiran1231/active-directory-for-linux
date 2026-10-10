#pragma warning disable CA1416 // Shared detached enum values only.
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;
using static SddlExportInputs;

internal static class SddlCompositionContracts
{
    internal static IEnumerable<Input> Inputs()
    {
        foreach (var (type, objects) in new (byte, uint)[] {
            (9,0), (10,0), (11,0), (11,1), (11,2), (11,3), (12,1), (13,0), (14,0), (15,1), (16,1) })
        {
            var dacl = type is 9 or 10 or 11 or 12;
            var fixture = Make($"empty-{type}-objects-{objects}", "composition-empty-callback", dacl,
                Ace(type, dacl ? (byte)0 : (byte)64, 16, objectFlags: objects));
            foreach (var input in Selections(fixture)) yield return input;
        }
        // Exact valid condition bytes from the prior recorded FL/XA fixtures.
        var condition = Convert.FromHexString("61727478F90A0000004C006500760065006C0004020000000000000003028500");
        foreach (byte type in new byte[] { 9, 10, 11, 13 })
        {
            var fixture = Make($"condition-control-{type}", "composition-valid-control", type != 13,
                Ace(type, type == 13 ? (byte)64 : (byte)0, 16, objectFlags: type == 11 ? 1u : 0u, opaque: condition));
            foreach (var input in Selections(fixture)) yield return input;
        }
        static IEnumerable<Input> Selections(Fixture fixture)
        {
            yield return new(fixture, "export-selected", fixture.Dacl ? AccessControlSections.Access : AccessControlSections.Audit, "callback-composition");
            yield return new(fixture, "export-unselected", fixture.Dacl ? AccessControlSections.Audit : AccessControlSections.Access, "callback-composition");
            yield return new(fixture, "export-all", AccessControlSections.All, "callback-composition");
        }
    }

    internal static void Write(string path, int start, int count)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var inputs = Inputs().ToArray();
        if (start < 0 || start >= inputs.Length || count is < 1 or > 16) throw new ArgumentOutOfRangeException();
        var end = Math.Min(inputs.Length, start + count);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        Emit(new { Kind = "Header", Schema = "sddl-callback-composition-v1", Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, TotalCases = inputs.Length, Start = start, Count = end - start,
            Scope = "45 detached callback export/reparse compositions. Binary input, formatting and native reparse are separately recorded. No lookup or persistence." });
        for (var i = start; i < end; i++) Emit(SddlExportContracts.Observe(inputs[i], i));
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
    }
}
