#pragma warning disable CA1416 // Shared detached enum values only.
using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Text.Json;
using static SddlExportInputs;

internal static class SddlAlarmContracts
{
    internal static IEnumerable<Input> Inputs()
    {
        var fixtures = new List<Fixture>();
        foreach (byte type in new byte[] {3,8,14,16})
            foreach (byte audit in new byte[] {0,64,128,192})
                foreach (byte inheritance in new byte[] {0,8})
                    fixtures.Add(Make($"alarm-{type}-flags-{audit | inheritance}", "alarm-family", false,
                        Ace(type,(byte)(audit | inheritance),16,objectFlags:type is 8 or 16 ? 1u : 0u)));
        // Reviewed inactive ordinary audit controls must retain their approved behavior.
        foreach (byte type in new byte[] {2,7})
            foreach (byte flags in new byte[] {8,72})
                fixtures.Add(Make($"inactive-audit-{type}-{flags}", "reviewed-inactive-control", false,
                    Ace(type,flags,16,objectFlags:type == 7 ? 1u : 0u)));
        // Check absent, inherited-only and both GUID layouts without a broad cross-product.
        foreach (byte type in new byte[] {8,16})
            foreach (uint objects in new uint[] {0,2,3})
                fixtures.Add(Make($"object-alarm-{type}-layout-{objects}", "alarm-family", false,
                    Ace(type,64,16,objectFlags:objects)));
        var condition = Convert.FromHexString("61727478F90A0000004C006500760065006C0004020000000000000003028500");
        foreach (byte type in new byte[] {14,16})
            foreach (byte flags in new byte[] {64,192})
                fixtures.Add(Make($"callback-alarm-{type}-valid-{flags}", "alarm-family", false,
                    Ace(type,flags,16,objectFlags:type == 16 ? 1u : 0u,opaque:condition)));
        // Exact standalone shape of the reviewed AL and OL parse strings (937/987).
        foreach (byte type in new byte[] {3,8})
        {
            var ace = Ace(type,64,16,objectFlags:type == 8 ? 1u : 0u);
            var bytes = new byte[28 + ace.Length]; bytes[0] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2),0x8010);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12),20); bytes[20] = type == 8 ? (byte)4 : (byte)2;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(22),(ushort)(8 + ace.Length));
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(24),1); ace.CopyTo(bytes,28);
            fixtures.Add(new($"standalone-alarm-{type}","alarm-family",false,bytes));
        }
        foreach (var fixture in fixtures)
        {
            yield return new(fixture,"export-selected",AccessControlSections.Audit,"alarm-composition");
            yield return new(fixture,"export-unselected",AccessControlSections.Access,"alarm-composition");
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
        Emit(new { Kind = "Header", Schema = "sddl-alarm-composition-v1", Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, TotalCases = inputs.Length, Start = start, Count = end - start,
            Scope = "96 detached alarm-family formatting/reparse compositions. Binary input, formatting and native reparse are separately recorded. No lookup or persistence." });
        for (var i = start; i < end; i++) Emit(SddlExportContracts.Observe(inputs[i], i));
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
    }
}
