#pragma warning disable CA1416 // Shared detached enum values only.
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;
using static SddlExportInputs;

internal static class SddlRawContractContracts
{
    internal static IEnumerable<Input> Inputs()
    {
        var unknown = Convert.FromHexString("61727478FF000000");
        var valid = Convert.FromHexString("61727478F90A0000004C006500760065006C0004020000000000000003028500");
        var fixtures = new List<Fixture>();
        void Add(string name, byte type, byte flags, int mask = 16, uint objects = 0, byte[]? opaque = null, bool? access = null)
            => fixtures.Add(Make(name, "raw-contract", access ?? type is 9 or 10 or 11 or 12,
                Ace(type, flags, mask, objects, opaque)));
        Add("unknown-XA",9,0,opaque:unknown);
        Add("unknown-XA-zero",9,0,0,opaque:unknown);
        Add("unknown-XA-SA",9,64,opaque:unknown);
        Add("unknown-XD",10,0,opaque:unknown);
        Add("unknown-ZA",11,0,objects:1,opaque:unknown);
        Add("unknown-XU-SA",13,64,opaque:unknown);
        Add("unknown-XU-unaudited",13,0,opaque:unknown);
        Add("unknown-XU-zero",13,64,0,opaque:unknown);
        Add("unknown-XU-IO",13,8,opaque:unknown);
        Add("unknown-ZA-reserved",11,0,objects:5,opaque:unknown);
        foreach (byte type in new byte[] {2,3,7,8})
            foreach (byte flags in new byte[] {0,8})
                Add($"unaudited-{type}-{flags}",type,flags,objects:type >= 7 ? 1u : 0u);
        Add("unaudited-AU-zero",2,0,0);
        Add("unaudited-OU-zero",7,0,0,1);
        Add("unaudited-AU-DACL",2,0,access:true);
        Add("valid-XU-unaudited",13,0,opaque:valid);
        Add("valid-XU-unaudited-zero",13,0,0,opaque:valid);
        Add("arbitrary-XA",9,0,opaque:[1,2,3,4]);
        Add("arbitrary-XU",13,64,opaque:[1,2,3,4]);
        Add("extra-padding-XA",9,0,opaque:[..valid,0,0,0,0]);
        Add("unknown-object-deny",12,0,objects:1,opaque:unknown);
        Add("valid-XU-SA",13,64,opaque:valid);
        Add("ordinary-AU-SA",2,64);
        Add("truncated-literal-XA",9,0,opaque:Convert.FromHexString("61727478F9000000"));
        Add("underflow-XA",9,0,opaque:Convert.FromHexString("6172747880000000"));
        Add("opaque-unaudited-AU",2,0,opaque:[1,2,3,4]);
        foreach (var fixture in fixtures)
        {
            yield return new(fixture,"export-selected",fixture.Dacl ? AccessControlSections.Access : AccessControlSections.Audit,"raw-contract");
            yield return new(fixture,"export-unselected",fixture.Dacl ? AccessControlSections.Audit : AccessControlSections.Access,"raw-contract");
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
        Emit(new { Kind = "Header", Schema = "sddl-raw-contract-v1", Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, TotalCases = inputs.Length, Start = start, Count = end - start,
            Scope = "64 detached raw formatting/validation compositions. Binary input, formatting and native reparse are separately recorded. No lookup or persistence." });
        for (var i = start; i < end; i++) Emit(SddlExportContracts.Observe(inputs[i], i));
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
    }
}
