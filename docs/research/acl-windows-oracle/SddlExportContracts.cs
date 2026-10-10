#pragma warning disable CA1416 // Detached objects only.
using System.Runtime.InteropServices;
using System.Text.Json;
using static SddlMixedContracts;
using ExportProbe = SddlMixedContracts.Probe;
#if PORTABLE_FACADE
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
#else
using A = System.Security.AccessControl;
using P = System.Security.Principal;
#endif

internal static class SddlExportContracts
{
    internal static object Observe(int index, Action<ExportProbe, A.CommonSecurityDescriptor, byte[]>? before = null,
        Action<ExportProbe, A.CommonSecurityDescriptor, byte[]>? after = null)
    {
        var input = SddlExportInputs.Create().ElementAt(index);
        A.RawSecurityDescriptor? raw = null; byte[]? bytes = null, original = null;
        var parsed = Capture(() =>
        {
            raw = input.Fixture.Text is null ? new(input.Fixture.Bytes, 0) : new(input.Fixture.Text);
            bytes = Bytes(raw); original = (byte[])bytes.Clone(); return Describe(raw);
        });
        object? rawExport = null, imported = null, commonImported = null, prepared = null, commonPrepared = null;
        object? result = null, commonResult = null, final = null, commonFinal = null;
        if (bytes is not null)
        {
            ExportProbe? facade = null; A.CommonSecurityDescriptor? common = null;
            imported = Capture(() => { facade = new ExportProbe(bytes); return Snapshot(facade); });
            commonImported = Capture(() => { common = new(true, true, bytes, 0); return CommonSnapshot(common); });
            if (facade is not null && common is not null)
            {
                if (input.Operation == "owner-then-export")
                { facade.SetSecurityDescriptorSddlForm("O:S-1-5-19", System.Security.AccessControl.AccessControlSections.Owner); common.Owner = new P.SecurityIdentifier("S-1-5-19"); }
                prepared = Snapshot(facade); commonPrepared = CommonSnapshot(common);
                before?.Invoke(facade, common, original!);
                if (input.Operation is "edit-owner" or "edit-group")
                {
                    var owner = input.Operation == "edit-owner";
                    var text = owner ? "O:S-1-5-19" : "G:S-1-5-32-545";
                    result = Capture(() => { facade.SetSecurityDescriptorSddlForm(text, input.Sections); return null; });
                    commonResult = Capture(() =>
                    { if (owner) common.Owner = new P.SecurityIdentifier("S-1-5-19"); else common.Group = new P.SecurityIdentifier("S-1-5-32-545"); return null; });
                }
                else
                {
                    rawExport = Capture(() => Export(raw!.GetSddlForm(input.Sections)));
                    result = Capture(() => Export(facade.GetSecurityDescriptorSddlForm(input.Sections)));
                    commonResult = Capture(() => Export(common.GetSddlForm(input.Sections)));
                }
                final = Snapshot(facade); commonFinal = CommonSnapshot(common);
                after?.Invoke(facade, common, original!);
            }
        }
        return new { Kind = "Observation", Case = index, input.Label, Fixture = input.Fixture.Name, input.Fixture.Family,
            InputHex = input.Fixture.Text is null ? Convert.ToHexString(input.Fixture.Bytes) : null,
            InputUtf16Hex = input.Fixture.Text is null ? null : SddlBoundaryInputs.Utf16Hex(input.Fixture.Text),
            input.Operation, SelectedSections = (int)input.Sections, OriginalRaw = parsed, RawExport = rawExport,
            FacadeImport = imported, CommonImport = commonImported, PreparedBefore = prepared, CommonPreparedBefore = commonPrepared,
            Result = result, CommonResult = commonResult, FacadeAfter = final, CommonAfter = commonFinal,
            CallerInputUnchanged = original is null ? (bool?)null : original.AsSpan().SequenceEqual(bytes),
            RawObjectUnchanged = raw is null ? (bool?)null : original!.AsSpan().SequenceEqual(Bytes(raw)) };
    }

    private static object Export(string text) => new { Utf16Hex = SddlBoundaryInputs.Utf16Hex(text), CodeUnits = text.Length,
        Reparse = Capture(() => Describe(new A.RawSecurityDescriptor(text))) };

    private static object CommonSnapshot(A.CommonSecurityDescriptor value)
    {
        var bytes = new byte[value.BinaryLength]; value.GetBinaryForm(bytes, 0);
        return new { Descriptor = Describe(new A.RawSecurityDescriptor(bytes, 0)), value.IsContainer, value.IsDS,
            value.IsDiscretionaryAclCanonical, value.IsSystemAclCanonical };
    }

    internal static void Write(string path, int start, int count)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var total = SddlExportInputs.Create().Count();
        if (start < 0 || start >= total || count is < 1 or > 16) throw new ArgumentOutOfRangeException();
        var end = Math.Min(total, start + count);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        Emit(new { Kind = "Header", Schema = "sddl-retained-export-v1", Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, AclAssembly = typeof(A.RawSecurityDescriptor).Assembly.FullName,
            TotalCases = total, Start = start, Count = end - start, FreshBaselinePerObservation = true,
            Scope = "Raw, direct CommonSecurityDescriptor and detached AD export; original source, normalized and prepared state remain separate. No lookup or persistence." });
        for (var index = start; index < end; index++) Emit(Observe(index));
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
    }
}
