#pragma warning disable CA1416 // Detached descriptors only; no persistence or identity lookup.
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;
#if PORTABLE_FACADE
using A = AdForLinux.Security.AccessControl;
using M = AdForLinux.DirectoryServices;
#else
using A = System.Security.AccessControl;
using M = System.DirectoryServices;
#endif

internal static class SddlMixedContracts
{
    internal static object Observe(int index, Action<Probe, byte[]>? before = null, Action<Probe, byte[]>? after = null)
    {
        var input = SddlMixedInputs.Create().ElementAt(index);
        // Nothing is shared between cases, including operations on the same fixture.
        A.RawSecurityDescriptor? raw = null;
        byte[]? bytes = null, original = null;
        var parsed = Capture(() =>
        {
            raw = new A.RawSecurityDescriptor(input.Text);
            bytes = Bytes(raw); original = (byte[])bytes.Clone();
            return Describe(raw);
        });
        Probe? facade = null;
        object? imported = null, result = null, final = null;
        if (bytes is not null)
        {
            imported = Capture(() => { facade = new Probe(bytes); return Snapshot(facade); });
            if (facade is not null)
            {
                before?.Invoke(facade, original!);
                result = Capture(() =>
                {
                    if (input.Operation == "parse-copy") return Describe(new A.RawSecurityDescriptor(bytes, 0));
                    if (input.Edit is not null)
                    { facade.SetSecurityDescriptorSddlForm(input.Edit, input.Sections); return null; }
                    var text = facade.GetSecurityDescriptorSddlForm(input.Sections);
                    return new { Utf16Hex = SddlBoundaryInputs.Utf16Hex(text), CodeUnits = text.Length,
                        Reparse = Capture(() => Describe(new A.RawSecurityDescriptor(text))) };
                });
                final = Snapshot(facade);
                after?.Invoke(facade, original!);
            }
        }
        return new { Kind = "Observation", Case = index, input.Label, input.Fixture, input.Operation,
            InputUtf16Hex = SddlBoundaryInputs.Utf16Hex(input.Text), SelectedSections = (int)input.Sections,
            EditUtf16Hex = input.Edit is null ? null : SddlBoundaryInputs.Utf16Hex(input.Edit),
            OriginalRaw = parsed, FacadeImport = imported, Result = result, FacadeAfter = final,
            CallerInputUnchanged = original is null ? (bool?)null : original.AsSpan().SequenceEqual(bytes),
            RawObjectUnchanged = raw is null ? (bool?)null : original!.AsSpan().SequenceEqual(Bytes(raw)) };
    }

    internal static object Snapshot(Probe facade) => new
    {
        Descriptor = Describe(new A.RawSecurityDescriptor(facade.GetSecurityDescriptorBinaryForm(), 0)),
        Flags = facade.Flags(), facade.AreAccessRulesCanonical, facade.AreAuditRulesCanonical,
        facade.AreAccessRulesProtected, facade.AreAuditRulesProtected
    };

    internal static object Describe(A.RawSecurityDescriptor raw) => new
    {
        Hex = Convert.ToHexString(Bytes(raw)), raw.BinaryLength, Control = (int)raw.ControlFlags,
        Owner = raw.Owner?.Value, Group = raw.Group?.Value,
        DaclHex = AclHex(raw.DiscretionaryAcl), SaclHex = AclHex(raw.SystemAcl)
    };
    private static string? AclHex(A.RawAcl? acl)
    {
        if (acl is null) return null;
        var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return Convert.ToHexString(bytes);
    }
    internal static byte[] Bytes(A.RawSecurityDescriptor raw)
    { var bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0); return bytes; }
    internal static object Capture(Func<object?> action)
    {
        object? result = null; string? type = null, parameter = null; int? code = null;
        try { result = action(); }
        catch (Exception ex) { type = ex.GetType().FullName; parameter = (ex as ArgumentException)?.ParamName; code = (ex as Win32Exception)?.NativeErrorCode; }
        return new { Outcome = result, ExceptionType = type, ParamName = parameter, NativeErrorCode = code };
    }

    internal sealed class Probe : M.ActiveDirectorySecurity
    {
#if PORTABLE_FACADE
        // Raw import keeps source bytes/provenance; never seed from normalized native output.
        internal Probe(byte[] raw) : base(raw, M.SecurityMasks.Owner | M.SecurityMasks.Group | M.SecurityMasks.Dacl | M.SecurityMasks.Sacl) { }
#else
        internal Probe(byte[] raw)
        {
            SetSecurityDescriptorBinaryForm(raw);
            // Initialization is not the operation under test. Observe normalization
            // separately, then measure only the fresh operation's dirty flags.
            WriteLock();
            try { OwnerModified = GroupModified = AccessRulesModified = AuditRulesModified = false; }
            finally { WriteUnlock(); }
        }
#endif
        internal bool[] Flags()
        {
            ReadLock();
            try { return [OwnerModified, GroupModified, AccessRulesModified, AuditRulesModified]; }
            finally { ReadUnlock(); }
        }
    }

    internal static void Write(string path, int start, int count)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        const int total = 64;
        if (start < 0 || start >= total || count is < 1 or > 16) throw new ArgumentOutOfRangeException();
        var end = Math.Min(total, start + count);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
        Emit(new { Kind = "Header", Schema = "sddl-mixed-operations-v1", Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, AclAssembly = typeof(A.RawSecurityDescriptor).Assembly.FullName,
            FacadeAssembly = typeof(M.ActiveDirectorySecurity).Assembly.FullName, TotalCases = total, Start = start, Count = end - start,
            FreshBaselinePerObservation = true, Scope = "Detached ordinary-size operations. Original raw bytes and facade normalization are separate; no lookup or persistence." });
        for (var index = start; index < end; index++) Emit(Observe(index));
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
    }
}
