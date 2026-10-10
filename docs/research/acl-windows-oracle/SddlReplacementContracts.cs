#pragma warning disable CA1416 // Detached numeric identities and descriptors only.
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;
using static SddlMixedContracts;
#if PORTABLE_FACADE
using A = AdForLinux.Security.AccessControl;
using P = AdForLinux.Security.Principal;
#else
using A = System.Security.AccessControl;
using P = System.Security.Principal;
#endif

internal static class SddlReplacementContracts
{
    internal sealed record Input(bool Audit, string Opposite, int Operation, bool Shared)
    {
        internal string Label => $"replacement/{(Audit ? "SACL" : "DACL")}/{Opposite}/{(Shared ? "aliases" : Operation.ToString())}";
        internal AccessControlSections Target => Audit ? AccessControlSections.Audit : AccessControlSections.Access;
        internal AccessControlSections Other => Audit ? AccessControlSections.Access : AccessControlSections.Audit;
        internal byte[] Source()
        {
            var condition = Convert.FromHexString(Opposite == "malformed-callback" ? "61727478FF000000"
                : "61727478F90A0000004C006500760065006C0004020000000000000003028500");
            var extra = Opposite switch
            {
                "ordinary" => SddlExportInputs.Ace(Audit ? (byte)0 : (byte)2, Audit ? (byte)0 : (byte)64,32),
                "unsupported" => new byte[] {22,0,8,0,1,2,3,4},
                _ => SddlExportInputs.Ace(Audit ? (byte)9 : (byte)13, Audit ? (byte)0 : (byte)64,32,opaque:condition)
            };
            return SddlExportInputs.Make(Label,"replacement",Audit,extra).Bytes;
        }
    }
    internal sealed record Step(string Name, AccessControlSections Sections, byte[]? Binary = null, string? Text = null);
    internal static IEnumerable<Input> Inputs()
    {
        foreach (var audit in new[] {false,true})
            foreach (var opposite in new[] {"ordinary","valid-callback","malformed-callback","unsupported"})
                for (var op = 0; op < 8; op++) yield return new(audit,opposite,op,false);
        foreach (var audit in new[] {false,true})
            foreach (var opposite in new[] {"ordinary","valid-callback","malformed-callback","unsupported"})
                yield return new(audit,opposite,8,true);
    }
    internal static IEnumerable<Step> Steps(Input input)
    {
        var candidate = SddlExportInputs.Make("candidate","replacement",false).Bytes;
        foreach (var (field,mask) in new[] {(16,input.Audit ? 64 : 32),(12,input.Audit ? 32 : 64)})
        { var offset = BinaryPrimitives.ReadInt32LittleEndian(candidate.AsSpan(field)); BinaryPrimitives.WriteInt32LittleEndian(candidate.AsSpan(offset + 12),mask); }
        SetIdentity(candidate,true,19); SetIdentity(candidate,false,545);
        var valid = input.Audit ? "S:(AU;SA;WP;;;WD)" : "D:(A;;WP;;;WD)";
        var malformed = valid + (input.Audit ? "D:(XA;;RP;;;WD;(@User.Level ==))" : "S:(XU;SA;RP;;;WD;(@User.Level ==))");
        var binary = new Step("binary-replace",input.Target,candidate);
        var owner = new Step("prior-owner",AccessControlSections.Owner,Text:"O:S-1-5-20");
        var compound = new Step("compound-assignment",AccessControlSections.All,candidate);
        if (input.Shared)
        {
            yield return owner;
            var identical = input.Source(); SetIdentity(identical,true,20);
            yield return new("identical-all",AccessControlSections.All,identical);
            yield return binary;
            yield return new("edit-shared-old-acl",input.Target);
            yield return compound;
            yield break;
        }
        switch (input.Operation)
        {
            case 0: yield return binary; break;
            case 1: yield return new("sddl-replace",input.Target,Text:valid); break;
            case 2: yield return new("identical-all",AccessControlSections.All,input.Source()); break;
            case 3: yield return owner; yield return binary; break;
            case 4:
                yield return binary;
                yield return new("malformed-after-success",AccessControlSections.All,Text:"O:S-1-5-19G:S-1-5-32-545" + malformed);
                break;
            case 5:
                yield return new("malformed-unselected-text",input.Target,Text:malformed);
                var bad = (byte[])candidate.Clone(); var off = BinaryPrimitives.ReadInt32LittleEndian(bad.AsSpan(input.Audit ? 16 : 12));
                BinaryPrimitives.WriteUInt16LittleEndian(bad.AsSpan(off + 2),7);
                yield return new("malformed-unselected-binary",input.Target,bad);
                break;
            case 6: yield return owner; yield return compound; break;
            case 7: yield return new("replace-opposite",input.Other,candidate); break;
        }
    }
    private static void SetIdentity(byte[] bytes, bool owner, int final)
    {
        var offset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(owner ? 4 : 8));
        var length = 8 + 4 * bytes[offset + 1];
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(offset + length - 4),final);
    }
    internal sealed class Context
    {
        internal readonly Input Input;
        internal readonly FacadeContracts.Wrapper Main;
        internal readonly FacadeContracts.Wrapper? Peer, Alias;
        internal readonly A.CommonSecurityDescriptor InitialDescriptor;
        internal readonly A.DiscretionaryAcl InitialDacl;
        internal readonly A.SystemAcl InitialSacl;
        internal Context(Input input, byte[] source)
        {
            Input = input;
            InitialDescriptor = new(true,true,source,0);
            InitialDacl = InitialDescriptor.DiscretionaryAcl!; InitialSacl = InitialDescriptor.SystemAcl!;
            Main = new(InitialDescriptor);
            if (input.Shared)
            {
                Peer = new(InitialDescriptor);
                Alias = new(new A.CommonSecurityDescriptor(true,true,InitialDescriptor.ControlFlags,
                    InitialDescriptor.Owner,InitialDescriptor.Group,InitialSacl,InitialDacl));
            }
        }
        internal void Apply(Step step)
        {
            if (step.Name == "edit-shared-old-acl")
            {
                if (Input.Audit) InitialSacl.AddAudit(AuditFlags.Success,new P.SecurityIdentifier("S-1-5-19"),64,0,0);
                else InitialDacl.AddAccess(AccessControlType.Allow,new P.SecurityIdentifier("S-1-5-19"),64,0,0);
            }
            else if (step.Binary is not null) Main.SetSecurityDescriptorBinaryForm(step.Binary,step.Sections);
            else Main.SetSecurityDescriptorSddlForm(step.Text!,step.Sections);
        }
        internal object Snapshot() => new
        {
            Main = SnapshotWrapper(Main), Peer = Peer is null ? null : SnapshotWrapper(Peer), Alias = Alias is null ? null : SnapshotWrapper(Alias),
            References = new { MainDescriptor = ReferenceEquals(Main.Descriptor,InitialDescriptor),
                PeerDescriptor = Peer is null ? (bool?)null : ReferenceEquals(Main.Descriptor,Peer.Descriptor),
                MainDaclInitial = ReferenceEquals(Main.Descriptor.DiscretionaryAcl,InitialDacl),
                MainSaclInitial = ReferenceEquals(Main.Descriptor.SystemAcl,InitialSacl),
                AliasDaclInitial = Alias is null ? (bool?)null : ReferenceEquals(Alias.Descriptor.DiscretionaryAcl,InitialDacl),
                AliasSaclInitial = Alias is null ? (bool?)null : ReferenceEquals(Alias.Descriptor.SystemAcl,InitialSacl),
                SharedDacl = Alias is null ? (bool?)null : ReferenceEquals(Main.Descriptor.DiscretionaryAcl,Alias.Descriptor.DiscretionaryAcl),
                SharedSacl = Alias is null ? (bool?)null : ReferenceEquals(Main.Descriptor.SystemAcl,Alias.Descriptor.SystemAcl) }
        };
        private static object SnapshotWrapper(FacadeContracts.Wrapper wrapper) => new
        { Descriptor = Describe(new A.RawSecurityDescriptor(wrapper.GetSecurityDescriptorBinaryForm(),0)), Flags = wrapper.Flags() };
    }
    internal static object Observe(int id, Action<Context,Step,bool,bool>? hook = null)
    {
        var input = Inputs().ElementAt(id); var source = input.Source(); var saved = (byte[])source.Clone(); Context? context = null;
        var imported = Capture(() => { context = new(input,source); return context.Snapshot(); });
        var steps = new List<object>();
        if (context is not null)
            foreach (var step in Steps(input))
            {
                var supplied = step.Binary is null ? null : (byte[])step.Binary.Clone();
                var before = context.Snapshot(); hook?.Invoke(context,step,true,false);
                var success = false;
                var result = Capture(() => { context.Apply(step); success = true; return null; });
                hook?.Invoke(context,step,false,success);
                steps.Add(new { step.Name, Sections = (int)step.Sections,
                    BinaryHex = supplied is null ? null : Convert.ToHexString(supplied),
                    TextUtf16Hex = step.Text is null ? null : SddlBoundaryInputs.Utf16Hex(step.Text),
                    Before = before, Result = result, After = context.Snapshot(),
                    SuppliedBinaryUnchanged = supplied is null ? (bool?)null : supplied.AsSpan().SequenceEqual(step.Binary) });
            }
        return new { Kind = "Observation", Case = id, input.Label, input.Audit, input.Opposite, input.Operation, input.Shared,
            SourceHex = Convert.ToHexString(saved), Import = imported, Steps = steps, SourceUnchanged = saved.AsSpan().SequenceEqual(source) };
    }
    internal static void Write(string path,int start,int count)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        const int total = 72;
        if (start < 0 || start >= total || count is < 1 or > 16) throw new ArgumentOutOfRangeException();
        var end = Math.Min(total,start + count);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { AutoFlush = true };
        Emit(new { Kind = "Header", Schema = "sddl-selected-replacement-v1", Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription, TotalCases = total, Start = start, Count = end - start,
            Scope = "64 selected ACL replacement scenarios plus eight shared-alias cases. Detached objects, fresh baselines, raw input and observable state separate; no lookup or persistence." });
        for (var i = start; i < end; i++) Emit(Observe(i));
        void Emit(object value) => output.WriteLine(JsonSerializer.Serialize(value));
    }
}
