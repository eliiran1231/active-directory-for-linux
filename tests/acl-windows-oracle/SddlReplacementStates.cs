#pragma warning disable CA1416
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;
using static SddlMixedContracts;
#if PORTABLE_FACADE
using A = AdForLinux.Security.AccessControl;
#else
using A = System.Security.AccessControl;
#endif

// Small state-transition matrix; native observable state never stands in for retained bytes.
internal static class SddlReplacementStates
{
    internal sealed record Input(bool Audit, string From, string To, int IntegerCode)
    {
        internal string Label => $"replacement-state/{(Audit ? "SACL" : "DACL")}/{From}-{To}/int{IntegerCode}";
        internal AccessControlSections Target => Audit ? AccessControlSections.Audit : AccessControlSections.Access;
        internal byte[] Source() => Image(Audit,From,SourceFlags(From),IntegerCode);
    }
    internal const int Count = 24;
    internal static IEnumerable<Input> Inputs()
    {
        foreach (var audit in new[] {false,true})
            foreach (var from in new[] {"absent","null","empty"})
                foreach (var to in new[] {"absent","null","empty"}) yield return new(audit,from,to,0);
        foreach (var audit in new[] {false,true})
            for (var code = 1; code <= 3; code++) yield return new(audit,"inherited","empty",code);
    }
    // Controls are deliberately distinct: exercise propagation/retention of P, AI and AR.
    private static int SourceFlags(string state) => state == "null" ? 0x1000 : state == "empty" ? 0x500 : 0;
    private static int TargetFlags(string state) => state == "absent" ? 0x400 : state == "null" ? 0x100 : 0x1400;
    internal static byte[] Image(bool audit,string state,int targetFlags,int integerCode = 0)
    {
        var ordinary = SddlExportInputs.Make("state","state",false).Bytes;
        byte[] Component(int field)
        {
            var off = BinaryPrimitives.ReadInt32LittleEndian(ordinary.AsSpan(field));
            var len = field < 12 ? 8 + 4 * ordinary[off + 1] : BinaryPrimitives.ReadUInt16LittleEndian(ordinary.AsSpan(off + 2));
            return ordinary.AsSpan(off,len).ToArray();
        }
        var target = state is "absent" or "null" ? Array.Empty<byte>() : new byte[] {4,0,8,0,0,0,0,0};
        var other = Component(audit ? 16 : 12);
        if (state == "inherited")
            target = Acl(SddlExportInputs.Ace(audit ? (byte)2 : (byte)0,audit ? (byte)82 : (byte)18,16));
        if (integerCode != 0)
        {
            var condition = Convert.FromHexString("61727478F90A0000004C006500760065006C00" + integerCode.ToString("X2") + "020000000000000003028500");
            other = Acl(SddlExportInputs.Ace(audit ? (byte)9 : (byte)13,audit ? (byte)0 : (byte)64,32,opaque:condition));
        }
        var parts = new[] {Component(4),Component(8),audit ? target : other,audit ? other : target};
        var bytes = new byte[20 + parts.Sum(p => p.Length)]; bytes[0] = 1;
        var present = audit ? 0x10 : 4;
        var flags = 0x8014 | (audit ? targetFlags << 1 : targetFlags);
        if (state == "absent") flags &= ~present;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2),(ushort)flags);
        var offset = 20;
        for (var i = 0; i < parts.Length; i++) if (parts[i].Length != 0)
        { BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4 + i * 4),offset);parts[i].CopyTo(bytes,offset);offset += parts[i].Length; }
        return bytes;
    }
    private static byte[] Acl(byte[] ace)
    {
        var bytes = new byte[8 + ace.Length];bytes[0] = 4;bytes[4] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(2),(ushort)bytes.Length);ace.CopyTo(bytes,8);return bytes;
    }
    internal static IEnumerable<SddlReplacementContracts.Step> Steps(Input input)
    {
        yield return new("prior-owner",AccessControlSections.Owner,Text:"O:S-1-5-20");
        var identical = input.Source(); var owner = BinaryPrimitives.ReadInt32LittleEndian(identical.AsSpan(4));
        BinaryPrimitives.WriteInt32LittleEndian(identical.AsSpan(owner + 8),20);
        yield return new("identical-all",AccessControlSections.All,identical);
        yield return new("selected-replace",input.Target,Image(input.Audit,input.To,TargetFlags(input.To)));
        yield return new("protect-preserve",input.Target);
        yield return new("unprotect",input.Target);
        yield return new("compound-replace",AccessControlSections.All,Image(input.Audit,"empty",0));
        yield return new("malformed-compound",AccessControlSections.All,Text:"O:S-1-5-19G:S-1-5-32-545D:(XA;;RP;;;WD;(@User.Level ==))");
    }
    internal sealed class Context
    {
        internal readonly Input Input;
        internal readonly FacadeContracts.Wrapper Main,Peer,Alias;
        internal readonly A.CommonSecurityDescriptor Descriptor;
        internal readonly A.DiscretionaryAcl? Dacl;
        internal readonly A.SystemAcl? Sacl;
        internal Context(Input input,byte[] source)
        {
            Input = input;Descriptor = new(true,true,source,0);Dacl = Descriptor.DiscretionaryAcl;Sacl = Descriptor.SystemAcl;
            Main = new(Descriptor);Peer = new(Descriptor);
            Alias = new(new A.CommonSecurityDescriptor(true,true,Descriptor.ControlFlags,Descriptor.Owner,Descriptor.Group,Sacl,Dacl));
        }
        internal void Apply(SddlReplacementContracts.Step step) => ApplyTo(Main,Input,step);
        internal object Snapshot() => new
        {
            Main = View(Main),Peer = View(Peer),Alias = View(Alias),
            References = new {MainDescriptor = ReferenceEquals(Main.Descriptor,Descriptor),PeerDescriptor = ReferenceEquals(Main.Descriptor,Peer.Descriptor),
                MainDaclInitial = ReferenceEquals(Main.Descriptor.DiscretionaryAcl,Dacl),MainSaclInitial = ReferenceEquals(Main.Descriptor.SystemAcl,Sacl),
                AliasDaclInitial = ReferenceEquals(Alias.Descriptor.DiscretionaryAcl,Dacl),AliasSaclInitial = ReferenceEquals(Alias.Descriptor.SystemAcl,Sacl)}
        };
        private static object View(FacadeContracts.Wrapper wrapper) => new
        { Descriptor = Describe(new A.RawSecurityDescriptor(wrapper.GetSecurityDescriptorBinaryForm(),0)),Flags = wrapper.Flags() };
    }
    internal static void ApplyTo(A.ObjectSecurity wrapper,Input input,SddlReplacementContracts.Step step)
    {
        if (step.Name is "protect-preserve" or "unprotect")
        {
            if (input.Audit) wrapper.SetAuditRuleProtection(step.Name == "protect-preserve",true);
            else wrapper.SetAccessRuleProtection(step.Name == "protect-preserve",true);
        }
        else if (step.Binary is not null) wrapper.SetSecurityDescriptorBinaryForm(step.Binary,step.Sections);
        else wrapper.SetSecurityDescriptorSddlForm(step.Text!,step.Sections);
    }
    internal static object Observe(int id,Action<Context,SddlReplacementContracts.Step?,bool,bool>? hook = null)
    {
        var input = Inputs().ElementAt(id);var source = input.Source();var saved = (byte[])source.Clone();Context? context = null;
        var imported = Capture(() => {context = new(input,source);hook?.Invoke(context,null,true,true);return context.Snapshot();});
        // Native formatting success distinguishes actual accepted integer encodings from arbitrary opaque bytes.
        var rawExport = input.IntegerCode == 0 ? null : Capture(() => new A.RawSecurityDescriptor(source,0).GetSddlForm(AccessControlSections.All));
        var steps = new List<object>();
        if (context is not null) foreach (var step in Steps(input))
        {
            var supplied = step.Binary is null ? null : (byte[])step.Binary.Clone();var before = context.Snapshot();hook?.Invoke(context,step,true,false);
            var success = false;var result = Capture(() => {context.Apply(step);success = true;return null;});hook?.Invoke(context,step,false,success);
            steps.Add(new {step.Name,Sections = (int)step.Sections,BinaryHex = supplied is null ? null : Convert.ToHexString(supplied),
                TextUtf16Hex = step.Text is null ? null : SddlBoundaryInputs.Utf16Hex(step.Text),Before = before,Result = result,After = context.Snapshot(),
                SuppliedBinaryUnchanged = supplied is null ? (bool?)null : supplied.AsSpan().SequenceEqual(step.Binary)});
        }
        return new {Kind = "Observation",Case = id,input.Label,input.Audit,input.From,input.To,input.IntegerCode,
            SourceHex = Convert.ToHexString(saved),Import = imported,RawExport = rawExport,Steps = steps,SourceUnchanged = saved.AsSpan().SequenceEqual(source)};
    }
    internal static void Write(string path,int start,int count)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (start < 0 || start >= Count || count is < 1 or > 16) throw new ArgumentOutOfRangeException();
        var end = Math.Min(Count,start + count);Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var output = new StreamWriter(new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) {AutoFlush = true};
        output.WriteLine(JsonSerializer.Serialize(new {Kind = "Header",Schema = "sddl-replacement-states-v1",Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription,TotalCases = Count,Start = start,Count = end - start,
            Scope = "18 absent/null/empty transitions and six retained Int8/16/32 controls; shared aliases, protection and rollback; no lookup/persistence."}));
        for (var i = start; i < end; i++) output.WriteLine(JsonSerializer.Serialize(Observe(i)));
    }
}
