#pragma warning disable CA1416
using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AdForLinux.DirectoryServices;
using Xunit;
using A = AdForLinux.Security.AccessControl;
using C = AdForLinux.DirectoryServices.Security.Core;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    public static IEnumerable<object[]> ReplacementStateCases() => Enumerable.Range(0,SddlReplacementStates.Count).Select(i => new object[] {i});
    public static IEnumerable<object[]> ReplacementCoverageCases() => Enumerable.Range(0,SddlReplacementStates.Count)
        .SelectMany(i => new[] {true,false}.Select(target => new object[] {i,target}));
    private sealed record StateBoundary(A.ObjectSecurity Wrapper,A.CommonSecurityDescriptor Descriptor,A.DiscretionaryAcl? Dacl,A.SystemAcl? Sacl,
        A.InteropSnapshot Snapshot,C.AclMutationEngine Engine,C.AclMutationEngine? DaclProvenance,C.AclMutationEngine? SaclProvenance,
        SecurityMasks Intent,SecurityMasks Assignment,long ReadVersion,bool[]? Dirty)
    {
        internal static StateBoundary Take(A.ObjectSecurity wrapper)
        {
            var d = wrapper._securityDescriptor;
            return new(wrapper,d,d.DiscretionaryAcl,d.SystemAcl,wrapper.CaptureInteropSnapshot(),d.MutationState,
                d.DiscretionaryAcl?.RetainedMutation,d.SystemAcl?.RetainedMutation,d.MutationState.WriteIntent,
                wrapper.AssignmentSections,wrapper.ReadVersion,(wrapper as FacadeContracts.Wrapper)?.Flags());
        }
        internal void Check(AccessControlSections permitted,bool success,bool identical)
        {
            var now = Wrapper.CaptureInteropSnapshot();var d = Wrapper._securityDescriptor;
            Assert.Same(Descriptor,d);Assert.Equal(Snapshot.Original,now.Original);
            Assert.Equal(Snapshot.Source,now.Source);Assert.Equal(Snapshot.Attachment,now.Attachment);
            Assert.Equal(Snapshot.Retrieved,now.Retrieved);Assert.Equal(ReadVersion,Wrapper.ReadVersion);
            Assert.False(Wrapper.HasRawReadContext);Assert.Null(Wrapper.CaptureIdentityRead().Resolver);
            if (!success)
            {
                Assert.Equal(Snapshot.Raw,now.Raw);Assert.Equal(Snapshot.Observable,now.Observable);
                Assert.Equal(Snapshot.Generation,now.Generation);Assert.Equal(Snapshot.Pending,now.Pending);
                Assert.Equal(Intent,d.MutationState.WriteIntent);Assert.Equal(Assignment,Wrapper.AssignmentSections);
                Assert.Same(Engine,d.MutationState);Assert.Same(Dacl,d.DiscretionaryAcl);Assert.Same(Sacl,d.SystemAcl);
                Assert.Same(DaclProvenance,d.DiscretionaryAcl?.RetainedMutation);Assert.Same(SaclProvenance,d.SystemAcl?.RetainedMutation);
                if (Dirty is not null) Assert.Equal(Dirty,((FacadeContracts.Wrapper)Wrapper).Flags());
                return;
            }
            var changed = SecurityMasks.None;
            foreach (var (field,section,mask,flags) in new[] {
                (4,AccessControlSections.Owner,SecurityMasks.Owner,0),(8,AccessControlSections.Group,SecurityMasks.Group,0),
                (12,AccessControlSections.Audit,SecurityMasks.Sacl,0x2a10),(16,AccessControlSections.Access,SecurityMasks.Dacl,0x1504) })
            {
                var prior = ReplacementComponent(Snapshot.Raw,field);var current = ReplacementComponent(now.Raw,field);
                var controlChange = (BinaryPrimitives.ReadUInt16LittleEndian(Snapshot.Raw.AsSpan(2)) ^ BinaryPrimitives.ReadUInt16LittleEndian(now.Raw.AsSpan(2))) & flags;
                if (!prior.AsSpan().SequenceEqual(current) || controlChange != 0) changed |= mask;
                if ((section & permitted) == 0) {Assert.Equal(prior,current);Assert.Equal(0,controlChange);}
            }
            Assert.Equal(Intent | changed,d.MutationState.WriteIntent);
            Assert.Equal(d.MutationState.WriteIntent,now.Pending);
            if ((permitted & AccessControlSections.Access) == 0) Assert.Same(Dacl,d.DiscretionaryAcl);
            if ((permitted & AccessControlSections.Audit) == 0) Assert.Same(Sacl,d.SystemAcl);
            if (identical || permitted == AccessControlSections.None)
            {Assert.Equal(Snapshot.Raw,now.Raw);Assert.Equal(Snapshot.Generation,now.Generation);}
        }
    }
    [Theory]
    [MemberData(nameof(ReplacementStateCases))]
    public void Replacement_state_transitions_match_measured_native_with_exact_preservation_pins(int id)
    {
        StateBoundary[]? before = null;
        var actual = JsonSerializer.SerializeToNode(SddlReplacementStates.Observe(id,(context,step,starting,success) =>
        {
            if (step is null)
            {
                Assert.Equal(context.Input.Source(),context.Main.CaptureInteropSnapshot().Raw);
                Assert.Equal(context.Input.Source(),context.Main.CaptureInteropSnapshot().Original);
                return;
            }
            if (starting) {before = new[] {context.Main,context.Peer,context.Alias}.Select(StateBoundary.Take).ToArray();return;}
            Assert.NotNull(before);
            for (var i = 0; i < before.Length; i++) before[i].Check(i == 2 ? AccessControlSections.None : step.Sections,success,step.Name == "identical-all");
            Assert.Same(context.Main.Descriptor,context.Peer.Descriptor);
            Assert.Equal(context.Main.GetSecurityDescriptorBinaryForm(),context.Peer.GetSecurityDescriptorBinaryForm());
            Assert.Same(context.Dacl,context.Alias.Descriptor.DiscretionaryAcl);Assert.Same(context.Sacl,context.Alias.Descriptor.SystemAcl);
        }))!;
        Assert.Null(actual["Import"]!["ExceptionType"]);Assert.True(actual["SourceUnchanged"]!.GetValue<bool>());
        foreach (var step in actual["Steps"]!.AsArray()) if (step!["SuppliedBinaryUnchanged"] is not null) Assert.True(step["SuppliedBinaryUnchanged"]!.GetValue<bool>());
        VerifyStateNative(id,actual);
    }
    [Theory]
    [MemberData(nameof(ReplacementCoverageCases))]
    public void Partial_retrieval_keeps_coverage_separate_from_replacement_intent(int id,bool targetRetrieved)
    {
        var input = SddlReplacementStates.Inputs().ElementAt(id);var raw = input.Source();
        var mask = input.Audit == targetRetrieved ? SecurityMasks.Sacl : SecurityMasks.Dacl;
        var context = new SddlReplacementStates.Context(input,raw);
        var main = new ActiveDirectorySecurity(context.Descriptor,mask);
        Assert.Equal(raw,main.CaptureInteropSnapshot().Raw);Assert.Equal(mask,main.CaptureInteropSnapshot().Retrieved);
        foreach (var step in SddlReplacementStates.Steps(input))
        {
            var before = new A.ObjectSecurity[] {main,context.Peer,context.Alias}.Select(StateBoundary.Take).ToArray();
            var error = Record.Exception(() => SddlReplacementStates.ApplyTo(main,input,step));
            // Detached coverage does not invent server-read authority. Explicit setters
            // may retain intent outside coverage; importing it elsewhere is a separate gate.
            var expectedRefusal = step.Name == "malformed-compound" || input.IntegerCode != 0 && step.Name == "compound-replace"
                || step.Name == "identical-all" && input.From == "empty" || step.Name == "selected-replace" && input.To == "null";
            Assert.Equal(expectedRefusal,error is not null);
            if (step.Name == "malformed-compound") Assert.IsType<ArgumentException>(error);
            else if (expectedRefusal && step.Name == "compound-replace") Assert.IsType<InvalidOperationException>(error);
            else if (expectedRefusal) Assert.IsType<NotSupportedException>(error);
            for (var i = 0; i < before.Length; i++) before[i].Check(i == 2 ? AccessControlSections.None : step.Sections,error is null,step.Name == "identical-all");
            Assert.Equal(mask,main.CaptureInteropSnapshot().Retrieved);
            Assert.Equal(main.PendingWriteSections,main.CaptureInteropSnapshot().Pending);
            Assert.Equal(context.Main.GetSecurityDescriptorBinaryForm(),main.GetSecurityDescriptorBinaryForm());
        }
    }
    [Fact]
    public void Replacement_state_inventory_distinguishes_retained_integer_encodings_and_controls()
    {
        var inputs = SddlReplacementStates.Inputs().ToArray();
        Assert.Equal(16,StatePins.Value.Count);Assert.Equal(530,StatePins.Value.Sum(p => p!["Facets"]!.AsArray().Count));
        Assert.Equal(24,inputs.Length);Assert.Equal(18,inputs.Count(i => i.IntegerCode == 0));
        Assert.Equal(6,inputs.Count(i => i.IntegerCode != 0));Assert.Equal(168,inputs.Sum(i => SddlReplacementStates.Steps(i).Count()));
        Assert.Equal(Enumerable.Range(0,24),StateNative.Value.Select(r => r!["Case"]!.GetValue<int>()));
        foreach (var (input,row) in inputs.Zip(StateNative.Value))
        {
            Assert.Equal(input.Label,row!["Label"]!.GetValue<string>());
            Assert.Equal(Convert.ToHexString(input.Source()),row["SourceHex"]!.GetValue<string>());
            if (input.IntegerCode != 0)
            {
                Assert.Null(row["RawExport"]!["ExceptionType"]);
                Assert.Contains("@USER.Level >= 2",row["RawExport"]!["Outcome"]!.GetValue<string>());
            }
        }
    }
    private static readonly Lazy<JsonArray> StateNative = new(() =>
    {
#if NET10_0_OR_GREATER
        const string name = "AclOracle.ReplacementStates.net10.json.gz";
#else
        const string name = "AclOracle.ReplacementStates.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(name)!;
        using var gzip = new GZipStream(stream,CompressionMode.Decompress);return JsonNode.Parse(gzip)!["Observations"]!.AsArray();
    });
    private static readonly Lazy<JsonArray> StatePins = new(() =>
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.ReplacementStates.Refusals.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    });
    private static void VerifyStateNative(int id,JsonNode actual)
    {
        var native = StateNative.Value[id]!;var pin = StatePins.Value.SingleOrDefault(p => p!["Case"]!.GetValue<int>() == id);
        if (pin is not null)
        {
            var original = actual.DeepClone();
            foreach (var refusal in pin["RefusedSteps"]!.AsArray())
            {
                var index = refusal!["Step"]!.GetValue<int>();var step = original["Steps"]![index]!;
                Assert.Null(native["Steps"]![index]!["Result"]!["ExceptionType"]);
                Assert.True(JsonNode.DeepEquals(step["Before"],step["After"]));
                if (refusal["Reason"]!.GetValue<string>() == "supplied-nonassignable-auto-inherit-request")
                {
                    Assert.Equal("System.NotSupportedException",step["Result"]!["ExceptionType"]!.GetValue<string>());
                    Assert.Contains(step["Name"]!.GetValue<string>(),new[] {"identical-all","selected-replace"});
                    var supplied = Convert.FromHexString(step["BinaryHex"]!.GetValue<string>());
                    Assert.NotEqual(0,BinaryPrimitives.ReadUInt16LittleEndian(supplied.AsSpan(2)) & 0x300);
                }
                else
                {
                    Assert.Equal("unreviewed-retained-integer-replacement",refusal["Reason"]!.GetValue<string>());
                    Assert.Equal("compound-replace",step["Name"]!.GetValue<string>());
                    Assert.InRange(native["IntegerCode"]!.GetValue<int>(),1,3);
                    Assert.Equal("System.InvalidOperationException",step["Result"]!["ExceptionType"]!.GetValue<string>());
                }
            }
            Assert.Equal(pin["NativeObservationSha256"]!.GetValue<string>(),Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(native.ToJsonString()))).ToLowerInvariant());
            foreach (var facet in pin["Facets"]!.AsArray())
            {
                var path = facet!["Path"]!.GetValue<string>().Split('/');
                if (path[0] == "RawExport")
                {
                    Assert.InRange(native["IntegerCode"]!.GetValue<int>(),1,3);
                    Assert.Equal("retained-integer-encoding-outside-lossless-export-subset",facet["Reason"]!.GetValue<string>());
                    Assert.Null(native["RawExport"]!["ExceptionType"]);
                    Assert.Equal("System.NotSupportedException",original["RawExport"]!["ExceptionType"]!.GetValue<string>());
                }
                else
                {
                    Assert.Equal("Steps",path[0]);Assert.Contains(path[2],new[] {"Before","Result","After"});
                    var index = int.Parse(path[1]);var cause = facet["CauseStep"]!.GetValue<int>();
                    Assert.True(cause < index || cause == index && path[2] != "Before");
                    var refusal = Assert.Single(pin["RefusedSteps"]!.AsArray(),r => r!["Step"]!.GetValue<int>() == cause)!;
                    Assert.Equal(cause == index ? refusal["Reason"]!.GetValue<string>() : "state-carried-from-prior-refusal",facet["Reason"]!.GetValue<string>());
                }
                JsonNode portableParent = actual,nativeParent = native;
                foreach (var part in path[..^1]) {portableParent = Get(portableParent,part)!;nativeParent = Get(nativeParent,part)!;}
                var key = path[^1];var portableValue = Get(portableParent,key);var nativeValue = Get(nativeParent,key);
                Assert.True(portableValue is null or JsonValue);Assert.True(nativeValue is null or JsonValue);
                Assert.True(JsonNode.DeepEquals(facet["PortableValue"],portableValue),$"Portable pin {id}/{facet["Path"]}");
                Assert.True(JsonNode.DeepEquals(facet["NativeValue"],nativeValue));
                if (portableParent is JsonArray array) array[int.Parse(key)] = nativeValue?.DeepClone();else portableParent[key] = nativeValue?.DeepClone();
            }
        }
        Assert.True(JsonNode.DeepEquals(native,actual),$"Replacement state mismatch {id}");
        static JsonNode? Get(JsonNode node,string part) => node is JsonArray ? node[int.Parse(part)] : node[part];
    }
}
