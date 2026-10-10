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
    public static IEnumerable<object[]> SelectedReplacementCases() => Enumerable.Range(0,72).Select(i => new object[] {i});

    private sealed record ReplacementState(FacadeContracts.Wrapper Wrapper, A.CommonSecurityDescriptor Descriptor,
        A.DiscretionaryAcl Dacl, A.SystemAcl Sacl, A.InteropSnapshot Snapshot, byte[] Raw, byte[] Original,
        byte[] Live, SecurityMasks Intent, long Version, long ReadVersion, bool[] Flags,
        C.AclMutationEngine State, C.AclMutationEngine? DaclProvenance, C.AclMutationEngine? SaclProvenance);

    [Theory]
    [MemberData(nameof(SelectedReplacementCases))]
    public void Selected_acl_replacement_preserves_unselected_raw_prior_intent_aliases_and_atomic_failures(int id)
    {
        ReplacementState[]? before = null;
        var observed = JsonSerializer.SerializeToNode(SddlReplacementContracts.Observe(id,(context,step,starting,success) =>
        {
            var wrappers = new[] {context.Main,context.Peer,context.Alias}.Where(w => w is not null).Cast<FacadeContracts.Wrapper>().ToArray();
            if (starting)
            {
                if (before is null) Assert.Equal(context.Input.Source(),context.Main.Descriptor.MutationState.Descriptor.GetBinaryForm());
                before = wrappers.Select(w => new ReplacementState(w,w.Descriptor,w.Descriptor.DiscretionaryAcl!,w.Descriptor.SystemAcl!,
                    w.CaptureInteropSnapshot(),w.Descriptor.MutationState.Descriptor.GetBinaryForm(),w.Descriptor.MutationState.OriginalDescriptor.GetBinaryForm(),
                    w.GetSecurityDescriptorBinaryForm(),w.Descriptor.MutationState.WriteIntent,w.Descriptor.MutationVersion,w.ReadVersion,w.Flags(),w.Descriptor.MutationState,
                    w.Descriptor.DiscretionaryAcl!.RetainedMutation,w.Descriptor.SystemAcl!.RetainedMutation)).ToArray();
                return;
            }
            Assert.NotNull(before);
            var malformed = step.Name is "malformed-after-success" or "malformed-unselected-text" or "malformed-unselected-binary";
            var forbidden = context.Input.Opposite != "ordinary" && step.Name is "compound-assignment" or "replace-opposite";
            Assert.Equal(!malformed && !forbidden,success);
            foreach (var previous in before)
            {
                var wrapper = previous.Wrapper; var descriptor = wrapper.Descriptor;
                var current = wrapper.CaptureInteropSnapshot(); var raw = descriptor.MutationState.Descriptor.GetBinaryForm();
                Assert.Same(previous.Descriptor,descriptor);
                Assert.Equal(previous.Original,descriptor.MutationState.OriginalDescriptor.GetBinaryForm());
                Assert.Equal(previous.Snapshot.Source,current.Source); Assert.Equal(previous.Snapshot.Attachment,current.Attachment);
                Assert.Equal(previous.Snapshot.Retrieved,current.Retrieved); Assert.Equal(previous.ReadVersion,wrapper.ReadVersion);
                Assert.False(wrapper.HasRawReadContext);
                if (!success)
                {
                    Assert.Equal(previous.Raw,raw); Assert.Equal(previous.Live,wrapper.GetSecurityDescriptorBinaryForm());
                    Assert.Equal(previous.Intent,descriptor.MutationState.WriteIntent); Assert.Equal(previous.Version,descriptor.MutationVersion);
                    Assert.Equal(previous.Flags,wrapper.Flags()); Assert.Equal(previous.Snapshot.Generation,current.Generation);
                    Assert.Equal(previous.Snapshot.Pending,current.Pending);
                    Assert.Same(previous.Dacl,descriptor.DiscretionaryAcl); Assert.Same(previous.Sacl,descriptor.SystemAcl);
                    Assert.Same(previous.State,descriptor.MutationState);
                    Assert.Same(previous.DaclProvenance,descriptor.DiscretionaryAcl!.RetainedMutation);
                    Assert.Same(previous.SaclProvenance,descriptor.SystemAcl!.RetainedMutation);
                    continue;
                }
                var alias = ReferenceEquals(wrapper,context.Alias);
                var editingAlias = step.Name == "edit-shared-old-acl";
                var permitted = editingAlias ? (alias ? step.Sections : AccessControlSections.None)
                    : alias ? AccessControlSections.None : step.Sections;
                var changed = SecurityMasks.None;
                foreach (var (field,section,mask,controlMask) in new[] {
                    (4,AccessControlSections.Owner,SecurityMasks.Owner,0), (8,AccessControlSections.Group,SecurityMasks.Group,0),
                    (12,AccessControlSections.Audit,SecurityMasks.Sacl,0x2a10), (16,AccessControlSections.Access,SecurityMasks.Dacl,0x1504) })
                {
                    var oldBytes = ReplacementComponent(previous.Raw,field); var newBytes = ReplacementComponent(raw,field);
                    var controlChanged = ((BinaryPrimitives.ReadUInt16LittleEndian(previous.Raw.AsSpan(2))
                        ^ BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(2))) & controlMask) != 0;
                    if (!oldBytes.AsSpan().SequenceEqual(newBytes) || controlChanged) changed |= mask;
                    if ((permitted & section) == 0)
                    { Assert.Equal(oldBytes,newBytes); Assert.False(controlChanged); }
                    else if (!editingAlias)
                    {
                        var supplied = step.Binary ?? Image(new A.RawSecurityDescriptor(step.Text!));
                        Assert.Equal(ReplacementComponent(supplied,field),newBytes);
                    }
                }
                Assert.Equal(previous.Intent | changed,descriptor.MutationState.WriteIntent);
                Assert.True(descriptor.MutationVersion >= previous.Version);
                if (step.Name == "identical-all") Assert.Equal(previous.Snapshot.Generation,current.Generation);
                if (changed != SecurityMasks.None) Assert.True(descriptor.MutationVersion > previous.Version);
                if ((permitted & AccessControlSections.Access) == 0) Assert.Same(previous.Dacl,descriptor.DiscretionaryAcl);
                if ((permitted & AccessControlSections.Audit) == 0) Assert.Same(previous.Sacl,descriptor.SystemAcl);
                if (alias && !editingAlias || !alias && editingAlias)
                { Assert.Equal(previous.Raw,raw); Assert.Equal(previous.Live,wrapper.GetSecurityDescriptorBinaryForm()); Assert.Equal(previous.Flags,wrapper.Flags()); }
            }
            if (context.Peer is not null)
            {
                Assert.Same(context.Main.Descriptor,context.Peer.Descriptor);
                Assert.Equal(context.Main.GetSecurityDescriptorBinaryForm(),context.Peer.GetSecurityDescriptorBinaryForm());
                Assert.Same(context.InitialDacl,context.Alias!.Descriptor.DiscretionaryAcl);
                Assert.Same(context.InitialSacl,context.Alias.Descriptor.SystemAcl);
            }
        }))!;
        Assert.Null(observed["Import"]!["ExceptionType"]);
        Assert.True(observed["SourceUnchanged"]!.GetValue<bool>());
        foreach (var step in observed["Steps"]!.AsArray())
            if (step!["SuppliedBinaryUnchanged"] is not null) Assert.True(step["SuppliedBinaryUnchanged"]!.GetValue<bool>());
        VerifyReplacementNative(id,observed);
        static byte[] Image(A.RawSecurityDescriptor descriptor) { var bytes = new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);return bytes; }
    }
    private static byte[] ReplacementComponent(byte[] bytes,int field)
    {
        var offset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(field));
        if (offset == 0) return [];
        var length = field < 12 ? 8 + bytes[offset + 1] * 4 : BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 2));
        return bytes.AsSpan(offset,length).ToArray();
    }

    private static readonly Lazy<JsonArray> ReplacementNative = new(() =>
    {
#if NET10_0_OR_GREATER
        const string resource = "AclOracle.Replacement.net10.json.gz";
#else
        const string resource = "AclOracle.Replacement.net8.json.gz";
#endif
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream(resource)!;
        using var gzip = new GZipStream(stream,CompressionMode.Decompress);
        return JsonNode.Parse(gzip)!["Observations"]!.AsArray();
    });
    private static readonly Lazy<JsonArray> ReplacementRefusals = new(() =>
    {
        using var stream = typeof(PortableSecurityFoundationTests).Assembly.GetManifestResourceStream("AclOracle.Replacement.Refusals.json")!;
        return JsonNode.Parse(stream)!.AsArray();
    });

    [Fact]
    public void Selected_replacement_inventory_keeps_all_cases_steps_and_refusals_explicit()
    {
        var inputs = SddlReplacementContracts.Inputs().ToArray();
        Assert.Equal(72,inputs.Length); Assert.Equal(64,inputs.Count(i => !i.Shared)); Assert.Equal(8,inputs.Count(i => i.Shared));
        Assert.Equal(136,inputs.Sum(i => SddlReplacementContracts.Steps(i).Count()));
        Assert.Equal(Enumerable.Range(0,72),ReplacementNative.Value.Select(r => r!["Case"]!.GetValue<int>()));
        foreach (var (input,row) in inputs.Zip(ReplacementNative.Value))
        {
            Assert.Equal(input.Label,row!["Label"]!.GetValue<string>());
            Assert.Equal(Convert.ToHexString(input.Source()),row["SourceHex"]!.GetValue<string>());
            Assert.Equal(SddlReplacementContracts.Steps(input).Select(s => s.Name),row["Steps"]!.AsArray().Select(s => s!["Name"]!.GetValue<string>()));
        }
        Assert.Equal(18,ReplacementRefusals.Value.Count);
        Assert.Equal(182,ReplacementRefusals.Value.Sum(p => p!["Facets"]!.AsArray().Count));
        Assert.Equal(ReplacementRefusals.Value.Count,ReplacementRefusals.Value.Select(p => p!["Case"]!.GetValue<int>()).Distinct().Count());
    }

    private static void VerifyReplacementNative(int id,JsonNode actual)
    {
        var expected = ReplacementNative.Value[id]!;
        var unmodified = actual.DeepClone();
        var pin = ReplacementRefusals.Value.SingleOrDefault(p => p!["Case"]!.GetValue<int>() == id);
        if (pin is not null)
        {
            Assert.Equal(expected["Label"]!.GetValue<string>(),pin["Label"]!.GetValue<string>());
            Assert.Equal(pin["NativeObservationSha256"]!.GetValue<string>(),
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expected.ToJsonString()))).ToLowerInvariant());
            Assert.NotEqual("ordinary",expected["Opposite"]!.GetValue<string>());
            Assert.Equal("unreviewed-replacement-atomic-refusal",pin["Classification"]!.GetValue<string>());
            foreach (var facet in pin["Facets"]!.AsArray())
            {
                var path = facet!["Path"]!.GetValue<string>().Split('/');
                Assert.Equal("Steps",path[0]); var index = int.Parse(path[1]);
                var step = unmodified["Steps"]![index]!;
                Assert.Contains(path[2],new[] {"Result","After"});
                Assert.Contains(step["Name"]!.GetValue<string>(),new[] {"compound-assignment","replace-opposite"});
                Assert.Equal("System.InvalidOperationException",step["Result"]!["ExceptionType"]!.GetValue<string>());
                Assert.Null(expected["Steps"]![index]!["Result"]!["ExceptionType"]);
                Assert.True(JsonNode.DeepEquals(step["Before"],step["After"]));
                JsonNode target = actual, native = expected;
                foreach (var part in path[..^1])
                { target = target is JsonArray ? target[int.Parse(part)]! : target[part]!; native = native is JsonArray ? native[int.Parse(part)]! : native[part]!; }
                var key = path[^1];
                var portableValue = target is JsonArray ? target[int.Parse(key)] : target[key];
                Assert.True(JsonNode.DeepEquals(facet["PortableValue"],portableValue),$"Pinned portable facet {id}/{facet["Path"]}");
                var nativeValue = native is JsonArray ? native[int.Parse(key)] : native[key];
                Assert.True(JsonNode.DeepEquals(facet["NativeValue"],nativeValue));
                if (target is JsonArray array) array[int.Parse(key)] = nativeValue?.DeepClone(); else target[key] = nativeValue?.DeepClone();
            }
        }
        Assert.True(JsonNode.DeepEquals(expected,actual),$"Selected replacement mismatch: {id}");
    }
}
