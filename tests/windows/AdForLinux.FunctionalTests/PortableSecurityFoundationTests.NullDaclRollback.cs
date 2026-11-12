#pragma warning disable CA1416
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Nodes;
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;
using Xunit;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static void AssertNullDaclAtomicFailure(JsonElement row, object? outcome)
    {
        var scenario = row.GetProperty("Case").GetInt32() - 3517;
        Assert.InRange(scenario, 0, 39);
        Assert.Equal("FacadeNullDaclFailure", row.GetProperty("Operation").GetString());
        Assert.Equal(scenario, row.GetProperty("Arguments").GetProperty("Scenario").GetInt32());
        var expected = JsonNode.Parse(row.GetProperty("Outcome").GetRawText())!;
        var zeroMask = scenario % 20 is >= 8 and < 16;
        Assert.Equal(zeroMask ? "System.ArgumentException" : "System.ArgumentNullException",
            expected["Result"]!["ExceptionType"]!.GetValue<string>());
        Assert.Equal(zeroMask ? "accessMask" : "sid", expected["Result"]!["ParamName"]!.GetValue<string>());
        // Pin both actual Windows images. Only the failed call's materialization
        // differs deliberately; every exception, flag and alias field still compares.
        const string before = "0100008000000000000000000000000000000000";
        const string after = "010004800000000000000000000000001400000004001C000100000000031400FFFFFFFF010100000000000100000000";
        foreach (var (start, end) in new[] { ("Before", "After"), ("AliasBefore", "AliasAfter") })
        {
            Assert.Equal(before, expected[start]!["Hex"]!.GetValue<string>());
            Assert.Equal(after, expected[end]!["Hex"]!.GetValue<string>());
            expected[end]!["Hex"] = before;
            Assert.Equal(expected[start]!.ToJsonString(), expected[end]!.ToJsonString());
        }
        Assert.Equal(expected.ToJsonString(), JsonSerializer.SerializeToNode(outcome)!.ToJsonString());
    }

    [Fact]
    public void Null_dacl_atomic_differences_are_exactly_the_forty_recorded_validation_failures()
    {
        var cases = new HashSet<int>();
        foreach (var recording in ClosureRecordings())
        {
            using var document = JsonDocument.Parse((string)recording[2]);
            var row = document.RootElement;
            if (row.GetProperty("Operation").GetString() != "FacadeNullDaclFailure") continue;
            var id = row.GetProperty("Case").GetInt32(); cases.Add(id);
            AssertNullDaclAtomicFailure(row, FacadeContracts.Execute("FacadeNullDaclFailure",
                row.GetProperty("Arguments").GetProperty("Scenario").GetInt32()));
        }
        Assert.Equal(Enumerable.Range(3517, 40), cases.Order());
    }

    public static IEnumerable<object[]> NullDaclValidationCases()
    {
        foreach (var present in new[] { false, true })
            for (var route = 0; route < 12; route++)
            {
                yield return [present, route, false];
                if (route < 8) yield return [present, route, true];
            }
    }

    [Theory]
    [MemberData(nameof(NullDaclValidationCases))]
    public void Failed_null_dacl_validation_preserves_all_aliases(bool present, int route, bool zeroMask)
    {
        var flags = present ? ControlFlags.DiscretionaryAclPresent : ControlFlags.None;
        var first = new A.CommonSecurityDescriptor(true, true, flags, null, null, null, null);
        var acl = first.DiscretionaryAcl!;
        var second = new A.CommonSecurityDescriptor(true, true, flags, null, null, null, acl);
        var assertFirst = CaptureNullDaclState(first); var assertSecond = CaptureNullDaclState(second);
        var exception = Record.Exception(() => FacadeContracts.NullDaclEdit(acl, route,
            zeroMask ? new SecurityIdentifier("S-1-5-18") : null!, zeroMask ? 0 : 16));
        if (zeroMask) Assert.Equal("accessMask", Assert.IsType<ArgumentException>(exception).ParamName);
        else Assert.Equal("sid", Assert.IsType<ArgumentNullException>(exception).ParamName);
        assertFirst(); assertSecond();
    }

    public static IEnumerable<object[]> NullDaclGrowthCases()
    {
        foreach (var present in new[] { false, true })
            for (var route = 0; route < 16; route++) yield return [present, route];
    }

    [Theory]
    [MemberData(nameof(NullDaclGrowthCases))]
    public void Successful_null_dacl_materialization_reconciles_all_aliases(bool present, int route)
    {
        var flags = present ? ControlFlags.DiscretionaryAclPresent : ControlFlags.None;
        var first = new A.CommonSecurityDescriptor(true, true, flags, null, null, null, null);
        var acl = first.DiscretionaryAcl!;
        var second = new A.CommonSecurityDescriptor(true, true, flags, null, null, null, acl);
        var original = first.MutationState.Descriptor.GetBinaryForm();
        var wrappers = new[] { new FacadeContracts.Wrapper(first), new FacadeContracts.Wrapper(second) };
        if (route < 12) FacadeContracts.NullDaclEdit(acl, route, new SecurityIdentifier("S-1-5-18"), 16);
        else first.SetDiscretionaryAclProtection((route & 1) != 0, (route & 2) != 0);
        Assert.False(acl.EveryOneFullAccessForNullDacl);
        foreach (var wrapper in wrappers)
        {
            var descriptor = wrapper.Descriptor;
            Assert.Same(acl, descriptor.DiscretionaryAcl);
            Assert.NotNull(descriptor.MutationState.Descriptor.Dacl);
            var projected = descriptor.MutationState.GetObservableAcl(SecurityMasks.Dacl)!;
            var bytes = new byte[projected.BinaryLength]; projected.WriteTo(bytes);
            Assert.Equal(A.FacadeMutation.Bytes(acl), bytes);
            Assert.Equal(original, descriptor.MutationState.OriginalDescriptor.GetBinaryForm());
            Assert.True(descriptor.MutationVersion > 0);
            Assert.Equal(SecurityMasks.Dacl, descriptor.ChangesSince(0));
            Assert.Equal(SecurityMasks.Dacl, wrapper.PendingWriteSections);
            Assert.Equal(new[] { false, false, false, false }, wrapper.Flags());
        }
        Assert.False(second.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected));
    }

    [Theory]
    [MemberData(nameof(NullDaclGrowthCases))]
    public void Outer_failure_restores_null_dacl_materialization_and_all_aliases(bool present, int route)
    {
        var flags = present ? ControlFlags.DiscretionaryAclPresent : ControlFlags.None;
        var first = new A.CommonSecurityDescriptor(true, true, flags, null, null, null, null);
        var acl = first.DiscretionaryAcl!;
        var second = new A.CommonSecurityDescriptor(true, true, flags, null, null, null, acl);
        var assertFirst = CaptureNullDaclState(first); var assertSecond = CaptureNullDaclState(second);
        Assert.Throws<InvalidOperationException>(() => A.FacadeMutation.Run(() =>
        {
            if (route < 12) FacadeContracts.NullDaclEdit(acl, route, new SecurityIdentifier("S-1-5-18"), 16);
            else first.SetDiscretionaryAclProtection((route & 1) != 0, (route & 2) != 0);
            Assert.False(acl.EveryOneFullAccessForNullDacl);
            throw new InvalidOperationException("Reject the enclosing operation.");
        }));
        assertFirst(); assertSecond();
    }

    [Theory]
    [MemberData(nameof(NullDaclGrowthCases))]
    public void Refused_null_dacl_growth_preserves_all_aliases(bool present, int route)
    {
        var flags = present ? ControlFlags.DiscretionaryAclPresent : ControlFlags.None;
        var first = new A.CommonSecurityDescriptor(true, true, flags, null, null, null, null);
        var acl = first.DiscretionaryAcl!;
        var input = first.MutationState.Descriptor.GetBinaryForm().Concat(new byte[] { 0xde, 0xad, 0xbe, 0xef }).ToArray();
        var second = new A.CommonSecurityDescriptor(true, true, input, 0);
        second.DiscretionaryAcl = acl;
        var assertFirst = CaptureNullDaclState(first); var assertSecond = CaptureNullDaclState(second);
        // The safe owner is registered first. Its staged publication must roll back
        // when materializing the second owner's synthetic DACL would drop its trailer.
        Assert.Throws<InvalidOperationException>(() =>
        {
            if (route < 12) FacadeContracts.NullDaclEdit(acl, route, new SecurityIdentifier("S-1-5-18"), 16);
            else second.SetDiscretionaryAclProtection((route & 1) != 0, (route & 2) != 0);
        });
        assertFirst(); assertSecond();
    }

    private static Action CaptureNullDaclState(A.CommonSecurityDescriptor descriptor)
    {
        var acl = descriptor.DiscretionaryAcl!;
        var wrapper = new FacadeContracts.Wrapper(descriptor);
        var observable = wrapper.GetSecurityDescriptorBinaryForm();
        var state = descriptor.MutationState; var raw = state.Descriptor.GetBinaryForm();
        var version = descriptor.MutationVersion; var changes = descriptor.ChangesSince(0);
        var flags = wrapper.Flags(); var intent = wrapper.PendingWriteSections;
        var retained = acl.RetainedMutation;
        Assert.True(acl.EveryOneFullAccessForNullDacl);
        return () =>
        {
            // Check raw state first to distinguish an observable-only marker leak.
            Assert.Same(state, descriptor.MutationState);
            Assert.Equal(raw, descriptor.MutationState.Descriptor.GetBinaryForm());
            Assert.Equal(version, descriptor.MutationVersion);
            Assert.Equal(changes, descriptor.ChangesSince(0));
            Assert.Equal(intent, wrapper.PendingWriteSections);
            Assert.Equal(flags, wrapper.Flags());
            Assert.Same(acl, descriptor.DiscretionaryAcl);
            Assert.Same(retained, acl.RetainedMutation);
            Assert.Equal(observable, wrapper.GetSecurityDescriptorBinaryForm());
            Assert.True(acl.EveryOneFullAccessForNullDacl);
        };
    }
}
