#pragma warning disable CA1416 // Framework enum values; only the portable codec is executed.
using System.Security.AccessControl;
using AdForLinux.Security.Principal;
using A = AdForLinux.Security.AccessControl;
using Xunit;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    [Fact]
    public void Conditional_export_never_loses_mutated_or_unexplained_payload_bytes()
    {
        var descriptor = new A.RawSecurityDescriptor("D:(XA;;RP;;;WD;(@User.Age >= 18))");
        var original = ((A.QualifiedAce)descriptor.DiscretionaryAcl![0]).GetOpaque()!;
        foreach (var position in Enumerable.Range(0, original.Length))
        foreach (var value in new byte[] { 0, 1, 4, 0x10, 0x50, 0x80, 0xff })
        {
            var payload = (byte[])original.Clone(); payload[position] = value;
            AssertPreservedCondition(payload);
        }
        foreach (var extra in new[] { new byte[4], new byte[] { 1, 2, 3, 4 }, original })
            AssertPreservedCondition(original.Concat(extra).ToArray());
    }

    [Fact]
    public void No_guid_object_callback_export_refusal_retains_its_native_extra_bytes()
    {
        var descriptor = new A.RawSecurityDescriptor("D:(ZA;;RP;;;WD;(@User.Age == 1))");
        var before = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(before, 0);
        Assert.Throws<NotSupportedException>(() => descriptor.GetSddlForm(AccessControlSections.All));
        var after = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(after, 0);
        Assert.Equal(before, after);
        var copy = new A.RawSecurityDescriptor(before, 0);
        copy.GetBinaryForm(after, 0); Assert.Equal(before, after);
    }

    private static void AssertPreservedCondition(byte[] payload)
    {
        var acl = new A.RawAcl(2, 1);
        acl.InsertAce(0, new A.CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 16,
            new SecurityIdentifier("S-1-1-0"), true, payload));
        var descriptor = new A.RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, acl);
        var before = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(before, 0);
        string? text = null;
        var error = Record.Exception(() => text = descriptor.GetSddlForm(AccessControlSections.All));
        if (error is null)
        {
            var parsed = new A.RawSecurityDescriptor(text!);
            Assert.Equal(payload, ((A.QualifiedAce)parsed.DiscretionaryAcl![0]).GetOpaque());
        }
        else Assert.IsType<NotSupportedException>(error);
        var after = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(after, 0);
        Assert.Equal(before, after);
    }

    [Fact]
    public void Resource_values_roundtrip_binary_without_export_or_aliasing()
    {
        var descriptor = new A.RawSecurityDescriptor("S:(RA;;;;;WD;(\"Sid\",TD,0,WD,S-1-5-32-544))");
        var bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        var copy = new A.RawSecurityDescriptor(bytes, 0);
        var expected = (byte[])bytes.Clone(); Array.Fill(bytes, (byte)0);
        var actual = new byte[copy.BinaryLength]; copy.GetBinaryForm(actual, 0);
        Assert.Equal(expected, actual);
        Assert.Throws<NotSupportedException>(() => copy.GetSddlForm(AccessControlSections.All));
        copy.GetBinaryForm(actual, 0); Assert.Equal(expected, actual);
    }
}
