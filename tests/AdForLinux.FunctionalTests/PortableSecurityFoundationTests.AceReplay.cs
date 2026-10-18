// Numeric framework enums only; all ACE and SID execution below is portable.
#pragma warning disable CA1416
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;
using SecurityIdentifier = AdForLinux.Security.Principal.SecurityIdentifier;
using GenericAce = AdForLinux.Security.AccessControl.GenericAce;
using CustomAce = AdForLinux.Security.AccessControl.CustomAce;
using QualifiedAce = AdForLinux.Security.AccessControl.QualifiedAce;
using CommonAce = AdForLinux.Security.AccessControl.CommonAce;
using ObjectAce = AdForLinux.Security.AccessControl.ObjectAce;
using CompoundAce = AdForLinux.Security.AccessControl.CompoundAce;

namespace AdForLinux.FunctionalTests;

public partial class PortableSecurityFoundationTests
{
    private static bool IsAceFoundationOperation(string operation) => operation.StartsWith("ace-", StringComparison.Ordinal);

    private static object? ReplayAceFoundation(string operation, JsonElement arguments)
    {
        Func<object?>? selected = null;
        RegisterAceFoundation((key, input, execute) =>
        {
            if (key != operation) return;
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(JsonSerializer.Serialize(input)), JsonNode.Parse(arguments.GetRawText())),
                $"ACE contract arguments changed for {operation}.");
            selected = execute;
        });
        Assert.NotNull(selected);
        return selected();
    }

    private static void RegisterAceFoundation(Action<string, object, Func<object?>> record)
    {
        foreach (var type in new[] { 0, 4, 16, 17, 21, 255 })
        foreach (var length in new[] { -1, 0, 1, 4, 65528, 65532 })
        {
            var input = new { Type = type, Length = length, Flags = 255 };
            record($"ace-custom-{type}-{length}", input, () =>
                AceFoundationSnapshot(new CustomAce((AceType)type, (AceFlags)255, length < 0 ? null : new byte[length])));
        }
        foreach (var hex in new[]
        {
            "FF000400", "FF20080001020304", "FF000000", "FF000300", "FF00050001", "FF000800",
            "00000400", "04000400", "1100080001020304", "1500080001020304",
        })
            record($"ace-parse-{hex}", new { Hex = hex, Offset = 0 }, () => AceFoundationSnapshot(GenericAce.CreateFromBinaryForm(Convert.FromHexString(hex), 0)));
        foreach (var offset in new[] { -1, 0, 1, 4, int.MaxValue })
        {
            record($"ace-write-offset-{offset}", new { Offset = offset, BufferLength = 8 }, () =>
            {
                var ace = new CustomAce((AceType)255, AceFlags.None, new byte[4]);
                var bytes = Enumerable.Repeat((byte)0xCC, 8).ToArray();
                ace.GetBinaryForm(bytes, offset);
                return Convert.ToHexString(bytes);
            });
            record($"ace-read-offset-{offset}", new { Offset = offset, Hex = "FF000400FF000400" }, () =>
                AceFoundationSnapshot(GenericAce.CreateFromBinaryForm(Convert.FromHexString("FF000400FF000400"), offset)));
        }
        record("ace-write-null", new { Null = true }, () => { new CustomAce((AceType)255, AceFlags.None, null).GetBinaryForm(null!, 0); return null; });
        record("ace-read-null", new { Null = true }, () => AceFoundationSnapshot(GenericAce.CreateFromBinaryForm(null!, 0)));
        record("ace-custom-live-opaque-deep-copy", new { Hex = "01020304" }, () =>
        {
            var opaque = new byte[] { 1, 2, 3, 4 };
            var ace = new CustomAce((AceType)255, (AceFlags)255, opaque);
            var copy = (CustomAce)ace.Copy();
            var constructorAliases = ReferenceEquals(opaque, ace.GetOpaque());
            var copyAliases = ReferenceEquals(ace.GetOpaque(), copy.GetOpaque());
            opaque[0] = 0xFE;
            return new { ConstructorAliases = constructorAliases, CopyAliases = copyAliases, Original = AceFoundationSnapshot(ace), Copy = AceFoundationSnapshot(copy), Equal = ace.Equals(copy) };
        });
        foreach (var qualifier in new[] { AceQualifier.AccessAllowed, AceQualifier.AccessDenied, AceQualifier.SystemAudit, AceQualifier.SystemAlarm })
        foreach (var callback in new[] { false, true })
        foreach (var objectAce in new[] { false, true })
            record($"ace-qualified-{qualifier}-{callback}-{objectAce}", new { Qualifier = (int)qualifier, Callback = callback, Object = objectAce }, () =>
            {
                var sid = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
                var opaque = new byte[] { 0xAA, 0, 0xBB, 0 };
                QualifiedAce ace = objectAce
                    ? new ObjectAce((AceFlags)0xDF, qualifier, 0x30, sid, unchecked((ObjectAceFlags)0x80000003),
                        Guid.Parse("11111111-1111-1111-1111-111111111111"), Guid.Empty, callback, opaque)
                    : new CommonAce((AceFlags)0xDF, qualifier, unchecked((int)0x80000001), sid, callback, opaque);
                var copy = ace.Copy();
                return new { Original = AceFoundationSnapshot(ace), Copy = AceFoundationSnapshot(copy), Equal = ace.Equals(copy), Callback = ace.IsCallback, Opaque = Convert.ToHexString(ace.GetOpaque()!) };
            });
        record("ace-compound", new { Mask = 0x12345678 }, () => AceFoundationSnapshot(new CompoundAce(AceFlags.Inherited, 0x12345678, CompoundAceType.Impersonation, new SecurityIdentifier("S-1-1-0"))));
    }

    private static object AceFoundationSnapshot(GenericAce ace)
    {
        var bytes = new byte[ace.BinaryLength];
        ace.GetBinaryForm(bytes, 0);
        return new
        {
            Type = ace.GetType().Name, AceType = (byte)ace.AceType, Flags = (byte)ace.AceFlags,
            Length = ace.BinaryLength, Hex = Convert.ToHexString(bytes), Hash = ace.GetHashCode(),
            ace.IsInherited, Inheritance = (int)ace.InheritanceFlags, Propagation = (int)ace.PropagationFlags,
            Audit = (int)ace.AuditFlags,
        };
    }
}
