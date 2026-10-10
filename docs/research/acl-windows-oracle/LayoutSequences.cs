using System.Buffers.Binary;
using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

internal static partial class SeededSequences
{
    private static void RecordLayoutSequences(List<Observation> observations)
    {
        var baseline = Sd.Build(Sd.U1, Sd.U1, Sd.Acl(4, Sd.Ace(0, 0, 0x10, Sd.U1)), sacl: Sd.Acl(4));
        var fixtures = new List<(string Name, byte[] Raw)>();
        foreach (var fill in new byte[] { 0, 0xA5 })
        {
            fixtures.Add(($"leading-{fill:X2}", Insert(baseline, 20, 4, fill)));
            fixtures.Add(($"intercomponent-{fill:X2}", Insert(baseline, Offset(baseline, 16), 4, fill)));
            fixtures.Add(($"trailing-{fill:X2}", Insert(baseline, baseline.Length, 4, fill)));
        }
        fixtures.Add(("unaligned", Insert(baseline, 20, 1, 0xA5)));
        var shared = baseline.ToArray();
        WriteOffset(shared, 8, Offset(shared, 4)); // Former group bytes remain as an orphan.
        fixtures.Add(("shared-owner-group-with-orphan", shared));
        var embedded = baseline.ToArray();
        WriteOffset(embedded, 4, Offset(embedded, 16) + 16);
        WriteOffset(embedded, 8, Offset(embedded, 16) + 16); // Both standalone SIDs become orphans.
        fixtures.Add(("owner-group-inside-ace-with-orphans", embedded));
        fixtures.Add(("absent-sections", Insert(Sd.Build(Sd.U1, Sd.U1, null), 20, 4, 0xA5)));
        var nullSections = Sd.Build(Sd.U1, Sd.U1, null, nullDacl: true);
        BinaryPrimitives.WriteUInt16LittleEndian(nullSections.AsSpan(2), (ushort)(Sd.SelfRelative | Sd.DaclPresent | Sd.SaclPresent));
        fixtures.Add(("null-sections", Insert(nullSections, nullSections.Length, 4, 0xA5)));
        fixtures.Add(("empty-sections", Insert(Sd.Build(Sd.U1, Sd.U1, Sd.Acl(4), sacl: Sd.Acl(4)), 20, 4, 0xA5)));

        foreach (var fixture in fixtures)
        foreach (var operation in new[] { "Import", "Owner", "Group", "Set", "Add", "RemoveSpecific", "RemoveAll", "Protect" })
        {
            var descriptor = new M.ActiveDirectorySecurity();
            var input = Convert.ToHexString(fixture.Raw);
            var output = input;
            var section = operation is "Owner" or "Group" ? operation : "Dacl";
            var sid = new B.SecurityIdentifier(operation is "Owner" or "Group" or "Add"
                ? "S-1-5-21-1-2-3-1002" : "S-1-5-21-1-2-3-1001");
            var ruleBytes = Array.Empty<byte>();
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            try
            {
                descriptor.SetSecurityDescriptorBinaryForm(fixture.Raw);
                // Import records raw -> imported; mutations record actual imported
                // input separately from the original storage in RequestedDescriptorHex.
                if (operation != "Import") input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
                if (operation == "Owner") descriptor.SetOwner(sid);
                else if (operation == "Group") descriptor.SetGroup(sid);
                else if (operation == "Protect") descriptor.SetAccessRuleProtection(true, true);
                else if (operation != "Import")
                {
                    var rights = (M.ActiveDirectoryRights)(operation == "Set" ? 0x20 : 0x10);
                    var rule = new M.ActiveDirectoryAccessRule(sid, rights, E.AccessControlType.Allow);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var change);
                    modified = change;
                }
                output = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            }
            catch (Exception ex)
            {
                exception = ex.GetType().FullName; message = ex.Message;
                // Preserve actual post-failure Microsoft state if import or mutation
                // rejects a layout; never manufacture a successful expected value.
                output = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            }
            observations.Add(new Observation($"layout-{fixture.Name}-{operation}", 0, section, operation, sid.Value,
                Convert.ToHexString(ruleBytes), input, output, returned, modified, exception, message,
                RequestedDescriptorHex: Convert.ToHexString(fixture.Raw)));
        }

        // Import independently constructed persistence candidates. Their opaque
        // gaps stay at original offsets; only a known terminal ACL may be resized.
        foreach (var fill in new byte[] { 0, 0xA5 })
        foreach (var leading in new[] { true, false })
        {
            var raw = Insert(baseline, leading ? 20 : Offset(baseline, 16), 4, fill);
            var aclAt = Offset(raw, 16);
            var setMask = raw.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(setMask.AsSpan(aclAt + 12), 0x20);
            Candidate($"{(leading ? "leading" : "intercomponent")}-{fill:X2}-setmask", setMask);
            var replacement = leading
                ? Sd.Acl(4, Sd.Ace(0, 0, 0x10, Sd.U1), Sd.Ace(0, 0, 0x10, Sd.U2))
                : Sd.Acl(4);
            var resized = raw.AsSpan(0, aclAt).ToArray().Concat(replacement).ToArray();
            Candidate($"{(leading ? "leading" : "intercomponent")}-{fill:X2}-{(leading ? "grow" : "shrink")}", resized);
        }
        var ownerPatch = Insert(baseline, 20, 4, 0xA5);
        Sd.U2.CopyTo(ownerPatch, Offset(ownerPatch, 4));
        Candidate("same-size-owner-offset-patch", ownerPatch);
        foreach (var field in new[] { 4, 8 })
        {
            // shared ends exactly in its referenced DACL; standalone former group
            // bytes remain untouched. Append an independent replacement SID only.
            var unshared = shared.Concat(Sd.U2).ToArray();
            WriteOffset(unshared, field, shared.Length);
            Candidate(field == 4 ? "shared-owner-append-unshare" : "shared-group-append-unshare", unshared);
        }

        // Both identity SIDs originally live inside the terminal DACL's ACE. Shrink
        // that ACL to empty while preserving standalone orphan bytes, then allocate
        // independent copies of the referenced identities after the shortened ACL.
        var embeddedAcl = Offset(embedded, 16);
        var emptyAcl = Sd.Acl(4);
        var embeddedShrink = embedded.AsSpan(0, embeddedAcl).ToArray()
            .Concat(emptyAcl).Concat(Sd.U1).Concat(Sd.U1).ToArray();
        WriteOffset(embeddedShrink, 4, embeddedAcl + emptyAcl.Length);
        WriteOffset(embeddedShrink, 8, embeddedAcl + emptyAcl.Length + Sd.U1.Length);
        Candidate("embedded-sids-terminal-shrink", embeddedShrink);

        void Candidate(string name, byte[] raw)
        {
            var descriptor = new M.ActiveDirectorySecurity();
            string? exception = null, message = null;
            try { descriptor.SetSecurityDescriptorBinaryForm(raw); }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"layout-candidate-{name}", 0, "Dacl", "Import",
                "S-1-5-21-1-2-3-1001", "", Convert.ToHexString(raw),
                Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), null, null, exception, message,
                RequestedDescriptorHex: Convert.ToHexString(raw)));
        }

        static int Offset(byte[] bytes, int field) => checked((int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(field)));
        static void WriteOffset(byte[] bytes, int field, int offset) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(field), (uint)offset);
        static byte[] Insert(byte[] original, int at, int length, byte fill)
        {
            var result = new byte[original.Length + length];
            original.AsSpan(0, at).CopyTo(result);
            result.AsSpan(at, length).Fill(fill);
            original.AsSpan(at).CopyTo(result.AsSpan(at + length));
            foreach (var field in new[] { 4, 8, 12, 16 })
            {
                var offset = Offset(original, field);
                if (offset != 0 && offset >= at) WriteOffset(result, field, offset + length);
            }
            return result;
        }
    }
}
