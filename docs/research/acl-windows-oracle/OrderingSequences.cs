using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

internal static partial class SeededSequences
{
    private static void RecordOrderingAndCompaction(List<Observation> observations)
    {
        var fixtures = new (string Name, bool Audit, byte[][] Aces)[]
        {
            ("i2", true, new[] { Sd.Ace(2, 0x40, 0x20, Sd.U2), Sd.Ace(2, 0x80, 4, Sd.U2) }),
            ("i2-reverse", true, new[] { Sd.Ace(2, 0x80, 4, Sd.U2), Sd.Ace(2, 0x40, 0x20, Sd.U2) }),
            ("ties", true, new[] { Sd.Ace(2, 0x40, 0x10, Sd.U2), Sd.Ace(2, 0x80, 0x20, Sd.U2), Sd.Ace(2, 0xC0, 0x40, Sd.U2) }),
            ("family", true, new[] { Sd.ObjAce(7, 0x40, 0x10, 1, Sd.G1, null, Sd.U1), Sd.Ace(2, 0x80, 0x20, Sd.U2) }),
            ("sid", true, new[] { Sd.Ace(2, 0x40, 0x10, Sd.U2), Sd.Ace(2, 0x80, 0x20, Sd.U1) }),
            ("inherited", true, new[] { Sd.Ace(2, 0x40, 0x20, Sd.U2), Sd.Ace(2, 0x80, 4, Sd.U2), Sd.Ace(2, 0x50, 8, Sd.U2), Sd.Ace(2, 0x90, 0x10, Sd.U1) }),
            ("dacl-ties", false, new[] { Sd.Ace(0, 0, 0x20, Sd.U2), Sd.Ace(0, 2, 4, Sd.U2) }),
            ("dacl-family", false, new[] { Sd.ObjAce(5, 0, 0x10, 1, Sd.G1, null, Sd.U1), Sd.Ace(0, 0, 0x20, Sd.U2) }),
        };
        foreach (var fixture in fixtures)
        foreach (var operation in new[] { "Add", "AddExisting", "Set", "Reset", "Remove", "RemoveSpecific", "RemoveAll", "Purge", "Protect", "ProtectDrop", "Unprotect" })
        {
            var raw = Build(fixture.Audit, fixture.Aces);
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(raw);
            Capture($"ordering-{fixture.Name}-{operation}", 0, descriptor, fixture.Audit, operation, raw);
        }
        foreach (var fixture in fixtures.Where(x => x.Name is "i2" or "inherited" or "dacl-ties"))
        {
            var raw = Build(fixture.Audit, fixture.Aces);
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(raw);
            var index = 0;
            foreach (var operation in new[] { "Add", "Add", "AddExisting", "Set", "Remove", "ProtectDrop", "Purge", "Unprotect" })
                Capture($"ordering-sequence-{fixture.Name}", index++, descriptor, fixture.Audit, operation, index == 1 ? raw : null);
        }
        foreach (var audit in new[] { false, true })
        foreach (var shape in new[] { "duplicate", "masks", "scopes", "audit", "triple", "four", "object", "empty-guid" })
        {
            var type = (byte)(audit ? 2 : 0);
            var flags = (byte)(audit ? 0x40 : 0);
            var aces = shape switch
            {
                "duplicate" => new[] { Sd.Ace(type, flags, 0x10, Sd.U1), Sd.Ace(type, flags, 0x10, Sd.U1) },
                "masks" => new[] { Sd.Ace(type, flags, 0x10, Sd.U1), Sd.Ace(type, flags, 0x20, Sd.U1) },
                "scopes" => new[] { Sd.Ace(type, flags, 0x10, Sd.U1), Sd.Ace(type, (byte)(flags | 10), 0x10, Sd.U1) },
                "audit" => new[] { Sd.Ace(type, flags, 0x10, Sd.U1), Sd.Ace(type, (byte)(audit ? 0x80 : 2), 0x10, Sd.U1) },
                "triple" => new[] { Sd.Ace(type, flags, 0x10, Sd.U1), Sd.Ace(type, flags, 0x20, Sd.U1), Sd.Ace(type, flags, 0x40, Sd.U1) },
                "four" => new[] { Sd.Ace(type, flags, 0x10, Sd.U1), Sd.Ace(type, flags, 0x20, Sd.U1), Sd.Ace(type, flags, 0x40, Sd.U1), Sd.Ace(type, flags, 0x80, Sd.U1) },
                "object" => new[] { Sd.ObjAce((byte)(audit ? 7 : 5), flags, 0x10, 1, Sd.G1, null, Sd.U1), Sd.ObjAce((byte)(audit ? 7 : 5), flags, 0x20, 1, Sd.G1, null, Sd.U1) },
                _ => new[] { Sd.ObjAce((byte)(audit ? 7 : 5), (byte)(flags | 2), 0x10, 3, Guid.Empty, Sd.G2, Sd.U1), Sd.ObjAce((byte)(audit ? 7 : 5), (byte)(flags | 2), 0x20, 2, null, Sd.G2, Sd.U1) },
            };
            foreach (var reverse in new[] { false, true })
            {
                var raw = Build(audit, reverse ? aces.AsEnumerable().Reverse().ToArray() : aces);
                var descriptor = new M.ActiveDirectorySecurity();
                descriptor.SetSecurityDescriptorBinaryForm(raw);
                observations.Add(new Observation($"import-{shape}-{audit}-{reverse}", 0, audit ? "Sacl" : "Dacl", "Import",
                    "S-1-5-21-1-2-3-1001", "", Convert.ToHexString(raw), Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                    null, null, null, null, RequestedDescriptorHex: Convert.ToHexString(raw)));
            }
        }

        static byte[] Build(bool audit, byte[][] aces) => audit
            ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, aces))
            : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, aces));
        void Capture(string sequence, int index, M.ActiveDirectorySecurity descriptor, bool audit, string operation, byte[]? requested)
        {
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            var sid = new B.SecurityIdentifier(operation == "Add" ? "S-1-1-0" : "S-1-5-21-1-2-3-1002");
            var actualOperation = operation == "AddExisting" ? "Add" : operation;
            var rights = operation == "Add" ? M.ActiveDirectoryRights.ExtendedRight : M.ActiveDirectoryRights.WriteProperty;
            var access = new M.ActiveDirectoryAccessRule(sid, rights, E.AccessControlType.Allow);
            var auditing = new M.ActiveDirectoryAuditRule(sid, rights, E.AuditFlags.Success);
            var rule = audit ? RuleBytes(auditing) : RuleBytes(access);
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            try
            {
                if (operation == "Purge") { if (audit) descriptor.PurgeAuditRules(sid); else descriptor.PurgeAccessRules(sid); }
                else if (operation is "Protect" or "ProtectDrop" or "Unprotect")
                {
                    if (audit) descriptor.SetAuditRuleProtection(operation != "Unprotect", operation != "ProtectDrop");
                    else descriptor.SetAccessRuleProtection(operation != "Unprotect", operation != "ProtectDrop");
                }
                else if (audit) { returned = descriptor.ModifyAuditRule(Enum.Parse<E.AccessControlModification>(actualOperation), auditing, out var change); modified = change; }
                else { returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(actualOperation), access, out var change); modified = change; }
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation(sequence, index, audit ? "Sacl" : "Dacl", actualOperation, sid.Value,
                Convert.ToHexString(rule), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                RequestedDescriptorHex: requested is null ? null : Convert.ToHexString(requested)));
        }
    }
}
