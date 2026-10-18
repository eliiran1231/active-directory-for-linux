using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

internal static partial class SeededSequences
{
    // Each operation starts from a fresh import. The selected rule is obtained from
    // Microsoft's observable collection, not reconstructed from an assumed merge.
    private static void RecordProjectedReconciliation(List<Observation> observations)
    {
        foreach (var audit in new[] { false, true })
        foreach (var shape in new[] { "duplicate", "masks", "scopes", "audit", "triple", "four", "object", "empty-guid" })
        foreach (var neighbors in new[] { false, true })
        foreach (var action in new[] { "Add-exact", "Add-subset", "Add-new-bit", "Remove-exact", "Remove-subset", "Remove-absent-bit", "RemoveSpecific-exact", "RemoveSpecific-subset" })
        {
            var type = (byte)(audit ? 2 : 0);
            var flags = (byte)(audit ? 0x40 : 0);
            var objectType = (byte)(audit ? 7 : 5);
            byte[] Common(uint mask, byte extra = 0) => Sd.Ace(type, (byte)(flags | extra), mask, Sd.U1);
            var aces = (shape switch
            {
                "duplicate" => new[] { Common(0x10), Common(0x10) },
                "masks" => new[] { Common(0x10), Common(0x20) },
                "scopes" => new[] { Common(0x10), Common(0x10, 10) },
                "audit" => new[] { Common(0x10), Sd.Ace(type, (byte)(audit ? 0x80 : 2), 0x10, Sd.U1) },
                "triple" => new[] { Common(0x10), Common(0x20), Common(0x40) },
                "four" => new[] { Common(0x10), Common(0x20), Common(0x40), Common(0x80) },
                "object" => new[] { Sd.ObjAce(objectType, flags, 0x10, 1, Sd.G1, null, Sd.U1), Sd.ObjAce(objectType, flags, 0x20, 1, Sd.G1, null, Sd.U1) },
                _ => new[] { Sd.ObjAce(objectType, (byte)(flags | 2), 0x10, 3, Guid.Empty, Sd.G2, Sd.U1), Sd.ObjAce(objectType, (byte)(flags | 2), 0x20, 2, null, Sd.G2, Sd.U1) },
            }).ToList();
            if (neighbors)
            {
                // Same identity, distinct object scope and inheritance scope, plus a
                // different identity. These originals must not be silently compacted
                // simply because another projected entry is explicitly modified.
                aces.Add(Sd.ObjAce(objectType, flags, 0x10, 1, Sd.G2, null, Sd.U1));
                aces.Add(Sd.ObjAce(objectType, (byte)(flags | 10), 0x20, 3, Sd.G2, Sd.G1, Sd.U1));
                aces.Add(Sd.Ace(type, flags, 0x10, Sd.U2));
                aces.Add(Sd.Ace(type, flags, 0x20, Sd.U2));
            }
            var raw = audit
                ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, aces.ToArray()))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, aces.ToArray()));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(raw);
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            var operation = action.Split('-')[0];
            var variant = action[(operation.Length + 1)..];
            var sid = new B.SecurityIdentifier("S-1-5-21-1-2-3-1001");
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes;
            if (audit)
            {
                var selected = descriptor.GetAuditRules(true, false, typeof(B.SecurityIdentifier)).Cast<M.ActiveDirectoryAuditRule>()
                    .First(x => x.IdentityReference.Equals(sid));
                var rule = variant == "exact" ? selected : new M.ActiveDirectoryAuditRule(sid,
                    Rights(selected.ActiveDirectoryRights, variant), selected.AuditFlags, selected.ObjectType,
                    selected.InheritanceType, selected.InheritedObjectType);
                ruleBytes = RuleBytes(rule);
                try { returned = descriptor.ModifyAuditRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var change); modified = change; }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            }
            else
            {
                var selected = descriptor.GetAccessRules(true, false, typeof(B.SecurityIdentifier)).Cast<M.ActiveDirectoryAccessRule>()
                    .First(x => x.IdentityReference.Equals(sid));
                var rule = variant == "exact" ? selected : new M.ActiveDirectoryAccessRule(sid,
                    Rights(selected.ActiveDirectoryRights, variant), selected.AccessControlType, selected.ObjectType,
                    selected.InheritanceType, selected.InheritedObjectType);
                ruleBytes = RuleBytes(rule);
                try { returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var change); modified = change; }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            }
            observations.Add(new Observation($"projected-reconcile-{shape}-{audit}-{neighbors}-{action}", 0,
                audit ? "Sacl" : "Dacl", operation, sid.Value, Convert.ToHexString(ruleBytes), input,
                Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                RequestedDescriptorHex: Convert.ToHexString(raw)));
        }

        // Revision two carrying object ACEs is accepted by the codec/import. A
        // semantically redundant explicit Add can still promote the ACL revision.
        foreach (var audit in new[] { false, true })
        {
            var ace = Sd.ObjAce((byte)(audit ? 7 : 5), (byte)(audit ? 0x40 : 0), 0x10, 1, Sd.G1, null, Sd.U1);
            var raw = audit
                ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(2, ace, ace))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(2, ace, ace));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(raw);
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            var sid = new B.SecurityIdentifier("S-1-5-21-1-2-3-1001");
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes;
            if (audit)
            {
                var rule = descriptor.GetAuditRules(true, false, typeof(B.SecurityIdentifier)).Cast<M.ActiveDirectoryAuditRule>().First();
                ruleBytes = RuleBytes(rule);
                try { returned = descriptor.ModifyAuditRule(E.AccessControlModification.Add, rule, out var change); modified = change; }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            }
            else
            {
                var rule = descriptor.GetAccessRules(true, false, typeof(B.SecurityIdentifier)).Cast<M.ActiveDirectoryAccessRule>().First();
                ruleBytes = RuleBytes(rule);
                try { returned = descriptor.ModifyAccessRule(E.AccessControlModification.Add, rule, out var change); modified = change; }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            }
            observations.Add(new Observation($"projected-reconcile-revision2-object-duplicate-{audit}-Add", 0,
                audit ? "Sacl" : "Dacl", "Add", sid.Value, Convert.ToHexString(ruleBytes), input,
                Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                RequestedDescriptorHex: Convert.ToHexString(raw)));
        }

        static M.ActiveDirectoryRights Rights(M.ActiveDirectoryRights original, string variant)
        {
            var mask = unchecked((int)original);
            return (M.ActiveDirectoryRights)(variant switch
            {
                "subset" => mask & -mask,
                "new-bit" or "absent-bit" => 0x10000,
                _ => throw new InvalidOperationException(variant),
            });
        }
    }
}
