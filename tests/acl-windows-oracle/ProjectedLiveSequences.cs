using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

internal static partial class SeededSequences
{
    private static void RecordProjectedLiveSequences(List<Observation> observations)
    {
        foreach (var audit in new[] { false, true })
        foreach (var four in new[] { false, true })
        foreach (var neighbors in new[] { false, true })
        {
            var type = (byte)(audit ? 2 : 0);
            var flags = (byte)(audit ? 0x40 : 0);
            var aces = new List<byte[]> { Sd.Ace(type, flags, 0x10, Sd.U1), Sd.Ace(type, flags, 0x20, Sd.U1), Sd.Ace(type, flags, 0x40, Sd.U1) };
            if (four) aces.Add(Sd.Ace(type, flags, 0x80, Sd.U1));
            if (neighbors)
            {
                aces.Add(Sd.ObjAce((byte)(audit ? 7 : 5), flags, 0x10, 1, Sd.G2, null, Sd.U1));
                aces.Add(Sd.ObjAce((byte)(audit ? 7 : 5), (byte)(flags | 10), 0x20, 3, Sd.G2, Sd.G1, Sd.U1));
                aces.Add(Sd.Ace(type, flags, 0x10, Sd.U2));
                aces.Add(Sd.Ace(type, flags, 0x20, Sd.U2));
            }
            var raw = audit
                ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, aces.ToArray()))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, aces.ToArray()), sacl: Sd.Acl(4));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(raw);
            var sid = new B.SecurityIdentifier("S-1-5-21-1-2-3-1001");
            var sequence = $"projected-live-{(four ? "four" : "triple")}-{audit}-{neighbors}";
            var index = 0;
            // Select the removal subset from the actual imported rule. Keep it for
            // later operations, rather than reimporting any intermediate bytes.
            var firstMask = audit
                ? (int)descriptor.GetAuditRules(true, false, typeof(B.SecurityIdentifier)).Cast<M.ActiveDirectoryAuditRule>().First(x => x.IdentityReference.Equals(sid)).ActiveDirectoryRights
                : (int)descriptor.GetAccessRules(true, false, typeof(B.SecurityIdentifier)).Cast<M.ActiveDirectoryAccessRule>().First(x => x.IdentityReference.Equals(sid)).ActiveDirectoryRights;
            var subset = firstMask & -firstMask;
            Capture("Remove", subset);
            Capture("Get", 0);
            Capture("Get", 0);
            Capture("RemoveConflict", 0x20);
            Capture("Get", 0);
            Capture("Owner", 0);
            Capture("Group", 0);
            Capture("OppositeAdd", 0x100);
            Capture("Get", 0);
            Capture("RemoveSpecific", four ? 0xC0 : 0x40);
            Capture("Get", 0);
            Capture("Add", subset);
            Capture("Remove", 0x10000);
            Capture("RemoveSpecific", subset);
            Capture("Add", 0x10000);
            Capture("Remove", 0x20);
            Capture("Get", 0);
            Capture("Set", 0x10);
            Capture("Add", 0x20);
            Capture("Reset", 0x40);
            Capture("Protect", 0);
            Capture("ProtectDrop", 0);
            Capture("Unprotect", 0);
            Capture("Purge", 0);
            Capture("RemoveAll", 0x40);
            Capture("Get", 0);

            void Capture(string action, int mask)
            {
                var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
                var section = audit ? "Sacl" : "Dacl";
                var operation = action switch { "OppositeAdd" => "Add", "RemoveConflict" => "Remove", _ => action };
                var targetAudit = action == "OppositeAdd" ? !audit : audit;
                var targetSid = action is "Owner" or "Group" or "OppositeAdd" ? new B.SecurityIdentifier("S-1-1-0") : sid;
                var ruleBytes = Array.Empty<byte>();
                bool? returned = null, modified = null;
                string? exception = null, message = null;
                try
                {
                    if (action == "Get")
                    {
                        // Exercise both collection and serialization getters twice;
                        // observed output records whether either changes live state.
                        for (var i = 0; i < 2; i++)
                        {
                            _ = descriptor.GetAccessRules(true, true, typeof(B.SecurityIdentifier));
                            _ = descriptor.GetAuditRules(true, true, typeof(B.SecurityIdentifier));
                            _ = descriptor.GetSecurityDescriptorBinaryForm();
                        }
                    }
                    else if (action == "Owner") { section = "Owner"; descriptor.SetOwner(targetSid); }
                    else if (action == "Group") { section = "Group"; descriptor.SetGroup(targetSid); }
                    else if (action is "Protect" or "ProtectDrop" or "Unprotect")
                    {
                        if (audit) descriptor.SetAuditRuleProtection(action != "Unprotect", action != "ProtectDrop");
                        else descriptor.SetAccessRuleProtection(action != "Unprotect", action != "ProtectDrop");
                    }
                    else if (action == "Purge")
                    {
                        if (audit) descriptor.PurgeAuditRules(targetSid);
                        else descriptor.PurgeAccessRules(targetSid);
                    }
                    else if (targetAudit)
                    {
                        section = "Sacl";
                        var rule = action == "RemoveConflict"
                            ? new M.ActiveDirectoryAuditRule(targetSid, (M.ActiveDirectoryRights)mask, E.AuditFlags.Success, Sd.G1)
                            : new M.ActiveDirectoryAuditRule(targetSid, (M.ActiveDirectoryRights)mask, E.AuditFlags.Success);
                        ruleBytes = RuleBytes(rule);
                        returned = descriptor.ModifyAuditRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var change);
                        modified = change;
                    }
                    else
                    {
                        section = "Dacl";
                        var rule = action == "RemoveConflict"
                            ? new M.ActiveDirectoryAccessRule(targetSid, (M.ActiveDirectoryRights)mask, E.AccessControlType.Allow, Sd.G1)
                            : new M.ActiveDirectoryAccessRule(targetSid, (M.ActiveDirectoryRights)mask, E.AccessControlType.Allow);
                        ruleBytes = RuleBytes(rule);
                        returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var change);
                        modified = change;
                    }
                }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
                observations.Add(new Observation(sequence, index, section, operation, targetSid.Value,
                    Convert.ToHexString(ruleBytes), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                    returned, modified, exception, message, RequestedDescriptorHex: index == 0 ? Convert.ToHexString(raw) : null));
                index++;
            }
        }
    }
}
