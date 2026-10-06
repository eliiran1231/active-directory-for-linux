// Detached Microsoft-only research. Records observations, never declares an allowlist.
using System.Runtime.InteropServices;
using System.Text.Json;
using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

internal static class SeededSequences
{
    internal static void Record(string path)
    {
        const int seed = 226;
        var random = new Random(seed);
        var observations = new List<Observation>();
        for (var sample = 0; sample < 8; sample++)
        {
            // Only known DS masks. Variation is deterministic and bounded, not fuzzed against AD.
            uint mask = new uint[] { 4, 8, 16, 32, 256 }[random.Next(5)];
            uint otherMask = new uint[] { 4, 8, 16, 32, 256 }[random.Next(5)];
            var trustee = sample % 2 == 0 ? "S-1-5-21-1-2-3-1001" : "S-1-5-21-1-2-3-1002";
            var objectType = sample % 2 == 0 ? Guid.Empty : Sd.G1;
            var auditFlags = new[] { E.AuditFlags.Success, E.AuditFlags.Failure, E.AuditFlags.Success | E.AuditFlags.Failure }[sample % 3];
            var auditAceFlags = (byte)(((auditFlags & E.AuditFlags.Success) != 0 ? 0x40 : 0)
                | ((auditFlags & E.AuditFlags.Failure) != 0 ? 0x80 : 0));
            foreach (var section in new[] { "Dacl", "Sacl" })
            {
                var descriptor = new M.ActiveDirectorySecurity();
                descriptor.SetSecurityDescriptorBinaryForm(Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4)));
                var sequence = $"seed-{seed}-{sample}-{section}";
                var sid = new B.SecurityIdentifier(trustee);
                // SACL uses one identity/object/scope, so these operations do not depend on disputed sorting.
                var steps = new[]
                {
                    ("Add", mask), ("Add", otherMask), ("Set", mask), ("Reset", otherMask),
                    ("Remove", otherMask), ("Add", mask), ("RemoveSpecific", mask),
                    ("Add", mask), ("RemoveAll", otherMask), ("Add", mask), ("Purge", mask),
                    ("Add", mask), ("Protect", mask), ("Unprotect", mask),
                    ("Owner", mask), ("Group", mask),
                };
                var index = 0;
                foreach (var (operation, rights) in steps)
                {
                    var isAudit = section == "Sacl";
                    var ruleBytes = objectType == Guid.Empty
                        ? Sd.Ace((byte)(isAudit ? 2 : 0), (byte)(isAudit ? auditAceFlags : 0), rights, Sd.Sid(trustee))
                        : Sd.ObjAce((byte)(isAudit ? 7 : 5), (byte)(isAudit ? auditAceFlags : 0), rights, 1, objectType, null, Sd.Sid(trustee));
                    var requestedRuleHex = Convert.ToHexString(ruleBytes);
                    var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
                    bool? returned = null, modified = null;
                    string? exception = null, message = null;
                    try
                    {
                        if (operation == "Owner") descriptor.SetOwner(sid);
                        else if (operation == "Group") descriptor.SetGroup(sid);
                        else if (operation == "Protect" || operation == "Unprotect")
                        {
                            if (isAudit) descriptor.SetAuditRuleProtection(operation == "Protect", true);
                            else descriptor.SetAccessRuleProtection(operation == "Protect", true);
                        }
                        else if (operation == "Purge")
                        {
                            if (isAudit) descriptor.PurgeAuditRules(sid);
                            else descriptor.PurgeAccessRules(sid);
                        }
                        else if (isAudit)
                        {
                            var rule = new M.ActiveDirectoryAuditRule(sid, (M.ActiveDirectoryRights)rights,
                                auditFlags, objectType, M.ActiveDirectorySecurityInheritance.None, Guid.Empty);
                            ruleBytes = RuleBytes(rule);
                            returned = descriptor.ModifyAuditRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var changed);
                            modified = changed;
                        }
                        else
                        {
                            var rule = new M.ActiveDirectoryAccessRule(sid, (M.ActiveDirectoryRights)rights,
                                E.AccessControlType.Allow, objectType, M.ActiveDirectorySecurityInheritance.None, Guid.Empty);
                            ruleBytes = RuleBytes(rule);
                            returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var changed);
                            modified = changed;
                        }
                    }
                    catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
                    observations.Add(new Observation(sequence, index++, section, operation, trustee,
                        Convert.ToHexString(ruleBytes), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                        returned, modified, exception, message, requestedRuleHex));
                }
            }
        }
        RecordInheritedProtection(observations);
        RecordAuditSplits(observations);
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var recording = new
        {
            SchemaVersion = 1, Seed = seed,
            Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription,
            MicrosoftAssembly = typeof(M.ActiveDirectorySecurity).Assembly.FullName,
            Scope = "Detached in-memory objects only; no DirectoryEntry, LDAP, Persist, token or privilege changes. Observations require review before replay acceptance.",
            Observations = observations,
        };
        File.WriteAllText(fullPath, JsonSerializer.Serialize(recording, new JsonSerializerOptions { WriteIndented = true }));
        // A compact machine-readable fallback when artifact download is unavailable.
        Console.WriteLine("SEEDED_JSON=" + JsonSerializer.Serialize(recording));
        Console.WriteLine($"Recorded {observations.Count} seeded observations to {path}");
    }

    private static void RecordInheritedProtection(List<Observation> observations)
    {
        foreach (var objectAce in new[] { false, true })
        foreach (var operation in new[] { "Protect", "ProtectDrop", "Unprotect" })
        {
            // Inherited deny follows inherited allow; preserving inheritance must retain their
            // relative order until explicit canonical grouping is actually requested by protection.
            var inheritedAllow = objectAce
                ? Sd.ObjAce(5, Sd.Inherited | Sd.Ci, 0x10, 1, Sd.G1, null, Sd.U1)
                : Sd.Ace(0, Sd.Inherited | Sd.Ci, 0x10, Sd.U1);
            var bytes = Sd.Build(Sd.Admins, Sd.Admins,
                Sd.Acl(4, Sd.Ace(0, 0, 0x20, Sd.U2), inheritedAllow,
                    Sd.Ace(1, Sd.Inherited, 0x20, Sd.U2)));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(bytes);
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            string? exception = null, message = null;
            try { descriptor.SetAccessRuleProtection(operation != "Unprotect", operation != "ProtectDrop"); }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"inherited-protection-{objectAce}-{operation}", 0,
                "Dacl", operation, "S-1-5-21-1-2-3-1001", Convert.ToHexString(inheritedAllow),
                input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                null, null, exception, message));
        }
    }

    private static void RecordAuditSplits(List<Observation> observations)
    {
        foreach (var objectAce in new[] { false, true })
        foreach (var flags in new[] { E.AuditFlags.Success, E.AuditFlags.Failure })
        {
            // Start with exactly one audit ACE. Removing one outcome, some mask bits and
            // self scope can yield up to three pieces, without adding/re-sorting other audits.
            var originalAce = objectAce
                ? Sd.ObjAce(7, 0xC2, 0x30, 1, Sd.G1, null, Sd.U1)
                : Sd.Ace(2, 0xC2, 0x30, Sd.U1);
            var removeAce = objectAce
                ? Sd.ObjAce(7, (byte)(flags == E.AuditFlags.Success ? 0x40 : 0x80), 0x10, 1, Sd.G1, null, Sd.U1)
                : Sd.Ace(2, (byte)(flags == E.AuditFlags.Success ? 0x40 : 0x80), 0x10, Sd.U1);
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, originalAce)));
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            try
            {
                var rule = new M.ActiveDirectoryAuditRule(new B.SecurityIdentifier(Sd.U1, 0),
                    M.ActiveDirectoryRights.ReadProperty, flags, objectAce ? Sd.G1 : Guid.Empty,
                    M.ActiveDirectorySecurityInheritance.None, Guid.Empty);
                removeAce = RuleBytes(rule);
                returned = descriptor.ModifyAuditRule(E.AccessControlModification.Remove, rule, out var changed);
                modified = changed;
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"audit-three-piece-{objectAce}-{flags}", 0, "Sacl", "Remove",
                "S-1-5-21-1-2-3-1001", Convert.ToHexString(removeAce), input,
                Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message));
        }
    }

    // Construct the recorded ACE from the actual Microsoft rule after its constructor
    // normalizes GUID applicability. Requested arguments are not the resulting rule.
    private static byte[] RuleBytes(M.ActiveDirectoryAccessRule rule) => RuleBytes(rule,
        unchecked((int)rule.ActiveDirectoryRights),
        rule.AccessControlType == E.AccessControlType.Allow ? E.AceQualifier.AccessAllowed : E.AceQualifier.AccessDenied,
        E.AceFlags.None, rule.ObjectFlags, rule.ObjectType, rule.InheritedObjectType);

    private static byte[] RuleBytes(M.ActiveDirectoryAuditRule rule) => RuleBytes(rule,
        unchecked((int)rule.ActiveDirectoryRights), E.AceQualifier.SystemAudit,
        ((rule.AuditFlags & E.AuditFlags.Success) != 0 ? E.AceFlags.SuccessfulAccess : E.AceFlags.None)
        | ((rule.AuditFlags & E.AuditFlags.Failure) != 0 ? E.AceFlags.FailedAccess : E.AceFlags.None),
        rule.ObjectFlags, rule.ObjectType, rule.InheritedObjectType);

    private static byte[] RuleBytes(E.AuthorizationRule rule, int mask, E.AceQualifier qualifier,
        E.AceFlags flags, E.ObjectAceFlags objectFlags, Guid objectType, Guid inheritedObjectType)
    {
        if ((rule.InheritanceFlags & E.InheritanceFlags.ContainerInherit) != 0) flags |= E.AceFlags.ContainerInherit;
        if ((rule.InheritanceFlags & E.InheritanceFlags.ObjectInherit) != 0) flags |= E.AceFlags.ObjectInherit;
        if ((rule.PropagationFlags & E.PropagationFlags.NoPropagateInherit) != 0) flags |= E.AceFlags.NoPropagateInherit;
        if ((rule.PropagationFlags & E.PropagationFlags.InheritOnly) != 0) flags |= E.AceFlags.InheritOnly;
        if (rule.IsInherited) flags |= E.AceFlags.Inherited;
        var sid = (B.SecurityIdentifier)rule.IdentityReference;
        E.GenericAce ace = objectFlags == E.ObjectAceFlags.None
            ? new E.CommonAce(flags, qualifier, mask, sid, false, null)
            : new E.ObjectAce(flags, qualifier, mask, sid, objectFlags, objectType, inheritedObjectType, false, null);
        var bytes = new byte[ace.BinaryLength];
        ace.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private sealed record Observation(string Sequence, int Index, string Section, string Operation,
        string Sid, string RuleHex, string InputHex, string OutputHex, bool? ReturnValue,
        bool? Modified, string? ExceptionType, string? ExceptionMessage, string? RequestedRuleHex = null);
}
