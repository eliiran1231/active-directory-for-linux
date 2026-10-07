// Detached Microsoft-only research. Records observations, never declares an allowlist.
using System.Runtime.InteropServices;
using System.Text.Json;
using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

internal static partial class SeededSequences
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
        RecordMixedObjectRemovals(observations);
        RecordRevisionAndAbsentAudit(observations);
        RecordRestorationAndSidOrder(observations);
        RecordRemovalScopePrecedence(observations);
        RecordInheritedGuidAndObjectInherit(observations);
        RecordObjectOiAndCombinedSequences(observations);
        RecordAsymmetricObjectMaskAdds(observations);
        RecordLaterStageMergeLeads(observations);
        RecordScopeMergeQualifiers(observations);
        RecordEmptyObjectMaskMerge(observations);
        RecordMergeValuePresenceMatrix(observations);
        RecordOrderingAndCompaction(observations);
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

    private static void RecordMergeValuePresenceMatrix(List<Observation> observations)
    {
        var shapes = new (Guid? Ot, Guid? Iot, Guid? NewOt, Guid? NewIot)[]
        {
            (Guid.Empty, Sd.G2, null, Sd.G2), (null, Sd.G2, Guid.Empty, Sd.G2),
            (Sd.G1, Guid.Empty, Sd.G1, null), (Sd.G1, null, Sd.G1, Guid.Empty),
            (Sd.G1, Sd.G2, Sd.G1, Sd.G2), (Sd.G2, Sd.G2, Sd.G1, Sd.G2),
            (null, Sd.G2, Sd.G1, Sd.G2), (Sd.G1, Sd.G2, null, Sd.G2),
            (Sd.G1, null, Sd.G1, Sd.G2), (Sd.G1, Sd.G2, Sd.G1, null),
            (Sd.G1, Sd.G1, Sd.G1, Sd.G2), (Guid.Empty, Sd.G2, Sd.G1, Sd.G2),
        };
        foreach (var stage in new[] { 1, 2, 3 })
        foreach (var mode in (stage == 2 ? new[] { "Audit" } : new[] { "Allow", "Deny", "Audit" }))
        for (var shape = 0; shape < shapes.Length; shape++)
        {
            var pair = shapes[shape];
            var audit = mode == "Audit";
            var type = (byte)(audit ? 7 : mode == "Deny" ? 6 : 5);
            var flags = (byte)((audit ? 0x40 : 0) | (stage == 3 ? 0 : 2));
            var of = (pair.Ot.HasValue ? 1u : 0u) | (pair.Iot.HasValue ? 2u : 0u);
            var source = Sd.ObjAce(type, flags, 0x10, of, pair.Ot, pair.Iot, Sd.U1);
            var requested = audit ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes = Array.Empty<byte>();
            try
            {
                var sid = new B.SecurityIdentifier(Sd.U1, 0);
                var rights = stage == 1 ? M.ActiveDirectoryRights.WriteProperty : M.ActiveDirectoryRights.ReadProperty;
                var inheritance = stage == 3 ? M.ActiveDirectorySecurityInheritance.Descendents : M.ActiveDirectorySecurityInheritance.All;
                if (audit)
                {
                    var rule = new M.ActiveDirectoryAuditRule(sid, rights,
                        stage == 2 ? E.AuditFlags.Failure : E.AuditFlags.Success,
                        pair.NewOt ?? Guid.Empty, inheritance, pair.NewIot ?? Guid.Empty);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAuditRule(E.AccessControlModification.Add, rule, out var changed);
                    modified = changed;
                }
                else
                {
                    var rule = new M.ActiveDirectoryAccessRule(sid, rights,
                        mode == "Deny" ? E.AccessControlType.Deny : E.AccessControlType.Allow,
                        pair.NewOt ?? Guid.Empty, inheritance, pair.NewIot ?? Guid.Empty);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAccessRule(E.AccessControlModification.Add, rule, out var changed);
                    modified = changed;
                }
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"merge-value-stage{stage}-{mode}-{shape}", 0,
                audit ? "Sacl" : "Dacl", "Add", "S-1-5-21-1-2-3-1001", Convert.ToHexString(ruleBytes),
                input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                RequestedDescriptorHex: Convert.ToHexString(requested)));
        }
    }

    private static void RecordEmptyObjectMaskMerge(List<Observation> observations)
    {
        foreach (var reverse in new[] { false, true })
        {
            var source = Sd.ObjAce(7, 0x42, reverse ? 0x20u : 0x10u,
                reverse ? 2u : 3u, reverse ? null : Guid.Empty, Sd.G2, Sd.U1);
            var requested = Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var rule = new M.ActiveDirectoryAuditRule(new B.SecurityIdentifier(Sd.U1, 0),
                reverse ? M.ActiveDirectoryRights.ReadProperty : M.ActiveDirectoryRights.WriteProperty,
                E.AuditFlags.Success, Guid.Empty, M.ActiveDirectorySecurityInheritance.All, Sd.G2);
            var requestedRule = Sd.ObjAce(7, 0x42, reverse ? 0x10u : 0x20u,
                reverse ? 3u : 2u, reverse ? Guid.Empty : null, Sd.G2, Sd.U1);
            for (var index = 0; index < 2; index++)
            {
                var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
                bool? returned = null, modified = null;
                string? exception = null, message = null;
                try
                {
                    returned = descriptor.ModifyAuditRule(E.AccessControlModification.Add, rule, out var changed);
                    modified = changed;
                }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
                observations.Add(new Observation($"empty-ot-mask-{reverse}", index, "Sacl", "Add",
                    "S-1-5-21-1-2-3-1001", Convert.ToHexString(RuleBytes(rule)), input,
                    Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                    Convert.ToHexString(requestedRule), index == 0 ? Convert.ToHexString(requested) : null));
            }
        }
    }

    private static void RecordScopeMergeQualifiers(List<Observation> observations)
    {
        foreach (var mode in new[] { "Deny", "Success", "Failure", "Both" })
        foreach (var reverse in new[] { false, true })
        {
            var audit = mode != "Deny";
            var auditFlags = mode == "Success" ? E.AuditFlags.Success : mode == "Failure" ? E.AuditFlags.Failure
                : audit ? E.AuditFlags.Success | E.AuditFlags.Failure : E.AuditFlags.None;
            var flags = (byte)(mode == "Success" ? 0x40 : mode == "Failure" ? 0x80 : audit ? 0xC0 : 0);
            var source = Sd.ObjAce((byte)(audit ? 7 : 6), (byte)(flags | (reverse ? 0x0A : 0)),
                0x10, reverse ? 3u : 1u, Sd.G1, reverse ? Sd.G2 : null, Sd.U1);
            var requested = audit ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            // Reverse audit produces a multi-entry SACL; do not conflate the next edit
            // with the unresolved existing-multi-entry SACL ordering policy.
            for (var index = 0; index < (audit && reverse ? 1 : 2); index++)
            {
                var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
                bool? returned = null, modified = null;
                string? exception = null, message = null;
                byte[] ruleBytes = Array.Empty<byte>();
                try
                {
                    var sid = new B.SecurityIdentifier(Sd.U1, 0);
                    var inheritance = reverse ? M.ActiveDirectorySecurityInheritance.None : M.ActiveDirectorySecurityInheritance.Descendents;
                    if (audit)
                    {
                        var rule = new M.ActiveDirectoryAuditRule(sid, M.ActiveDirectoryRights.ReadProperty,
                            auditFlags, Sd.G1, inheritance, reverse ? Guid.Empty : Sd.G2);
                        ruleBytes = RuleBytes(rule);
                        returned = descriptor.ModifyAuditRule(E.AccessControlModification.Add, rule, out var changed);
                        modified = changed;
                    }
                    else
                    {
                        var rule = new M.ActiveDirectoryAccessRule(sid, M.ActiveDirectoryRights.ReadProperty,
                            E.AccessControlType.Deny, Sd.G1, inheritance, reverse ? Guid.Empty : Sd.G2);
                        ruleBytes = RuleBytes(rule);
                        returned = descriptor.ModifyAccessRule(E.AccessControlModification.Add, rule, out var changed);
                        modified = changed;
                    }
                }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
                observations.Add(new Observation($"scope-qualifier-{mode}-{reverse}", index,
                    audit ? "Sacl" : "Dacl", "Add", "S-1-5-21-1-2-3-1001", Convert.ToHexString(ruleBytes),
                    input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                    RequestedDescriptorHex: index == 0 ? Convert.ToHexString(requested) : null));
            }
        }
    }

    private static void RecordLaterStageMergeLeads(List<Observation> observations)
    {
        foreach (var audit in new[] { false, true })
        foreach (var reverse in new[] { false, true })
        {
            var source = audit
                ? Sd.ObjAce(7, (byte)(reverse ? 0x82 : 0x42), 0x10, reverse ? 2u : 3u,
                    reverse ? null : Guid.Empty, Sd.G2, Sd.U1)
                : Sd.ObjAce(5, (byte)(reverse ? 0x0A : 0), 0x10, reverse ? 3u : 1u,
                    Sd.G1, reverse ? Sd.G2 : null, Sd.U1);
            var requested = audit ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var sid = new B.SecurityIdentifier(Sd.U1, 0);
            for (var index = 0; index < 2; index++)
            {
                var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
                bool? returned = null, modified = null;
                string? exception = null, message = null;
                byte[] ruleBytes = Array.Empty<byte>();
                var requestedRule = audit
                    ? Sd.ObjAce(7, (byte)(reverse ? 0x42 : 0x82), 0x10, reverse ? 3u : 2u,
                        reverse ? Guid.Empty : null, Sd.G2, Sd.U1)
                    : Sd.ObjAce(5, (byte)(reverse ? 0 : 0x0A), 0x10, reverse ? 1u : 3u,
                        Sd.G1, reverse ? null : Sd.G2, Sd.U1);
                try
                {
                    if (audit)
                    {
                        var rule = new M.ActiveDirectoryAuditRule(sid, M.ActiveDirectoryRights.ReadProperty,
                            reverse ? E.AuditFlags.Success : E.AuditFlags.Failure,
                            Guid.Empty, M.ActiveDirectorySecurityInheritance.All, Sd.G2);
                        ruleBytes = RuleBytes(rule);
                        returned = descriptor.ModifyAuditRule(E.AccessControlModification.Add, rule, out var changed);
                        modified = changed;
                    }
                    else
                    {
                        var rule = new M.ActiveDirectoryAccessRule(sid, M.ActiveDirectoryRights.ReadProperty,
                            E.AccessControlType.Allow, Sd.G1,
                            reverse ? M.ActiveDirectorySecurityInheritance.None : M.ActiveDirectorySecurityInheritance.Descendents,
                            reverse ? Guid.Empty : Sd.G2);
                        ruleBytes = RuleBytes(rule);
                        returned = descriptor.ModifyAccessRule(E.AccessControlModification.Add, rule, out var changed);
                        modified = changed;
                    }
                }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
                observations.Add(new Observation($"later-merge-{(audit ? "audit-empty-ot" : "scope-iot")}-{reverse}",
                    index, audit ? "Sacl" : "Dacl", "Add", "S-1-5-21-1-2-3-1001", Convert.ToHexString(ruleBytes),
                    input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                    Convert.ToHexString(requestedRule), index == 0 ? Convert.ToHexString(requested) : null));
            }
        }
    }

    private static void RecordAsymmetricObjectMaskAdds(List<Observation> observations)
    {
        var masks = new (uint Existing, uint Incoming)[]
        {
            (0x10, 0x10), (0x10, 0x14), (0x14, 0x10), (0x10, 0x30),
            (4, 0x14), (0x30, 0x14), (0x14, 0x24),
        };
        foreach (var pair in masks)
        foreach (var reverse in new[] { false, true })
        foreach (var mode in new[] { "Dacl", "AuditSuccess", "AuditFailure" })
        {
            var audit = mode != "Dacl";
            var existingFlags = reverse ? 3u : 2u;
            var source = Sd.ObjAce((byte)(audit ? 7 : 5), (byte)(audit ? 0x42 : 2),
                pair.Existing, existingFlags, reverse ? Sd.G1 : null, Sd.G2, Sd.U1);
            var requested = audit ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes = Array.Empty<byte>();
            try
            {
                var sid = new B.SecurityIdentifier(Sd.U1, 0);
                var ot = reverse ? Guid.Empty : Sd.G1;
                if (audit)
                {
                    var rule = new M.ActiveDirectoryAuditRule(sid, (M.ActiveDirectoryRights)pair.Incoming,
                        mode == "AuditSuccess" ? E.AuditFlags.Success : E.AuditFlags.Failure,
                        ot, M.ActiveDirectorySecurityInheritance.All, Sd.G2);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAuditRule(E.AccessControlModification.Add, rule, out var changed);
                    modified = changed;
                }
                else
                {
                    var rule = new M.ActiveDirectoryAccessRule(sid, (M.ActiveDirectoryRights)pair.Incoming,
                        E.AccessControlType.Allow, ot, M.ActiveDirectorySecurityInheritance.All, Sd.G2);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAccessRule(E.AccessControlModification.Add, rule, out var changed);
                    modified = changed;
                }
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"asymmetric-object-mask-{pair.Existing:X}-{pair.Incoming:X}-{reverse}-{mode}",
                0, audit ? "Sacl" : "Dacl", "Add", "S-1-5-21-1-2-3-1001", Convert.ToHexString(ruleBytes),
                input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                RequestedDescriptorHex: Convert.ToHexString(requested)));
        }
    }

    private static void RecordObjectOiAndCombinedSequences(List<Observation> observations)
    {
        foreach (var objectFlags in new uint[] { 1, 2, 3 })
        foreach (var flags in new byte[] { 1, 3, 5, 7, 9, 11, 13, 15 })
        foreach (var operation in new[] { "RemoveNone", "RemoveAllScope", "RemoveDescendents", "AddAllScope" })
        foreach (var audit in new[] { false, true })
        {
            Guid? ot = (objectFlags & 1) != 0 ? Sd.G1 : null;
            Guid? it = (objectFlags & 2) != 0 ? Sd.G2 : null;
            var source = Sd.ObjAce((byte)(audit ? 7 : 5), (byte)(flags | (audit ? 0xC0 : 0)),
                0x14, objectFlags, ot, it, Sd.U1);
            var requested = audit ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var scope = operation == "RemoveNone" ? M.ActiveDirectorySecurityInheritance.None
                : operation == "RemoveDescendents" ? M.ActiveDirectorySecurityInheritance.Descendents
                : M.ActiveDirectorySecurityInheritance.All;
            Capture($"object-oi-{objectFlags}-{flags}-{operation}-{(audit ? "Sacl" : "Dacl")}", 0,
                descriptor, audit, operation == "AddAllScope" ? "Add" : "Remove",
                operation == "AddAllScope" ? 0x14u : 0x10u, ot ?? Guid.Empty, it ?? Guid.Empty, scope,
                operation == "AddAllScope" ? E.AuditFlags.Success | E.AuditFlags.Failure : E.AuditFlags.Success, requested);
        }
        foreach (var noPropagate in new[] { false, true })
        {
            var flags = (byte)(noPropagate ? 7 : 3);
            var requested = Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4,
                Sd.ObjAce(5, flags, 0x14, 3, Sd.G1, Sd.G1, Sd.U1),
                Sd.Ace(1, Sd.Inherited | Sd.Ci, 0x20, Sd.U2)));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var sequence = $"combined-object-oi-dacl-{flags}";
            var steps = new (string Operation, uint Mask, Guid Ot, Guid It, M.ActiveDirectorySecurityInheritance Scope)[]
            {
                ("Remove", 0x14, Sd.G2, Sd.G2, M.ActiveDirectorySecurityInheritance.All),
                ("Remove", 0x14, Sd.G2, Sd.G2, M.ActiveDirectorySecurityInheritance.Descendents),
                ("Protect", 0, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("Remove", 0x10, Sd.G1, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("Unprotect", 0, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("Remove", 4, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.All),
                ("ProtectDrop", 0, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("RemoveSpecific", 0x10, Sd.G1, Sd.G1, noPropagate ? M.ActiveDirectorySecurityInheritance.Children : M.ActiveDirectorySecurityInheritance.Descendents),
            };
            for (var index = 0; index < steps.Length; index++)
            {
                var step = steps[index];
                Capture(sequence, index, descriptor, false, step.Operation, step.Mask, step.Ot, step.It,
                    step.Scope, E.AuditFlags.Success, index == 0 ? requested : null);
            }
        }
        {
            var requested = Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4,
                Sd.ObjAce(7, 0xC3, 0x14, 3, Sd.G1, Sd.G1, Sd.U1),
                Sd.Ace(2, 0x50, 0x20, Sd.U2)));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var steps = new (string Operation, uint Mask, Guid Ot, Guid It, M.ActiveDirectorySecurityInheritance Scope)[]
            {
                ("Remove", 0x20, Sd.G1, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("Remove", 4, Sd.G2, Sd.G2, M.ActiveDirectorySecurityInheritance.All),
                ("Owner", 0, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("Set", 0x10, Sd.G1, Sd.G1, M.ActiveDirectorySecurityInheritance.All),
                ("Protect", 0, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("Unprotect", 0, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("ProtectDrop", 0, Guid.Empty, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
                ("RemoveSpecific", 0x10, Sd.G1, Sd.G1, M.ActiveDirectorySecurityInheritance.All),
            };
            for (var index = 0; index < steps.Length; index++)
            {
                var step = steps[index];
                Capture("combined-object-oi-sacl", index, descriptor, true, step.Operation, step.Mask,
                    step.Ot, step.It, step.Scope, E.AuditFlags.Success, index == 0 ? requested : null);
            }
        }

        void Capture(string sequence, int index, M.ActiveDirectorySecurity descriptor, bool audit,
            string operation, uint mask, Guid ot, Guid it, M.ActiveDirectorySecurityInheritance scope,
            E.AuditFlags auditFlags, byte[]? requested)
        {
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            var sid = new B.SecurityIdentifier(operation == "Owner" ? Sd.U2 : Sd.U1, 0);
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes = Array.Empty<byte>();
            try
            {
                if (operation == "Owner") descriptor.SetOwner(sid);
                else if (operation is "Protect" or "ProtectDrop" or "Unprotect")
                {
                    if (audit) descriptor.SetAuditRuleProtection(operation != "Unprotect", operation != "ProtectDrop");
                    else descriptor.SetAccessRuleProtection(operation != "Unprotect", operation != "ProtectDrop");
                }
                else if (audit)
                {
                    var rule = new M.ActiveDirectoryAuditRule(sid, (M.ActiveDirectoryRights)mask, auditFlags, ot, scope, it);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAuditRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var changed);
                    modified = changed;
                }
                else
                {
                    var rule = new M.ActiveDirectoryAccessRule(sid, (M.ActiveDirectoryRights)mask, E.AccessControlType.Allow, ot, scope, it);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var changed);
                    modified = changed;
                }
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation(sequence, index, audit ? "Sacl" : "Dacl", operation, sid.Value,
                Convert.ToHexString(ruleBytes), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                returned, modified, exception, message, RequestedDescriptorHex: requested is null ? null : Convert.ToHexString(requested)));
        }
    }

    private static void RecordInheritedGuidAndObjectInherit(List<Observation> observations)
    {
        var cases = new List<(string Name, byte Flags, uint Mask, Guid? ExistingIt,
            uint RuleMask, Guid RuleIt, M.ActiveDirectorySecurityInheritance Scope, string Operation, Guid? ExistingOt, Guid RuleOt)>();
        foreach (var flags in new byte[] { 2, 6, 10, 14 })
        foreach (var scope in new[] { M.ActiveDirectorySecurityInheritance.All, M.ActiveDirectorySecurityInheritance.Descendents })
            cases.Add(($"distinct-inherited-{flags}-{scope}", flags, 0x30, Sd.G1, 0x10, Sd.G2, scope, "Remove", null, Guid.Empty));
        foreach (var flags in new byte[] { 1, 3, 5, 7, 9, 11, 13, 15 })
        {
            foreach (var scope in new[] { M.ActiveDirectorySecurityInheritance.None, M.ActiveDirectorySecurityInheritance.All, M.ActiveDirectorySecurityInheritance.Descendents })
                cases.Add(($"oi-{flags}-remove-{scope}", flags, 0x30, null, 0x10, Guid.Empty, scope, "Remove", null, Guid.Empty));
            cases.Add(($"oi-{flags}-add-same-mask", flags, 0x10, null, 0x10, Guid.Empty, M.ActiveDirectorySecurityInheritance.None, "Add", null, Guid.Empty));
        }
        foreach (var mask in new uint[] { 0x10, 0x14 })
        foreach (var scope in new[] { M.ActiveDirectorySecurityInheritance.All, M.ActiveDirectorySecurityInheritance.Descendents })
            cases.Add(($"distinct-both-guids-{mask}-{scope}", 2, mask, Sd.G1, mask, Sd.G2, scope, "Remove", Sd.G1, Sd.G2));
        foreach (var flags in new byte[] { 2, 10 })
        foreach (var scope in new[] { M.ActiveDirectorySecurityInheritance.All, M.ActiveDirectorySecurityInheritance.Descendents })
            cases.Add(($"missing-object-guid-distinct-inherited-{flags}-{scope}", flags, 0x10, Sd.G1, 0x10, Sd.G2, scope, "Remove", null, Sd.G2));
        foreach (var test in cases)
        foreach (var audit in new[] { false, true })
        {
            var flags = (byte)(test.Flags | (audit ? 0xC0 : 0));
            var source = test.ExistingIt.HasValue
                ? Sd.ObjAce((byte)(audit ? 7 : 5), flags, test.Mask, test.ExistingOt.HasValue ? 3u : 2u, test.ExistingOt, test.ExistingIt, Sd.U1)
                : Sd.Ace((byte)(audit ? 2 : 0), flags, test.Mask, Sd.U1);
            var requested = audit ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(requested);
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes = Array.Empty<byte>();
            try
            {
                var sid = new B.SecurityIdentifier(Sd.U1, 0);
                var operation = Enum.Parse<E.AccessControlModification>(test.Operation);
                if (audit)
                {
                    var rule = new M.ActiveDirectoryAuditRule(sid, (M.ActiveDirectoryRights)test.RuleMask,
                        E.AuditFlags.Success, test.RuleOt, test.Scope, test.RuleIt);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAuditRule(operation, rule, out var changed);
                    modified = changed;
                }
                else
                {
                    var rule = new M.ActiveDirectoryAccessRule(sid, (M.ActiveDirectoryRights)test.RuleMask,
                        E.AccessControlType.Allow, test.RuleOt, test.Scope, test.RuleIt);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAccessRule(operation, rule, out var changed);
                    modified = changed;
                }
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"propagation-{test.Name}-{(audit ? "Sacl" : "Dacl")}", 0,
                audit ? "Sacl" : "Dacl", test.Operation, "S-1-5-21-1-2-3-1001", Convert.ToHexString(ruleBytes),
                input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message,
                RequestedDescriptorHex: Convert.ToHexString(requested)));
        }
    }

    private static void RecordRemovalScopePrecedence(List<Observation> observations)
    {
        var cases = new (string Name, byte Flags, uint ObjectFlags, Guid? Ot, Guid? It,
            Guid RemoveOt, Guid RemoveIt, M.ActiveDirectorySecurityInheritance Scope, E.AuditFlags Audit)[]
        {
            ("self-vs-qualified-descendants", 0, 0, null, null, Sd.G1, Guid.Empty, M.ActiveDirectorySecurityInheritance.Descendents, E.AuditFlags.Success),
            ("descendants-vs-qualified-self", 10, 0, null, null, Sd.G1, Guid.Empty, M.ActiveDirectorySecurityInheritance.None, E.AuditFlags.Success),
            ("self-vs-inherited-guid-all", 0, 0, null, null, Guid.Empty, Sd.G1, M.ActiveDirectorySecurityInheritance.All, E.AuditFlags.Success),
            ("self-unused-inherited-guid", 0, 3, Sd.G1, Sd.G2, Sd.G1, Sd.G1, M.ActiveDirectorySecurityInheritance.All, E.AuditFlags.Success),
            ("propagating-inherited-guid-narrowing", 2, 0, null, null, Guid.Empty, Sd.G1, M.ActiveDirectorySecurityInheritance.All, E.AuditFlags.Success),
            ("qualified-before-audit-disjoint", 0, 0, null, null, Sd.G1, Guid.Empty, M.ActiveDirectorySecurityInheritance.None, E.AuditFlags.Failure),
        };
        foreach (var test in cases)
        foreach (var audit in new[] { false, true })
        {
            var flags = (byte)(test.Flags | (audit ? 0x40 : 0));
            var source = test.ObjectFlags == 0 ? Sd.Ace((byte)(audit ? 2 : 0), flags, 0x10, Sd.U1)
                : Sd.ObjAce((byte)(audit ? 7 : 5), flags, 0x10, test.ObjectFlags, test.Ot, test.It, Sd.U1);
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(audit
                ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source)));
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes = Array.Empty<byte>();
            try
            {
                var sid = new B.SecurityIdentifier(Sd.U1, 0);
                if (audit)
                {
                    var rule = new M.ActiveDirectoryAuditRule(sid, M.ActiveDirectoryRights.ReadProperty,
                        test.Audit, test.RemoveOt, test.Scope, test.RemoveIt);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAuditRule(E.AccessControlModification.Remove, rule, out var changed);
                    modified = changed;
                }
                else
                {
                    var rule = new M.ActiveDirectoryAccessRule(sid, M.ActiveDirectoryRights.ReadProperty,
                        E.AccessControlType.Allow, test.RemoveOt, test.Scope, test.RemoveIt);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAccessRule(E.AccessControlModification.Remove, rule, out var changed);
                    modified = changed;
                }
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"remove-precedence-{test.Name}-{(audit ? "Sacl" : "Dacl")}", 0,
                audit ? "Sacl" : "Dacl", "Remove", "S-1-5-21-1-2-3-1001", Convert.ToHexString(ruleBytes),
                input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message));
        }
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

    private static void RecordMixedObjectRemovals(List<Observation> observations)
    {
        // Object GUIDs constrain only object-specific mask bits, and inherited-object GUIDs
        // constrain propagation. Observe mixed residuals before choosing portable behavior.
        var cases = new (string Name, uint Mask, byte Flags, uint ObjectFlags, Guid? Ot, Guid? It,
            uint RemoveMask, Guid RemoveOt, M.ActiveDirectorySecurityInheritance Scope)[]
        {
            ("mixed-different-object", 0x14, 0, 1, Sd.G1, null, 0x14, Sd.G2, M.ActiveDirectorySecurityInheritance.None),
            ("mixed-remove-specific-leaves-global", 0x14, 0, 1, Sd.G1, null, 0x10, Sd.G1, M.ActiveDirectorySecurityInheritance.None),
            ("mixed-remove-global", 0x14, 0, 1, Sd.G1, null, 4, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
            ("mixed-inherited-guid-remove-global-self", 0x14, Sd.Ci, 3, Sd.G1, Sd.G2, 4, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
            ("both-guids-remove-wp-self", 0x30, Sd.Ci, 3, Sd.G1, Sd.G2, 0x20, Guid.Empty, M.ActiveDirectorySecurityInheritance.None),
            ("inherited-guid-remove-descendants", 0x30, Sd.Ci, 2, null, Sd.G2, 0x30, Guid.Empty, M.ActiveDirectorySecurityInheritance.Descendents),
        };
        foreach (var test in cases)
        foreach (var audit in new[] { false, true })
        {
            var source = Sd.ObjAce((byte)(audit ? 7 : 5), (byte)(test.Flags | (audit ? 0x40 : 0)),
                test.Mask, test.ObjectFlags, test.Ot, test.It, Sd.U1);
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(audit
                ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, source))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, source)));
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            byte[] ruleBytes = Array.Empty<byte>();
            try
            {
                var sid = new B.SecurityIdentifier(Sd.U1, 0);
                if (audit)
                {
                    var rule = new M.ActiveDirectoryAuditRule(sid, (M.ActiveDirectoryRights)test.RemoveMask,
                        E.AuditFlags.Success, test.RemoveOt, test.Scope, Guid.Empty);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAuditRule(E.AccessControlModification.Remove, rule, out var changed);
                    modified = changed;
                }
                else
                {
                    var rule = new M.ActiveDirectoryAccessRule(sid, (M.ActiveDirectoryRights)test.RemoveMask,
                        E.AccessControlType.Allow, test.RemoveOt, test.Scope, Guid.Empty);
                    ruleBytes = RuleBytes(rule);
                    returned = descriptor.ModifyAccessRule(E.AccessControlModification.Remove, rule, out var changed);
                    modified = changed;
                }
            }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation($"object-remove-{test.Name}-{(audit ? "Sacl" : "Dacl")}", 0,
                audit ? "Sacl" : "Dacl", "Remove", "S-1-5-21-1-2-3-1001", Convert.ToHexString(ruleBytes),
                input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()), returned, modified, exception, message));
        }
    }

    private static void RecordRevisionAndAbsentAudit(List<Observation> observations)
    {
        foreach (var populated in new[] { false, true })
        foreach (var operation in new[] { E.AccessControlModification.Add, E.AccessControlModification.Set, E.AccessControlModification.Reset })
        {
            var acl = populated ? Sd.Acl(2, Sd.Ace(0, 0, 0x20, Sd.U1)) : Sd.Acl(2);
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(Sd.Build(Sd.Admins, Sd.Admins, acl));
            var rule = new M.ActiveDirectoryAccessRule(new B.SecurityIdentifier(Sd.U1, 0),
                M.ActiveDirectoryRights.ReadProperty, E.AccessControlType.Allow, Sd.G1);
            Capture($"revision2-{(populated ? "common" : "empty")}-{operation}", descriptor, "Dacl", operation.ToString(), RuleBytes(rule),
                () => { var returned = descriptor.ModifyAccessRule(operation, rule, out var modified); return (returned, modified); });
        }
        {
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(Sd.Build(Sd.Admins, Sd.Admins,
                Sd.Acl(2, Sd.ObjAce(5, 0, 0x10, 1, Sd.G1, null, Sd.U1))));
            var rule = new M.ActiveDirectoryAccessRule(new B.SecurityIdentifier(Sd.U2, 0),
                M.ActiveDirectoryRights.WriteProperty, E.AccessControlType.Allow);
            Capture("revision2-already-object-common-add", descriptor, "Dacl", "Add", RuleBytes(rule),
                () => { var returned = descriptor.ModifyAccessRule(E.AccessControlModification.Add, rule, out var modified); return (returned, modified); }, trustee: "S-1-5-21-1-2-3-1002");
        }
        foreach (var nullSacl in new[] { false, true })
        foreach (var operation in new[] { E.AccessControlModification.Remove, E.AccessControlModification.RemoveAll, E.AccessControlModification.RemoveSpecific })
        {
            var input = Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4));
            if (nullSacl) input[2] |= 0x10; // SACL_PRESENT with zero SACL offset.
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(input);
            var rule = new M.ActiveDirectoryAuditRule(new B.SecurityIdentifier(Sd.U1, 0),
                M.ActiveDirectoryRights.ReadProperty, E.AuditFlags.Success);
            Capture($"{(nullSacl ? "null" : "absent")}-sacl-{operation}", descriptor, "Sacl", operation.ToString(), RuleBytes(rule),
                () => { var returned = descriptor.ModifyAuditRule(operation, rule, out var modified); return (returned, modified); }, requestedInput: input);
        }

        void Capture(string sequence, M.ActiveDirectorySecurity descriptor, string section,
            string operation, byte[] rule, Func<(bool Returned, bool Modified)> action,
            string trustee = "S-1-5-21-1-2-3-1001", byte[]? requestedInput = null)
        {
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            try { (returned, modified) = action(); }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation(sequence, 0, section, operation, trustee,
                Convert.ToHexString(rule), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                returned, modified, exception, message, RequestedDescriptorHex: requestedInput is null ? null : Convert.ToHexString(requestedInput)));
        }
    }

    private static void RecordRestorationAndSidOrder(List<Observation> observations)
    {
        var cases = new (string Name, byte[] Input, (E.AccessControlModification Operation, uint Mask)[] Steps)[]
        {
            ("split-then-restore", Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, Sd.Ace(0, Sd.Ci, 0x30, Sd.U1))),
                new[] { (E.AccessControlModification.Remove, 0x20u), (E.AccessControlModification.Add, 0x20u), (E.AccessControlModification.Add, 0x20u) }),
            ("import-split-then-restore", Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4,
                Sd.Ace(0, Sd.Ci, 0x10, Sd.U1), Sd.Ace(0, Sd.Ci | Sd.Io, 0x20, Sd.U1))),
                new[] { (E.AccessControlModification.Add, 0x20u), (E.AccessControlModification.Add, 0x20u) }),
            ("import-complementary-scopes", Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4,
                Sd.Ace(0, 0, 0x10, Sd.U1), Sd.Ace(0, Sd.Ci | Sd.Io, 0x10, Sd.U1))),
                new[] { (E.AccessControlModification.Add, 0x10u), (E.AccessControlModification.Add, 0x10u) }),
        };
        foreach (var test in cases)
        {
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(test.Input);
            var index = 0;
            foreach (var (operation, mask) in test.Steps)
            {
                var rule = new M.ActiveDirectoryAccessRule(new B.SecurityIdentifier(Sd.U1, 0),
                    (M.ActiveDirectoryRights)mask, E.AccessControlType.Allow);
                Capture(test.Name, index++, descriptor, operation, rule, test.Input);
            }
        }
        foreach (var adminsFirst in new[] { true, false })
        {
            var input = Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4,
                Sd.Ace(0, 0, 0x10, adminsFirst ? Sd.Admins : Sd.U1)));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(input);
            var rule = new M.ActiveDirectoryAccessRule(new B.SecurityIdentifier(adminsFirst ? Sd.U1 : Sd.Admins, 0),
                M.ActiveDirectoryRights.WriteProperty, E.AccessControlType.Allow);
            Capture($"sid-order-{(adminsFirst ? "admins-first" : "domain-first")}", 0, descriptor,
                E.AccessControlModification.Add, rule, input);
        }

        void Capture(string sequence, int index, M.ActiveDirectorySecurity descriptor,
            E.AccessControlModification operation, M.ActiveDirectoryAccessRule rule, byte[] requestedInput)
        {
            var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
            bool? returned = null, modified = null;
            string? exception = null, message = null;
            try { returned = descriptor.ModifyAccessRule(operation, rule, out var changed); modified = changed; }
            catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
            observations.Add(new Observation(sequence, index, "Dacl", operation.ToString(), rule.IdentityReference.Value,
                Convert.ToHexString(RuleBytes(rule)), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                returned, modified, exception, message,
                RequestedDescriptorHex: index == 0 ? Convert.ToHexString(requestedInput) : null));
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
        bool? Modified, string? ExceptionType, string? ExceptionMessage, string? RequestedRuleHex = null, string? RequestedDescriptorHex = null);
}
