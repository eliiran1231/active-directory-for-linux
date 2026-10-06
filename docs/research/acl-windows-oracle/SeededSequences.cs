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
                        ? Sd.Ace((byte)(isAudit ? 2 : 0), (byte)(isAudit ? 0x40 : 0), rights, Sd.Sid(trustee))
                        : Sd.ObjAce((byte)(isAudit ? 7 : 5), (byte)(isAudit ? 0x40 : 0), rights, 1, objectType, null, Sd.Sid(trustee));
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
                                E.AuditFlags.Success, objectType, M.ActiveDirectorySecurityInheritance.None, Guid.Empty);
                            returned = descriptor.ModifyAuditRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var changed);
                            modified = changed;
                        }
                        else
                        {
                            var rule = new M.ActiveDirectoryAccessRule(sid, (M.ActiveDirectoryRights)rights,
                                E.AccessControlType.Allow, objectType, M.ActiveDirectorySecurityInheritance.None, Guid.Empty);
                            returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(operation), rule, out var changed);
                            modified = changed;
                        }
                    }
                    catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
                    observations.Add(new Observation(sequence, index++, section, operation, trustee,
                        Convert.ToHexString(ruleBytes), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                        returned, modified, exception, message));
                }
            }
        }
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, JsonSerializer.Serialize(new
        {
            SchemaVersion = 1, Seed = seed,
            Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription,
            MicrosoftAssembly = typeof(M.ActiveDirectorySecurity).Assembly.FullName,
            Scope = "Detached in-memory objects only; no DirectoryEntry, LDAP, Persist, token or privilege changes. Observations require review before replay acceptance.",
            Observations = observations,
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Recorded {observations.Count} seeded observations to {path}");
    }

    private sealed record Observation(string Sequence, int Index, string Section, string Operation,
        string Sid, string RuleHex, string InputHex, string OutputHex, bool? ReturnValue,
        bool? Modified, string? ExceptionType, string? ExceptionMessage);
}
