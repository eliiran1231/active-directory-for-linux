using E = System.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;

internal static partial class SeededSequences
{
    private static void RecordSignedSidOrdering(List<Observation> observations)
    {
        // Microsoft's SID ordering uses unchecked signed subtraction. Pairwise
        // boundaries and the five-value sequence deliberately expose wraparound
        // and possible nontransitivity; outputs are always read from Microsoft.
        uint[] boundaries = [0, 1, 2147483647, 2147483648, 4294967295];
        var shapes = new List<(string Name, uint[] Values)>();
        for (var i = 0; i < boundaries.Length; i++)
        for (var j = i + 1; j < boundaries.Length; j++)
            shapes.Add(($"{boundaries[i]}-{boundaries[j]}", [boundaries[i], boundaries[j]]));
        shapes.Add(("all-five", boundaries));
        foreach (var audit in new[] { false, true })
        foreach (var reverse in new[] { false, true })
        foreach (var shape in shapes)
        {
            var values = reverse ? shape.Values.AsEnumerable().Reverse().ToArray() : shape.Values;
            var aces = values.Select(value => Sd.Ace((byte)(audit ? 2 : 0), (byte)(audit ? 0x40 : 0), 0x30,
                Sd.Sid($"S-1-5-{value}"))).ToArray();
            var raw = audit
                ? Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4), sacl: Sd.Acl(4, aces))
                : Sd.Build(Sd.Admins, Sd.Admins, Sd.Acl(4, aces), sacl: Sd.Acl(4));
            var descriptor = new M.ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(raw);
            var suffix = $"{shape.Name}-{audit}-{reverse}";
            observations.Add(new Observation($"import-signed-sid-{suffix}", 0, audit ? "Sacl" : "Dacl", "Import",
                $"S-1-5-{values[0]}", "", Convert.ToHexString(raw), Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                null, null, null, null, RequestedDescriptorHex: Convert.ToHexString(raw)));
            var index = 0;
            // Start with two unmatched removals and an already-covered addition:
            // actual before/after bytes establish which operations are noops.
            Capture("Remove", 2, 0x10000);
            Capture("RemoveSpecific", 2, 0x10000);
            Capture("Add", values[0], 0x10);
            Capture("Add", 2, 0x40);
            Capture("Remove", values[0], 0x10);
            Capture("Set", values[^1], 0x80);
            Capture("Get", values[0], 0);

            void Capture(string operation, uint value, int mask)
            {
                var input = Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm());
                var sid = new B.SecurityIdentifier($"S-1-5-{value}");
                var rule = Array.Empty<byte>();
                bool? returned = null, modified = null;
                string? exception = null, message = null;
                try
                {
                    if (operation == "Get")
                    {
                        _ = descriptor.GetAccessRules(true, true, typeof(B.SecurityIdentifier));
                        _ = descriptor.GetAuditRules(true, true, typeof(B.SecurityIdentifier));
                        _ = descriptor.GetSecurityDescriptorBinaryForm();
                    }
                    else if (audit)
                    {
                        var auditing = new M.ActiveDirectoryAuditRule(sid, (M.ActiveDirectoryRights)mask, E.AuditFlags.Success);
                        rule = RuleBytes(auditing);
                        returned = descriptor.ModifyAuditRule(Enum.Parse<E.AccessControlModification>(operation), auditing, out var changed);
                        modified = changed;
                    }
                    else
                    {
                        var access = new M.ActiveDirectoryAccessRule(sid, (M.ActiveDirectoryRights)mask, E.AccessControlType.Allow);
                        rule = RuleBytes(access);
                        returned = descriptor.ModifyAccessRule(Enum.Parse<E.AccessControlModification>(operation), access, out var changed);
                        modified = changed;
                    }
                }
                catch (Exception ex) { exception = ex.GetType().FullName; message = ex.Message; }
                observations.Add(new Observation($"projected-live-signed-sid-{suffix}", index, audit ? "Sacl" : "Dacl", operation,
                    sid.Value, Convert.ToHexString(rule), input, Convert.ToHexString(descriptor.GetSecurityDescriptorBinaryForm()),
                    returned, modified, exception, message, RequestedDescriptorHex: index == 0 ? Convert.ToHexString(raw) : null));
                index++;
            }
        }
    }
}
