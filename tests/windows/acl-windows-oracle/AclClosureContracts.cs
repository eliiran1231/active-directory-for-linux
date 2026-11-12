using System.Collections;
using System.Security.AccessControl;
using System.Security.Principal;

internal static class AclClosureContracts
{
    internal static void Record(Action<string, object, Func<object?>> record)
    {
        foreach (var revision in new byte[] { 0, 1, 2, 4, 255 })
        foreach (var capacity in new[] { -1, 0, 1 })
            record($"AclRawConstruct-{revision}-{capacity}", new { Revision = revision, Capacity = capacity }, () => AclContractSnapshot(new RawAcl(revision, capacity)));
        foreach (var action in new[] { "insert", "replace", "remove", "copy", "enumerate", "enumerator-before", "enumerator-after", "copy-small", "copy-negative", "copy-rank", "insert-negative", "insert-high", "replace-negative", "replace-high", "remove-negative", "remove-high", "insert-null", "replace-null" })
            record($"AclRawBehavior-{action}", new { Action = action }, () =>
            {
                var raw = AclContractRaw();
                switch (action)
                {
                    case "insert":
                        var inserted = new CustomAce((AceType)255, AceFlags.None, new byte[] { 1, 2, 3, 4 });
                        raw.InsertAce(1, inserted); inserted.AceFlags = AceFlags.Inherited;
                        return new { Aliases = ReferenceEquals(inserted, raw[1]), State = AclContractSnapshot(raw) };
                    case "replace":
                        var replacement = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x40, AclContractSid(), false, null);
                        raw[0] = replacement; replacement.AccessMask = 0x80;
                        return new { Aliases = ReferenceEquals(replacement, raw[0]), State = AclContractSnapshot(raw) };
                    case "remove": raw.RemoveAce(0); return AclContractSnapshot(raw);
                    case "copy":
                        var target = new GenericAce[raw.Count + 2]; raw.CopyTo(target, 1);
                        target[1].AceFlags = AceFlags.Inherited;
                        return new { Aliases = ReferenceEquals(target[1], raw[0]), State = AclContractSnapshot(raw), NullEdges = target[0] is null && target[^1] is null };
                    case "enumerate":
                        var enumerator = raw.GetEnumerator(); var counts = new List<int>();
                        while (enumerator.MoveNext()) counts.Add(enumerator.Current.BinaryLength);
                        enumerator.Reset(); return new { Lengths = counts, ResetMove = enumerator.MoveNext(), Aliases = ReferenceEquals(enumerator.Current, raw[0]) };
                    case "enumerator-before": return raw.GetEnumerator().Current;
                    case "enumerator-after": var end = raw.GetEnumerator(); while (end.MoveNext()) { } return end.Current;
                    case "copy-small": raw.CopyTo(new GenericAce[1], 0); break;
                    case "copy-negative": raw.CopyTo(new GenericAce[4], -1); break;
                    case "copy-rank": ((ICollection)raw).CopyTo(new GenericAce[2, 2], 0); break;
                    case "insert-negative": raw.InsertAce(-1, raw[0]); break;
                    case "insert-high": raw.InsertAce(3, raw[0]); break;
                    case "replace-negative": raw[-1] = raw[0]; break;
                    case "replace-high": raw[2] = raw[0]; break;
                    case "remove-negative": raw.RemoveAce(-1); break;
                    case "remove-high": raw.RemoveAce(2); break;
                    case "insert-null": raw.InsertAce(0, null!); break;
                    case "replace-null": raw[0] = null!; break;
                }
                return AclContractSnapshot(raw);
            });
        foreach (var audit in new[] { false, true })
        foreach (var container in new[] { false, true })
        foreach (var ds in new[] { false, true })
        foreach (var action in new[] { "import", "index-clone", "index-set", "common-mutate", "object-mutate", "rule-overload", "purge-inherited", "noncanonical" })
            record($"AclCommon-{audit}-{container}-{ds}-{action}", new { Audit = audit, Container = container, DS = ds, Action = action }, () =>
            {
                var raw = new RawAcl(4, 4);
                var qualifier = audit ? AceQualifier.SystemAudit : AceQualifier.AccessAllowed;
                var flags = audit ? AceFlags.SuccessfulAccess : AceFlags.None;
                raw.InsertAce(0, new CommonAce(flags, qualifier, 0x10, AclContractSid(), false, null));
                raw.InsertAce(1, new CommonAce(flags, qualifier, 0x20, AclContractSid(), false, null));
                raw.InsertAce(2, new CommonAce(flags | AceFlags.Inherited, qualifier, 0x40, AclContractSid(), false, null));
                if (action == "noncanonical")
                {
                    raw.RemoveAce(2);
                    raw.InsertAce(0, new CommonAce(flags | AceFlags.Inherited, qualifier, 0x40, AclContractSid(), false, null));
                }
                CommonAcl acl = audit ? new SystemAcl(container, ds, raw) : new DiscretionaryAcl(container, ds, raw);
                if (action == "import") return new { Imported = AclContractSnapshot(acl), AclContractRaw = AclContractSnapshot(raw), acl.IsCanonical, acl.IsContainer, acl.IsDS };
                if (action == "index-clone")
                {
                    var read = acl[0]; read.AceFlags ^= AceFlags.Inherited;
                    return new { Aliases = ReferenceEquals(read, acl[0]), State = AclContractSnapshot(acl) };
                }
                if (action == "index-set") { acl[0] = raw[0]; return AclContractSnapshot(acl); }
                if (action == "purge-inherited")
                {
                    acl.RemoveInheritedAces(); var explicitOnly = AclContractSnapshot(acl); acl.Purge(AclContractSid());
                    return new { ExplicitOnly = explicitOnly, Purged = AclContractSnapshot(acl) };
                }
                if (action == "noncanonical") { acl.Purge(AclContractSid()); return AclContractSnapshot(acl); }
                var states = new List<object>();
                var inheritance = container ? InheritanceFlags.ContainerInherit : InheritanceFlags.None;
                var propagation = PropagationFlags.None;
                var guid = Guid.Parse("11111111-1111-1111-1111-111111111111");
                var objectFlags = ObjectAceFlags.ObjectAceTypePresent;
                if (acl is DiscretionaryAcl dacl)
                {
                    if (action == "common-mutate")
                    {
                        dacl.AddAccess(AccessControlType.Allow, AclContractSid(), 0x40, inheritance, propagation); states.Add(AclContractSnapshot(dacl));
                        dacl.SetAccess(AccessControlType.Allow, AclContractSid(), 0x30, inheritance, propagation); states.Add(AclContractSnapshot(dacl));
                        states.Add(new { Removed = dacl.RemoveAccess(AccessControlType.Allow, AclContractSid(), 0x10, inheritance, propagation), State = AclContractSnapshot(dacl) });
                        dacl.RemoveAccessSpecific(AccessControlType.Allow, AclContractSid(), 0x20, inheritance, propagation);
                    }
                    else if (action == "object-mutate")
                    {
                        dacl.AddAccess(AccessControlType.Allow, AclContractSid(), 0x10, inheritance, propagation, objectFlags, guid, Guid.Empty); states.Add(AclContractSnapshot(dacl));
                        dacl.SetAccess(AccessControlType.Allow, AclContractSid(), 0x30, inheritance, propagation, objectFlags, guid, Guid.Empty); states.Add(AclContractSnapshot(dacl));
                        states.Add(new { Removed = dacl.RemoveAccess(AccessControlType.Allow, AclContractSid(), 0x10, inheritance, propagation, objectFlags, guid, Guid.Empty), State = AclContractSnapshot(dacl) });
                        dacl.RemoveAccessSpecific(AccessControlType.Allow, AclContractSid(), 0x20, inheritance, propagation, objectFlags, guid, Guid.Empty);
                    }
                    else
                    {
                        var rule = new AclContractAccessRule(AclContractSid(), 0x10, inheritance, guid);
                        dacl.AddAccess(AccessControlType.Allow, AclContractSid(), rule); states.Add(AclContractSnapshot(dacl));
                        dacl.SetAccess(AccessControlType.Allow, AclContractSid(), rule); states.Add(AclContractSnapshot(dacl));
                        states.Add(new { Removed = dacl.RemoveAccess(AccessControlType.Allow, AclContractSid(), rule), State = AclContractSnapshot(dacl) });
                        dacl.RemoveAccessSpecific(AccessControlType.Allow, AclContractSid(), rule);
                    }
                }
                else
                {
                    var sacl = (SystemAcl)acl;
                    if (action == "common-mutate")
                    {
                        sacl.AddAudit(AuditFlags.Success, AclContractSid(), 0x40, inheritance, propagation); states.Add(AclContractSnapshot(sacl));
                        sacl.SetAudit(AuditFlags.Success, AclContractSid(), 0x30, inheritance, propagation); states.Add(AclContractSnapshot(sacl));
                        states.Add(new { Removed = sacl.RemoveAudit(AuditFlags.Success, AclContractSid(), 0x10, inheritance, propagation), State = AclContractSnapshot(sacl) });
                        sacl.RemoveAuditSpecific(AuditFlags.Success, AclContractSid(), 0x20, inheritance, propagation);
                    }
                    else if (action == "object-mutate")
                    {
                        sacl.AddAudit(AuditFlags.Success, AclContractSid(), 0x10, inheritance, propagation, objectFlags, guid, Guid.Empty); states.Add(AclContractSnapshot(sacl));
                        sacl.SetAudit(AuditFlags.Success, AclContractSid(), 0x30, inheritance, propagation, objectFlags, guid, Guid.Empty); states.Add(AclContractSnapshot(sacl));
                        states.Add(new { Removed = sacl.RemoveAudit(AuditFlags.Success, AclContractSid(), 0x10, inheritance, propagation, objectFlags, guid, Guid.Empty), State = AclContractSnapshot(sacl) });
                        sacl.RemoveAuditSpecific(AuditFlags.Success, AclContractSid(), 0x20, inheritance, propagation, objectFlags, guid, Guid.Empty);
                    }
                    else
                    {
                        var rule = new AclContractAuditRule(AclContractSid(), 0x10, inheritance, guid);
                        sacl.AddAudit(AclContractSid(), rule); states.Add(AclContractSnapshot(sacl));
                        sacl.SetAudit(AclContractSid(), rule); states.Add(AclContractSnapshot(sacl));
                        states.Add(new { Removed = sacl.RemoveAudit(AclContractSid(), rule), State = AclContractSnapshot(sacl) });
                        sacl.RemoveAuditSpecific(AclContractSid(), rule);
                    }
                }
                states.Add(AclContractSnapshot(acl)); return states;
            });
        foreach (var hex in new[] { "0200080000000000", "0201080000000203", "02000C0000000000AABBCCDD", "02000C0001000000FF000400", "0200080001000000", "0200070000000000", "0200080000000000AABBCCDD" })
            record($"AclRawParse-{hex}", new { Hex = hex }, () => AclContractSnapshot(new RawAcl(Convert.FromHexString(hex), 0)));
        foreach (var offset in new[] { -1, 0, 1, int.MaxValue })
        {
            record($"AclReadOffset-{offset}", new { Offset = offset }, () => AclContractSnapshot(new RawAcl(new byte[] { 2, 0, 8, 0, 0, 0, 0, 0 }, offset)));
            record($"AclWriteOffset-{offset}", new { Offset = offset }, () => { var bytes = new byte[8]; new RawAcl(2, 0).GetBinaryForm(bytes, offset); return Convert.ToHexString(bytes); });
        }
    }

    private static SecurityIdentifier AclContractSid() => new("S-1-5-21-1-2-3-1001");
    private static RawAcl AclContractRaw()
    {
        var raw = new RawAcl(4, 2);
        raw.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x10, AclContractSid(), false, null));
        raw.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20, AclContractSid(), false, null));
        return raw;
    }
    private static object AclContractSnapshot(GenericAcl acl)
    {
        var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0);
        return new { Type = acl.GetType().Name, acl.Revision, acl.Count, Length = acl.BinaryLength, Hex = Convert.ToHexString(bytes), acl.IsSynchronized, SyncRootSelf = ReferenceEquals(acl, acl.SyncRoot) };
    }
    private sealed class AclContractAccessRule : ObjectAccessRule
    {
        internal AclContractAccessRule(SecurityIdentifier sid, int mask, InheritanceFlags inheritance, Guid guid)
            : base(sid, mask, false, inheritance, PropagationFlags.None, guid, Guid.Empty, AccessControlType.Allow) { }
    }
    private sealed class AclContractAuditRule : ObjectAuditRule
    {
        internal AclContractAuditRule(SecurityIdentifier sid, int mask, InheritanceFlags inheritance, Guid guid)
            : base(sid, mask, false, inheritance, PropagationFlags.None, guid, Guid.Empty, AuditFlags.Success) { }
    }
}
