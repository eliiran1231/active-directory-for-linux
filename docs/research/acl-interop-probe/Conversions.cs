// RESEARCH ONLY. Illustrative names; detached copies; Windows BCL target constructors are real.
using System.Runtime.Versioning;
using AdForLinux.DirectoryServices;
using P = AdForLinux.Security.Principal;
using A = AdForLinux.Security.AccessControl;
using M = System.DirectoryServices;
using B = System.Security.Principal;
using E = System.Security.AccessControl;
namespace Research.MicrosoftInterop;

[SupportedOSPlatform("windows")]
internal static class Conversions
{
    public static B.SecurityIdentifier ToMicrosoftObject(this P.SecurityIdentifier sid)
    {
        var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
        return new B.SecurityIdentifier(bytes, 0);
    }
    public static P.SecurityIdentifier FromMicrosoftObject(B.SecurityIdentifier sid)
    {
        var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
        return new P.SecurityIdentifier(bytes, 0);
    }
    public static B.NTAccount ToMicrosoftObject(this P.NTAccount name) => new(name.Value);
    public static P.NTAccount FromMicrosoftObject(B.NTAccount name) => new(name.Value);
    private static B.IdentityReference Export(P.IdentityReference identity) => identity switch
    {
        P.SecurityIdentifier sid => sid.ToMicrosoftObject(),
        P.NTAccount name => name.ToMicrosoftObject(),
        _ => throw new NotSupportedException("Research converter: unsupported identity kind.")
    };
    private static P.IdentityReference Import(B.IdentityReference identity) => identity switch
    {
        B.SecurityIdentifier sid => FromMicrosoftObject(sid),
        B.NTAccount name => FromMicrosoftObject(name),
        _ => throw new NotSupportedException("Research converter: unsupported identity kind.")
    };
    public static M.ActiveDirectoryAccessRule ToMicrosoftObject(this ActiveDirectoryAccessRule rule)
    {
        var identity = Export(rule.IdentityReference); // Value copy, never Translate/name lookup.
        var factory = new M.ActiveDirectorySecurity();
        var result = (M.ActiveDirectoryAccessRule)factory.AccessRuleFactory(identity, (int)rule.ActiveDirectoryRights,
            rule.IsInherited, rule.InheritanceFlags, rule.PropagationFlags, rule.AccessControlType, rule.ObjectType, rule.InheritedObjectType);
        if (result.ObjectFlags != rule.ObjectFlags) throw new NotSupportedException("GUID presence would change.");
        return result;
    }
    public static ActiveDirectoryAccessRule FromMicrosoftObject(M.ActiveDirectoryAccessRule rule) =>
        (ActiveDirectoryAccessRule)new ActiveDirectorySecurity().AccessRuleFactory(Import(rule.IdentityReference),
            (int)rule.ActiveDirectoryRights, rule.IsInherited, rule.InheritanceFlags, rule.PropagationFlags,
            rule.AccessControlType, rule.ObjectType, rule.InheritedObjectType);
    public static M.ActiveDirectoryAuditRule ToMicrosoftObject(this ActiveDirectoryAuditRule rule)
    {
        var identity = Export(rule.IdentityReference);
        var result = (M.ActiveDirectoryAuditRule)new M.ActiveDirectorySecurity().AuditRuleFactory(identity,
            (int)rule.ActiveDirectoryRights, rule.IsInherited, rule.InheritanceFlags, rule.PropagationFlags,
            rule.AuditFlags, rule.ObjectType, rule.InheritedObjectType);
        if (result.ObjectFlags != rule.ObjectFlags) throw new NotSupportedException("GUID presence would change.");
        return result;
    }
    public static ActiveDirectoryAuditRule FromMicrosoftObject(M.ActiveDirectoryAuditRule rule) =>
        (ActiveDirectoryAuditRule)new ActiveDirectorySecurity().AuditRuleFactory(Import(rule.IdentityReference),
            (int)rule.ActiveDirectoryRights, rule.IsInherited, rule.InheritanceFlags, rule.PropagationFlags,
            rule.AuditFlags, rule.ObjectType, rule.InheritedObjectType);
    public static M.ActiveDirectorySecurity ToMicrosoftObject(this ActiveDirectorySecurity descriptor)
    {
        // Only the scaffold's complete, empty-DACL fixture is supported; no unknown/partial data.
        var bytes = descriptor.GetSecurityDescriptorBinaryForm();
        var result = new M.ActiveDirectorySecurity();
        result.SetSecurityDescriptorBinaryForm(bytes);
        return result;
    }
    public static ActiveDirectorySecurity FromMicrosoftObject(M.ActiveDirectorySecurity descriptor, SecurityMasks knownSections)
    {
        if (knownSections != (SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl))
            throw new NotSupportedException("Research converter requires explicit complete-section provenance.");
        var result = new ActiveDirectorySecurity();
        result.SetSecurityDescriptorBinaryForm(descriptor.GetSecurityDescriptorBinaryForm());
        return result;
    }
    public static E.AuthorizationRuleCollection ToMicrosoftObject(this IReadOnlyList<A.AuthorizationRule> rules)
    {
        var result = new E.AuthorizationRuleCollection();
        foreach (var rule in rules)
            result.AddRule(rule switch
            {
                ActiveDirectoryAccessRule access => access.ToMicrosoftObject(),
                ActiveDirectoryAuditRule audit => audit.ToMicrosoftObject(),
                _ => throw new NotSupportedException("Research converter: unknown rule subtype.")
            });
        return result;
    }
    public static IReadOnlyList<A.AuthorizationRule> FromMicrosoftObject(E.AuthorizationRuleCollection rules)
    {
        var result = new List<A.AuthorizationRule>();
        foreach (E.AuthorizationRule rule in rules)
            result.Add(rule switch
            {
                M.ActiveDirectoryAccessRule access => FromMicrosoftObject(access),
                M.ActiveDirectoryAuditRule audit => FromMicrosoftObject(audit),
                _ => throw new NotSupportedException("Research converter: unknown Microsoft rule subtype.")
            });
        return result.AsReadOnly();
    }
}
