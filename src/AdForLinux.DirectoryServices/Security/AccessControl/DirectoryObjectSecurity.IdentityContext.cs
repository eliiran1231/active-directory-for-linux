#pragma warning disable CA1416
using System.Security.AccessControl;
using AdForLinux.Security.Principal;

namespace AdForLinux.Security.AccessControl;

public abstract partial class DirectoryObjectSecurity
{
    private AuthorizationRuleCollection GetTranslatedRules(bool access, bool includeExplicit, bool includeInherited)
    {
        QualifiedAce[] selected;
        IdentityRead read;
        ReadLock();
        try
        {
            lock (FacadeMutation.Gate)
            {
                var acl = access ? (CommonAcl?)SecurityDescriptor.DiscretionaryAcl : SecurityDescriptor.SystemAcl;
                selected = acl is null ? [] : Enumerable.Range(0, acl.Count).Select(i => acl[i]).OfType<QualifiedAce>()
                    .Where(a => !a.IsCallback && (a.IsInherited ? includeInherited : includeExplicit)
                        && (access ? a.AceQualifier is AceQualifier.AccessAllowed or AceQualifier.AccessDenied : a.AceQualifier == AceQualifier.SystemAudit))
                    .ToArray();
                read = CaptureIdentityRead();
            }
        }
        finally { ReadUnlock(); }
        // Do not resolve excluded rules, callback ACEs or an absent ACL.
        if (selected.Length == 0) return new AuthorizationRuleCollection();
        var identities = ResolveRead(read, selected.Select(a => (IdentityReference)a.SecurityIdentifier).ToArray(), typeof(NTAccount));
        var result = new AuthorizationRuleCollection();
        ReadLock();
        try
        {
            ValidateIdentityRead(read, () => true);
            for (var i = 0; i < selected.Length; i++)
            {
                var ace = selected[i]; var identity = identities[i];
                if (access)
                {
                    var kind = ace.AceQualifier == AceQualifier.AccessAllowed ? AccessControlType.Allow : AccessControlType.Deny;
                    result.AddRule(ace is ObjectAce obj
                        ? AccessRuleFactory(identity, ace.AccessMask, ace.IsInherited, ace.InheritanceFlags, ace.PropagationFlags, kind, obj.ObjectAceType, obj.InheritedObjectAceType)
                        : AccessRuleFactory(identity, ace.AccessMask, ace.IsInherited, ace.InheritanceFlags, ace.PropagationFlags, kind));
                }
                else result.AddRule(ace is ObjectAce obj
                    ? AuditRuleFactory(identity, ace.AccessMask, ace.IsInherited, ace.InheritanceFlags, ace.PropagationFlags, ace.AuditFlags, obj.ObjectAceType, obj.InheritedObjectAceType)
                    : AuditRuleFactory(identity, ace.AccessMask, ace.IsInherited, ace.InheritanceFlags, ace.PropagationFlags, ace.AuditFlags));
            }
            // Factories run outside shared/context gates and may invalidate this read.
            return ValidateIdentityRead(read, () => result);
        }
        finally { ReadUnlock(); }
    }
}
