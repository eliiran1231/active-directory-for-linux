namespace AdForLinux.DifferentialTests;

// Exact approved substitutions, not a namespace-wide exemption. Framework enums
// and every other signature/type remain subject to the existing strict comparisons.
internal static class PortableSecurityContract
{
    internal static readonly IReadOnlyDictionary<Type, Type> Types = new Dictionary<Type, Type>
    {
        [typeof(AdForLinux.Security.Principal.IdentityReference)] = typeof(System.Security.Principal.IdentityReference),
        [typeof(AdForLinux.Security.Principal.IdentityReferenceCollection)] = typeof(System.Security.Principal.IdentityReferenceCollection),
        [typeof(AdForLinux.Security.Principal.IdentityNotMappedException)] = typeof(System.Security.Principal.IdentityNotMappedException),
        [typeof(AdForLinux.Security.Principal.SecurityIdentifier)] = typeof(System.Security.Principal.SecurityIdentifier),
        [typeof(AdForLinux.Security.Principal.NTAccount)] = typeof(System.Security.Principal.NTAccount),
        [typeof(AdForLinux.Security.AccessControl.AuthorizationRule)] = typeof(System.Security.AccessControl.AuthorizationRule),
        [typeof(AdForLinux.Security.AccessControl.AccessRule)] = typeof(System.Security.AccessControl.AccessRule),
        [typeof(AdForLinux.Security.AccessControl.AuditRule)] = typeof(System.Security.AccessControl.AuditRule),
        [typeof(AdForLinux.Security.AccessControl.ObjectAccessRule)] = typeof(System.Security.AccessControl.ObjectAccessRule),
        [typeof(AdForLinux.Security.AccessControl.ObjectAuditRule)] = typeof(System.Security.AccessControl.ObjectAuditRule),
        [typeof(AdForLinux.Security.AccessControl.AuthorizationRuleCollection)] = typeof(System.Security.AccessControl.AuthorizationRuleCollection),
        [typeof(AdForLinux.Security.AccessControl.GenericAce)] = typeof(System.Security.AccessControl.GenericAce),
        [typeof(AdForLinux.Security.AccessControl.KnownAce)] = typeof(System.Security.AccessControl.KnownAce),
        [typeof(AdForLinux.Security.AccessControl.QualifiedAce)] = typeof(System.Security.AccessControl.QualifiedAce),
        [typeof(AdForLinux.Security.AccessControl.CommonAce)] = typeof(System.Security.AccessControl.CommonAce),
        [typeof(AdForLinux.Security.AccessControl.ObjectAce)] = typeof(System.Security.AccessControl.ObjectAce),
        [typeof(AdForLinux.Security.AccessControl.CompoundAce)] = typeof(System.Security.AccessControl.CompoundAce),
        [typeof(AdForLinux.Security.AccessControl.CustomAce)] = typeof(System.Security.AccessControl.CustomAce),
        [typeof(AdForLinux.Security.AccessControl.GenericAcl)] = typeof(System.Security.AccessControl.GenericAcl),
        [typeof(AdForLinux.Security.AccessControl.RawAcl)] = typeof(System.Security.AccessControl.RawAcl),
        [typeof(AdForLinux.Security.AccessControl.CommonAcl)] = typeof(System.Security.AccessControl.CommonAcl),
        [typeof(AdForLinux.Security.AccessControl.DiscretionaryAcl)] = typeof(System.Security.AccessControl.DiscretionaryAcl),
        [typeof(AdForLinux.Security.AccessControl.SystemAcl)] = typeof(System.Security.AccessControl.SystemAcl),
        [typeof(AdForLinux.Security.AccessControl.AceEnumerator)] = typeof(System.Security.AccessControl.AceEnumerator),
        [typeof(AdForLinux.Security.AccessControl.ObjectSecurity)] = typeof(System.Security.AccessControl.ObjectSecurity),
        [typeof(AdForLinux.Security.AccessControl.DirectoryObjectSecurity)] = typeof(System.Security.AccessControl.DirectoryObjectSecurity),
        [typeof(AdForLinux.Security.AccessControl.GenericSecurityDescriptor)] = typeof(System.Security.AccessControl.GenericSecurityDescriptor),
        [typeof(AdForLinux.Security.AccessControl.RawSecurityDescriptor)] = typeof(System.Security.AccessControl.RawSecurityDescriptor),
        [typeof(AdForLinux.Security.AccessControl.CommonSecurityDescriptor)] = typeof(System.Security.AccessControl.CommonSecurityDescriptor),
    };
    internal static Type? Map(Type? type) => type is not null && Types.TryGetValue(type, out var mapped) ? mapped : type;
    internal static string NormalizeName(string name) => Types.FirstOrDefault(pair => pair.Key.FullName == name).Value?.FullName ?? name;
}
