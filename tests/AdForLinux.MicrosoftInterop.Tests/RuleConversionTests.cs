using System.Security.AccessControl;
using AdForLinux.DirectoryServices.MicrosoftInterop;
using Xunit;
using D = AdForLinux.DirectoryServices;
using P = AdForLinux.Security.Principal;
using A = AdForLinux.Security.AccessControl;
using M = System.DirectoryServices;
using MP = System.Security.Principal;

namespace AdForLinux.MicrosoftInterop.Tests;

public class RuleConversionTests
{
    private static readonly Guid ObjectType = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid InheritedType = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public static IEnumerable<object[]> KnownRules()
    {
        for (var kind = 0; kind < 9; kind++)
            for (var inheritance = 0; inheritance < 5; inheritance++)
                for (var variant = 0; variant < 4; variant++)
                    yield return new object[] { kind, inheritance, variant };
    }

    [WindowsTheory]
    [MemberData(nameof(KnownRules))]
    public void Every_known_AD_rule_subtype_roundtrips_exact_fields(int kind, int inheritanceValue, int variant)
    {
        P.IdentityReference identity = (variant & 1) == 0 ? new P.SecurityIdentifier("S-1-5-21-1-2-3-1001") : new P.NTAccount("UNRESOLVED\\literal-user");
        var inheritance = (D.ActiveDirectorySecurityInheritance)inheritanceValue;
        var type = (variant & 2) == 0 ? AccessControlType.Allow : AccessControlType.Deny;
        var property = (variant & 2) == 0 ? D.PropertyAccess.Read : D.PropertyAccess.Write;
        var guid = (variant & 2) == 0 ? Guid.Empty : ObjectType;
        var inheritedGuid = (variant & 1) == 0 ? Guid.Empty : InheritedType;
        A.AuthorizationRule source = kind switch
        {
            0 => new D.ActiveDirectoryAccessRule(identity, D.ActiveDirectoryRights.ReadProperty | D.ActiveDirectoryRights.WriteProperty, type, guid, inheritance, inheritedGuid),
            1 => new D.ActiveDirectoryAuditRule(identity, D.ActiveDirectoryRights.ReadProperty, (variant & 2) == 0 ? AuditFlags.Success : AuditFlags.Success | AuditFlags.Failure, guid, inheritance, inheritedGuid),
            2 => new D.ListChildrenAccessRule(identity, type, inheritance, inheritedGuid),
            3 => new D.CreateChildAccessRule(identity, type, guid, inheritance, inheritedGuid),
            4 => new D.DeleteChildAccessRule(identity, type, guid, inheritance, inheritedGuid),
            5 => new D.PropertyAccessRule(identity, type, property, guid, inheritance, inheritedGuid),
            6 => new D.PropertySetAccessRule(identity, type, property, guid, inheritance, inheritedGuid),
            7 => new D.ExtendedRightAccessRule(identity, type, guid, inheritance, inheritedGuid),
            _ => new D.DeleteTreeAccessRule(identity, type, inheritance, inheritedGuid)
        };
        AuthorizationRule native = source is D.ActiveDirectoryAuditRule audit ? audit.ToMicrosoftObject() : ((D.ActiveDirectoryAccessRule)source).ToMicrosoftObject();
        A.AuthorizationRule back = native is M.ActiveDirectoryAuditRule nativeAudit ? nativeAudit.ToPortableObject() : ((M.ActiveDirectoryAccessRule)native).ToPortableObject();
        Assert.Equal(source.GetType().Name, native.GetType().Name);
        Assert.Equal(source.GetType(), back.GetType());
        Assert.Equal(Fields(source), Fields(native));
        Assert.Equal(Fields(source), Fields(back));
        Assert.NotSame(source, back);
        Assert.NotSame(identity, back.IdentityReference);
    }

    [WindowsTheory]
    [InlineData(false)] [InlineData(true)]
    public void Inherited_base_rules_use_factories_and_preserve_inherited_state(bool audit)
    {
        var native = new M.ActiveDirectorySecurity();
        var identity = new MP.SecurityIdentifier("S-1-5-21-1-2-3-1001");
        AuthorizationRule original = audit
            ? native.AuditRuleFactory(identity, 16, true, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AuditFlags.Success, ObjectType, InheritedType)
            : native.AccessRuleFactory(identity, 16, true, InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly, AccessControlType.Allow, ObjectType, InheritedType);
        AuthorizationRule copy = audit ? ((M.ActiveDirectoryAuditRule)original).ToPortableObject().ToMicrosoftObject()
            : ((M.ActiveDirectoryAccessRule)original).ToPortableObject().ToMicrosoftObject();
        Assert.True(copy.IsInherited); Assert.Equal(Fields(original), Fields(copy));
    }

    [WindowsFact]
    public void Identity_and_rule_collections_are_independent_readonly_and_preserve_duplicates()
    {
        var sid = new P.SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var account = new P.NTAccount("Unresolved\\Exact-Spelling");
        Assert.Equal(sid, sid.ToMicrosoftObject().ToPortableObject());
        Assert.Equal(account.Value, account.ToMicrosoftObject().ToPortableObject().Value);
        var ids = new P.IdentityReferenceCollection { sid, account, sid };
        var converted = ids.ToMicrosoftObjects(); ids.Clear();
        Assert.Equal(new[] { sid.Value, account.Value, sid.Value }, converted.Select(i => i.Value));
        Assert.Throws<NotSupportedException>(() => ((IList<MP.IdentityReference>)converted).Clear());
        var nativeIds = new MP.IdentityReferenceCollection { converted[0], converted[1], converted[0] };
        var back = nativeIds.ToPortableObjects(); nativeIds.Clear();
        Assert.Equal(converted.Select(i => i.Value), back.Select(i => i.Value));
        Assert.Throws<NotSupportedException>(() => ((IList<P.IdentityReference>)back).Clear());

        var rule = new D.CreateChildAccessRule(sid, AccessControlType.Allow, ObjectType);
        var rules = new A.AuthorizationRuleCollection(); rules.AddRule(rule); rules.AddRule(rule);
        var nativeRules = rules.ToMicrosoftObjects();
        Assert.Equal(2, nativeRules.Count); Assert.NotSame(nativeRules[0], nativeRules[1]);
        Assert.All(nativeRules, r => Assert.IsType<M.CreateChildAccessRule>(r));
        Assert.Throws<NotSupportedException>(() => ((IList<AuthorizationRule>)nativeRules).Clear());

        var nativeCollection = new AuthorizationRuleCollection();
        nativeCollection.AddRule(nativeRules[0]); nativeCollection.AddRule(nativeRules[0]);
        var duplicateCopies = nativeCollection.ToPortableObjects();
        Assert.Equal(2, duplicateCopies.Count);
        Assert.All(duplicateCopies, r => Assert.IsType<D.CreateChildAccessRule>(r));
        Assert.NotSame(duplicateCopies[0], duplicateCopies[1]);
        Assert.Equal(Fields(rule), Fields(duplicateCopies[0]));
        nativeCollection.AddRule(null);
        Assert.Throws<ArgumentNullException>(() => nativeCollection.ToPortableObjects());
        Assert.Equal(2, duplicateCopies.Count); // Previously returned collection stays independent.

        var sd = new M.ActiveDirectorySecurity(); sd.AddAccessRule((M.ActiveDirectoryAccessRule)nativeRules[0]);
        var portableRules = sd.GetAccessRules(true, false, typeof(MP.SecurityIdentifier)).ToPortableObjects();
        Assert.IsType<D.ActiveDirectoryAccessRule>(Assert.Single(portableRules));
        Assert.Throws<NotSupportedException>(() => ((IList<A.AuthorizationRule>)portableRules).Clear());
    }

    [WindowsFact]
    public void Unsupported_subclasses_and_non_AD_families_refuse_without_partial_results()
    {
        var sid = new P.SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var unsupported = new CustomRule(sid);
        Assert.Throws<NotSupportedException>(() => unsupported.ToMicrosoftObject());
        var collection = new A.AuthorizationRuleCollection();
        collection.AddRule(new D.ActiveDirectoryAccessRule(sid, D.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow));
        collection.AddRule(unsupported);
        Assert.Throws<NotSupportedException>(() => collection.ToMicrosoftObjects());
        Assert.Equal(2, collection.Count);
        Assert.Throws<NotSupportedException>(() => new NativeCustomRule(sid.ToMicrosoftObject()).ToPortableObject());
        var file = new FileSecurity();
        file.AddAccessRule(new FileSystemAccessRule(sid.ToMicrosoftObject(), FileSystemRights.Read, AccessControlType.Allow));
        Assert.Throws<NotSupportedException>(() => file.GetAccessRules(true, false, typeof(MP.SecurityIdentifier)).ToPortableObjects());
    }

    private sealed class CustomRule(P.IdentityReference identity) : D.ActiveDirectoryAccessRule(identity, D.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);
    private sealed class NativeCustomRule(MP.IdentityReference identity) : M.ActiveDirectoryAccessRule(identity, M.ActiveDirectoryRights.ReadProperty, AccessControlType.Allow);

    // Inspect public fields independently of the production codec. No native private reflection.
    private static object?[] Fields(object rule)
    {
        object? Get(string name) => rule.GetType().GetProperty(name)?.GetValue(rule);
        var identity = Get("IdentityReference")!;
        object? Integer(string name) => Get(name) is { } value ? Convert.ToInt32(value) : null;
        return new[] { identity.GetType().Name, identity.GetType().GetProperty("Value")!.GetValue(identity),
            Get("IsInherited"), Integer("InheritanceFlags"), Integer("PropagationFlags"),
            Integer("ActiveDirectoryRights"), Integer("AccessControlType"), Integer("AuditFlags"),
            Integer("ObjectFlags"), Get("ObjectType"), Get("InheritedObjectType"), Integer("InheritanceType") };
    }
}
