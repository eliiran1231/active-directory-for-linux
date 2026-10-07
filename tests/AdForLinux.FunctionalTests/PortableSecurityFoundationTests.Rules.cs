#pragma warning disable CA1416 // Framework access-control enums are values; no Windows APIs are invoked.
using System.Collections;
using System.Reflection;
using System.Security.AccessControl;
using Xunit;
using P = AdForLinux.Security.Principal;
using A = AdForLinux.Security.AccessControl;

namespace AdForLinux.FunctionalTests;

/// <summary>Pure managed public foundation contracts; no directory fixture or connection.</summary>
public partial class PortableSecurityFoundationTests
{
    private static P.SecurityIdentifier RuleSid() => new("S-1-5-21-1-2-3-1001");

    [Fact]
    public void Rule_bases_accept_portable_names_without_translation_and_keep_identity_instance()
    {
        var identity = new P.NTAccount("EXAMPLE", "alice");
        var rule = new FoundationAccess(identity, -1, true, InheritanceFlags.ContainerInherit,
            PropagationFlags.InheritOnly, AccessControlType.Deny);
        Assert.Same(identity, rule.IdentityReference);
        Assert.Equal(-1, rule.Mask);
        Assert.True(rule.IsInherited);
        Assert.Equal(InheritanceFlags.ContainerInherit, rule.InheritanceFlags);
        Assert.Equal(PropagationFlags.InheritOnly, rule.PropagationFlags);
        Assert.Equal(AccessControlType.Deny, rule.AccessControlType);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Propagation_is_cleared_only_without_inheritance(int propagation)
    {
        foreach (var inheritance in new[] { 0, 1, 2, 3 })
        {
            var rule = new FoundationAuthorization(RuleSid(), int.MinValue, false,
                (InheritanceFlags)inheritance, (PropagationFlags)propagation);
            Assert.Equal(inheritance == 0 ? PropagationFlags.None : (PropagationFlags)propagation,
                rule.PropagationFlags);
            Assert.Equal(int.MinValue, rule.Mask);
        }
    }

    [Fact]
    public void Rule_constructor_validation_precedence_and_parameter_names_are_stable()
    {
        var sid = RuleSid();
        Assert.Equal("identity", Assert.Throws<ArgumentNullException>(() => new FoundationAccess(null!, 0,
            false, (InheritanceFlags)(-1), (PropagationFlags)(-1), (AccessControlType)9)).ParamName);
        Assert.Equal("accessMask", Assert.Throws<ArgumentException>(() => new FoundationAccess(sid, 0,
            false, (InheritanceFlags)(-1), (PropagationFlags)(-1), (AccessControlType)9)).ParamName);
        Assert.Equal("inheritanceFlags", Assert.Throws<ArgumentOutOfRangeException>(() => new FoundationAccess(sid, 1,
            false, (InheritanceFlags)(-1), (PropagationFlags)(-1), (AccessControlType)9)).ParamName);
        Assert.Equal("propagationFlags", Assert.Throws<ArgumentOutOfRangeException>(() => new FoundationAccess(sid, 1,
            false, InheritanceFlags.None, (PropagationFlags)(-1), (AccessControlType)9)).ParamName);
        Assert.Equal("type", Assert.Throws<ArgumentOutOfRangeException>(() => new FoundationAccess(sid, 1,
            false, InheritanceFlags.None, PropagationFlags.None, (AccessControlType)9)).ParamName);
        Assert.Equal("accessMask", Assert.Throws<ArgumentException>(() => new FoundationAudit(sid, 0,
            false, InheritanceFlags.None, PropagationFlags.None, AuditFlags.None)).ParamName);
        Assert.Equal("auditFlags", Assert.Throws<ArgumentException>(() => new FoundationAudit(sid, 1,
            false, InheritanceFlags.None, PropagationFlags.None, AuditFlags.None)).ParamName);
        Assert.Equal("auditFlags", Assert.Throws<ArgumentOutOfRangeException>(() => new FoundationAudit(sid, 1,
            false, InheritanceFlags.None, PropagationFlags.None, (AuditFlags)(-1))).ParamName);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(4)]
    [InlineData(int.MaxValue)]
    public void Invalid_inheritance_and_propagation_bits_refuse_for_all_rule_families(int invalid)
    {
        foreach (var make in FoundationFactories())
        {
            Assert.Equal("inheritanceFlags", Assert.Throws<ArgumentOutOfRangeException>(() =>
                make((InheritanceFlags)invalid, PropagationFlags.None)).ParamName);
            Assert.Equal("propagationFlags", Assert.Throws<ArgumentOutOfRangeException>(() =>
                make(InheritanceFlags.None, (PropagationFlags)invalid)).ParamName);
        }
    }

    [Fact]
    public void Object_guid_presence_depends_on_exact_rights_and_container_inheritance()
    {
        var objectType = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var inheritedType = Guid.Parse("22222222-2222-2222-2222-222222222222");
        for (var bit = 0; bit < 32; bit++)
        foreach (var inheritance in new[] { 0, 1, 2, 3 })
        {
            var mask = unchecked(1 << bit);
            var expectedObject = (mask & 0x13b) == 0 ? Guid.Empty : objectType;
            var expectedInherited = (inheritance & (int)InheritanceFlags.ContainerInherit) == 0 ? Guid.Empty : inheritedType;
            var expectedFlags = (expectedObject == Guid.Empty ? 0 : 1) | (expectedInherited == Guid.Empty ? 0 : 2);
            var access = new FoundationObjectAccess(RuleSid(), mask, true, (InheritanceFlags)inheritance,
                PropagationFlags.InheritOnly, objectType, inheritedType, AccessControlType.Allow);
            var audit = new FoundationObjectAudit(RuleSid(), mask, true, (InheritanceFlags)inheritance,
                PropagationFlags.InheritOnly, objectType, inheritedType, AuditFlags.Success | AuditFlags.Failure);
            Assert.Equal(expectedObject, access.ObjectType);
            Assert.Equal(expectedObject, audit.ObjectType);
            Assert.Equal(expectedInherited, access.InheritedObjectType);
            Assert.Equal(expectedInherited, audit.InheritedObjectType);
            Assert.Equal((ObjectAceFlags)expectedFlags, access.ObjectFlags);
            Assert.Equal((ObjectAceFlags)expectedFlags, audit.ObjectFlags);
            Assert.Equal(AuditFlags.Success | AuditFlags.Failure, audit.AuditFlags);
        }
        var empty = new FoundationObjectAccess(RuleSid(), -1, false, InheritanceFlags.ContainerInherit,
            PropagationFlags.None, Guid.Empty, Guid.Empty, AccessControlType.Allow);
        Assert.Equal(ObjectAceFlags.None, empty.ObjectFlags);
    }

    [Fact]
    public void Authorization_collection_preserves_order_null_entries_and_standard_copy_behavior()
    {
        var first = new FoundationAccess(RuleSid(), 1, false, 0, 0, AccessControlType.Allow);
        var second = new FoundationAudit(RuleSid(), 2, false, 0, 0, AuditFlags.Success);
        var collection = new A.AuthorizationRuleCollection();
        collection.AddRule(first);
        collection.AddRule(null);
        collection.AddRule(second);
        Assert.Equal(3, collection.Count);
        Assert.Same(first, collection[0]);
        Assert.Null(collection[1]);
        Assert.Same(second, collection[2]);
        Assert.Equal(new A.AuthorizationRule?[] { first, null, second }, collection.Cast<A.AuthorizationRule?>());
        var destination = new A.AuthorizationRule[5];
        collection.CopyTo(destination, 1);
        Assert.Null(destination[0]);
        Assert.Same(first, destination[1]);
        Assert.Null(destination[2]);
        Assert.Same(second, destination[3]);
        Assert.Null(destination[4]);
        Assert.Throws<ArgumentOutOfRangeException>(() => collection[-1]);
        Assert.Throws<ArgumentOutOfRangeException>(() => collection[3]);
        Assert.Throws<ArgumentNullException>(() => collection.CopyTo(null!, 0));
        Assert.Throws<ArgumentException>(() => collection.CopyTo(new A.AuthorizationRule[2], 0));
        Assert.False(((ICollection)collection).IsSynchronized);
        Assert.Same(((ICollection)collection).SyncRoot, ((ICollection)collection).SyncRoot);
    }

    [Fact]
    public void Public_rule_base_constructor_and_mask_accessibility_match_protected_contract()
    {
        var authorization = typeof(A.AuthorizationRule);
        var constructor = Assert.Single(authorization.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic));
        Assert.True(constructor.IsFamilyOrAssembly);
        Assert.True(authorization.GetProperty("AccessMask", BindingFlags.Instance | BindingFlags.NonPublic)!.GetMethod!.IsFamilyOrAssembly);
        foreach (var type in new[] { typeof(A.AccessRule), typeof(A.AuditRule), typeof(A.ObjectAccessRule), typeof(A.ObjectAuditRule) })
        {
            Assert.True(type.IsAbstract);
            Assert.True(Assert.Single(type.GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic)).IsFamily);
        }
        Assert.True(typeof(A.AuthorizationRuleCollection).IsSealed);
        Assert.Equal(typeof(System.Collections.ReadOnlyCollectionBase), typeof(A.AuthorizationRuleCollection).BaseType);
    }

    [Fact]
    public void Invalid_identity_target_is_checked_after_scalar_flags_before_rule_qualifier()
    {
        var identity = new FoundationUnsupportedIdentity();
        Assert.Equal("propagationFlags", Assert.Throws<ArgumentOutOfRangeException>(() => new FoundationAccess(
            identity, 1, false, InheritanceFlags.None, (PropagationFlags)4, (AccessControlType)4)).ParamName);
        Assert.Equal("identity", Assert.Throws<ArgumentException>(() => new FoundationAccess(
            identity, 1, false, InheritanceFlags.None, PropagationFlags.None, (AccessControlType)4)).ParamName);
        Assert.Equal("identity", Assert.Throws<ArgumentException>(() => new FoundationAudit(
            identity, 1, false, InheritanceFlags.None, PropagationFlags.None, AuditFlags.None)).ParamName);
    }

    private sealed class FoundationUnsupportedIdentity : P.IdentityReference
    {
        public override string Value => "unsupported";
        public override bool IsValidTargetType(Type targetType) => false;
        public override P.IdentityReference Translate(Type targetType) => throw new InvalidOperationException("Must not resolve during construction.");
        public override bool Equals(object? o) => ReferenceEquals(this, o);
        public override int GetHashCode() => 0;
        public override string ToString() => Value;
    }

    private static IEnumerable<Func<InheritanceFlags, PropagationFlags, A.AuthorizationRule>> FoundationFactories()
    {
        yield return (i, p) => new FoundationAuthorization(RuleSid(), 1, false, i, p);
        yield return (i, p) => new FoundationAccess(RuleSid(), 1, false, i, p, AccessControlType.Allow);
        yield return (i, p) => new FoundationAudit(RuleSid(), 1, false, i, p, AuditFlags.Success);
        yield return (i, p) => new FoundationObjectAccess(RuleSid(), 1, false, i, p, Guid.Empty, Guid.Empty, AccessControlType.Allow);
        yield return (i, p) => new FoundationObjectAudit(RuleSid(), 1, false, i, p, Guid.Empty, Guid.Empty, AuditFlags.Success);
    }

    private sealed class FoundationAuthorization(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation)
        : A.AuthorizationRule(identity, mask, inherited, inheritance, propagation)
    { public int Mask => AccessMask; }
    private sealed class FoundationAccess(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AccessControlType type)
        : A.AccessRule(identity, mask, inherited, inheritance, propagation, type)
    { public int Mask => AccessMask; }
    private sealed class FoundationAudit(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, AuditFlags flags)
        : A.AuditRule(identity, mask, inherited, inheritance, propagation, flags);
    private sealed class FoundationObjectAccess(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, Guid objectType, Guid inheritedType, AccessControlType type)
        : A.ObjectAccessRule(identity, mask, inherited, inheritance, propagation, objectType, inheritedType, type);
    private sealed class FoundationObjectAudit(P.IdentityReference identity, int mask, bool inherited, InheritanceFlags inheritance, PropagationFlags propagation, Guid objectType, Guid inheritedType, AuditFlags flags)
        : A.ObjectAuditRule(identity, mask, inherited, inheritance, propagation, objectType, inheritedType, flags);
}
