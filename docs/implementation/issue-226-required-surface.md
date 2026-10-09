# Required portable security surface manifest

The target is the **full required public/protected dependency closure**, not a byte-only descriptor facade or a selected subset of convenient members. The approved destination remains `AdForLinux.Security.Principal` and `AdForLinux.Security.AccessControl` in the existing `AdForLinux.DirectoryServices` DLL. The ten AD classes retain their existing names and namespace. This manifest defines the inventory to implement and review; it does not itself switch the public AD hierarchy or claim that all recorded members already work portably.

## Authoritative recording

`docs/research/acl-windows-oracle/RequiredSurface.cs` exposes `RequiredSurface.Write(path)`. The oracle program invokes it through `--surface-json PATH`; the Windows offline workflow records both net8 and net10 with the existing pinned Microsoft System.DirectoryServices 9.0.0 package. Reflection reads metadata only: it never constructs identities or descriptors, invokes reflected members, resolves account names, opens a directory, persists security, or changes privileges. The output has schema `issue-226-required-surface-v1`.

The recorder has 39 explicit roots. Following return and parameter types alone would miss concrete ACE subclasses and some identity helpers, so these roots are deliberate:

- `ActiveDirectorySecurity` and all nine AD rule classes.
- `IdentityReference`, `SecurityIdentifier`, `NTAccount`, `IdentityReferenceCollection`, `IdentityNotMappedException`.
- `AuthorizationRule`, `AccessRule`, `AuditRule`, `ObjectAccessRule`, `ObjectAuditRule`, `AuthorizationRuleCollection`, `ObjectSecurity`, `DirectoryObjectSecurity`.
- `GenericSecurityDescriptor`, `RawSecurityDescriptor`, `CommonSecurityDescriptor`.
- `GenericAcl`, `RawAcl`, `CommonAcl`, `DiscretionaryAcl`, `SystemAcl`, `AceEnumerator`.
- `GenericAce`, `KnownAce`, `QualifiedAce`, `CommonAce`, `ObjectAce`, `CompoundAce`, `CustomAce`.

The graph recursively follows public/protected constructors, methods, fields, properties and index parameters, event types, base classes, interfaces, generic arguments and constraints, array/by-ref/pointer element types, and custom signature modifiers. Referenced security/principal types and AD enums are expanded. The recorder fails if a root or signature dependency is not represented. Enums include their underlying type and literal constants.

## Schema and comparison rules

`Types` contains deterministic, ordinally sorted declared-member records. A type includes its base and interfaces, class/enum/interface kind, abstract/sealed flags, assembly, generic parameters, and attributes. Each member has a stable `Key` containing kind, declaring type, name, generic arity and argument types where applicable. Return/property/field types remain separate structured fields. Method records retain parameter names, positions, `in`/`out`/optional/default metadata, custom modifiers, attributes, accessibility, static/abstract/virtual/final/new-slot flags, calling convention and base definition. Constructor GUID order is consequently explicit, not inferred from parameter types alone.

Properties include both accessor records, with each accessor's actual visibility. This distinguishes a protected getter-only property from a field or a public property with a restricted setter. Indexers retain their index parameter list. Events include add/remove/raise metadata. Accessor methods are also present among declared methods, intentionally; consumers must not count them as additional properties. Attributes are metadata observations, not permission to run the associated behavior.

`InheritedDeclarations` references public/protected base declarations, including shadowed declarations. Combined with the base graph and `BaseDefinition`, it preserves where a contract comes from and whether an override remains virtual or is sealed. It is not a flattened list of callable overloads. Constructors are not inherited. `NonSurfaceConstructors` separately records internal/private construction constraints; these are evidence about extensibility, not a request to publish additional constructors.

`FrameworkBoundary` explicitly lists retained framework dependencies outside the security replacement families: primitives, strings, GUIDs, arrays' element types, reflection types, collection/serialization infrastructure, exceptions, and safe handles, as encountered. These framework types are not recursively replaced. Framework base member references (for example `System.Object` or collection infrastructure) can therefore terminate outside `Types`. Security enum expansion likewise does not imply replacing approved shared framework enums. Custom attributes are captured as metadata, not recursively promoted into replacement types.

`Framework`, `RuntimeIdentifier`, `OperatingSystem`, and `AssemblyProvenance` capture recording provenance, including assembly identity, module version ID and informational version. Compare the structured surface separately from this runtime provenance. Do not require whole-file net8/net10 equality or silently discard runtime surface differences. Paths, timestamps and reflection enumeration order do not participate in member identity.

## Acceptance checks and implementation dependencies

The checked-in Windows recordings from .NET 8.0.31 and .NET 10.0.12 each contain exactly 39 roots, 55 security types, 702 declared members (including accessors and enum constants), and 28 framework boundaries. Both identify System.DirectoryServices 9.0.0.0. The surface tests assert those measured counts, all 55 type names, the root set, and critical descriptor/ACL/protected-hook contracts so a dropped family cannot silently shrink the implementation target. These are inventory completeness checks, not a claim that all members are implemented. Structural checks verify all 39 roots, all nine AD rule classes and their 45 public constructors, the ACL indexers, both `RawAcl` public constructors, the generic descriptor SDDL exporter, and the out-bool mutation hooks. Regenerate and compare the complete manifest after implementation; passing those spot checks alone is insufficient.

The required closure includes binary and SDDL constructors/exporters, raw and common descriptor owner/group/ACL members, raw ACL construction/indexing/insertion/removal, common ACL construction/indexing/mutation, ACE binary and opaque-payload APIs, identity collections, and the complete security/rule base contracts. A numerically portable SID foundation cannot erase name-translation signatures; offline translation behavior requires explicit implementation/behavior evidence and must never introduce implicit network access.

In particular, `ObjectSecurity.SecurityDescriptor` is a protected, nonvirtual, getter-only **property** of `CommonSecurityDescriptor`. `IsContainer` and `IsDS` are protected getter-only properties. The four protected dirty flags have protected get/set accessors. The protected abstract hooks are `bool ModifyAccess(AccessControlModification, AccessRule, out bool)` and `bool ModifyAudit(AccessControlModification, AuditRule, out bool)`; DirectoryObjectSecurity overrides them without sealing them. Protected constructors, lock hooks, persistence hooks, public virtual factories and inherited relationships must survive the eventual substitution. Recording persistence signatures does not authorize directory operations.

Implement the supporting closure while the existing AD classes still use the BCL hierarchy. Switch the AD security class, all nine rules, corresponding consumers and tests together once their portable dependencies compile. There must be no parallel AD API and no interim removal of protected hooks. DirectoryEntry's raw write preparation must be adapted to the portable descriptor before enabling its Windows commit path; owner/group/ACL selection and write intent must continue to use preserved raw storage. AccountManagement identity consumers and public SID exposure require coordinated migration as well. This foundation slice leaves the existing AD public classes and transport paths untouched.

The manifest proves API shape only. Constructor validation, SDDL behavior, mutable facade ownership, shared descriptor mutation visibility, lock semantics, dirty flags, identity translation, raw preservation and write-intent behavior still need their own detached observations and tests. It does not resolve them by reflection or claim they are complete.

`PortableSecurityFoundationTests.Surface.cs` consumes both checked-in Windows manifests as embedded resources `AclOracle.Surface.net8.json` and `AclOracle.Surface.net10.json`. It uses an explicit 27-type substitution map for the five current identity/collection/exception types, six rule/collection types, seven ACE types, six ACL/enumerator types, and three descriptor types; it does not rewrite an entire framework namespace. For each implemented type it checks every recorded declared public/protected member, rejects extra members, and compares signatures, parameter names, accessibility, method dispatch flags, base definitions, custom modifiers, constants, and type/base/interface shape. Compiler attributes and nullable annotations are retained in the manifest but are not asserted as binary signature parity. Private accessor implementation details are outside that comparison. Missing manifests fail the test rather than skip it.

The pointer constructor follow-up closes the last declared SID member gap; no gap remains within the 27 mapped types. The `WellKnownSidType`/domain-SID constructor and `IsWellKnown(WellKnownSidType)` are now implemented and must match the complete recorded member shapes. This requires the domain-SID property and helpers to be implemented; it does not allow them to disappear silently. Remove each gap as the member is implemented, and expand the exact type map as the remaining required closure lands. API-shape matching does not waive the separate numeric parsing, alias, translation, validation or behavioral replay obligations.


The detached ACL/descriptor follow-up is tracked in [closure status](issue-226-closure-status.md).
Its 3,268 native observations distinguish 2,292 exact successful outcomes, 940 exact native
exceptions and 36 explicit portable refusals. Surface parity for the 27 mapped types is an
API-shape check, not a claim of parity for deferred SDDL or of completion of ObjectSecurity,
DirectoryObjectSecurity, context-bound resolution or the AD hierarchy cutover.
