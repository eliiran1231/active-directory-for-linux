# Internal AD rule conversion matrix

This slice stages strict AD subtype snapshots and conversion boundaries while the existing
public AD rule hierarchy remains BCL-based. It adds no public API, optional-companion assembly
name, portable AD subclass hierarchy or persistence behavior. The required-surface inventory
still targets all nine AD rule classes and their 45 public constructors.

`InteropAdRuleValue` retains the exact recognized subtype, the complete existing rule-field
snapshot and `InheritanceType`. `InteropAdRuleCodec` validates fixed specialized rights,
access/audit family, GUID presence, inheritance flags and inherited state before invoking a
target factory. It checks all returned fields and concrete subtype before returning a target.
Unknown current AD subclasses and unknown subtype metadata refuse; specialization is never
silently downgraded to an ordinary access rule.

The internal current-hierarchy adapter supports ordinary access/audit rules and all seven
specializations: ListChildren, CreateChild, DeleteChild, Property, PropertySet, ExtendedRight
and DeleteTree. Current ordinary rules use their existing internal constructors to retain
`IsInherited`; Microsoft ordinary rules use actual public AD-security factories. Specialized
rules use their full public constructors, retain their fixed rights/property semantics and
refuse inherited or other fields those constructors cannot recreate. Property and PropertySet
remain distinct subtypes even when their fields otherwise match. Unrepresentable present-zero
GUID flags, unknown flags, inconsistent inheritance and loss of subclass identity refuse.

Snapshots contain data only. SID/name conversion copies values without translation; it carries
no resolver, credential, connection, directory authority or descriptor freshness token. External
constructor/inspection callbacks run outside the portable mutation gate. Converting a rule does
not mutate a descriptor or grant edit-back authority. Existing descriptor provenance/version
checks remain mandatory and are exercised after rule conversion and failed target validation.

## Directed evidence

The functional test project alone references pinned Microsoft System.DirectoryServices 9.0.0,
matching the existing oracle. The production projects gain no package dependency. On Windows,
tests construct actual Microsoft AD types, inspect all fields and concrete types, compare the
current hierarchy, export through the checked boundary and reconstruct the current subtype.
The test adapter is the Microsoft-side factory/inspector prototype for the eventual optional
companion; it is not a new shipped public converter.

The slice adds 707 offline cases: 450 constructor variants, 177 invalid-input cases, 64 factory
combinations and 16 inventory/subtype/atomicity/freshness guards. The constructor matrix covers
each of the 45 public constructors with ten variants: all five inheritance
modes where present, SID and account-name identities, allow/deny or all valid audit combinations,
read/write property selection, empty/nonempty GUIDs, raw signed masks and rights for which
object GUIDs are irrelevant. Invalid-input cases compare actual Windows exception type and
parameter for null identities, zero masks, invalid access/property/audit values and both lower
and upper inheritance enum bounds. They do not assert localized exception-message parity.
The 64 factory combinations cover ordinary-rule inherited state and raw inheritance/
propagation fields. Guards cover all seven specialized inherited-state/subtype-loss refusals,
unknown subclasses, inconsistent fields, callback locking, no lookup and descriptor freshness.

Linux exercises the immutable field/subtype validation boundary and explicit unsupported-platform
guard. It does **not** construct the current BCL-rooted AD rules or claim native constructor
exception execution. Windows runs the actual constructor/round-trip/exception comparisons.
Exact-head workflow results are recorded on PR228. Existing literal native oracle recordings
are unchanged; this matrix performs directed comparisons at execution time rather than inventing
or synthesizing recordings.

## Remaining dependencies

Public AD/rule/consumer cutover is still required before these same AD class names can be
constructed portably. Public companion exposure, final naming and friend access remain staged.
This does not implement Microsoft AD-security descriptor conversion, opaque/callback rule-list
conversion, generalized structural or ambiguous ACL edit-back, or arbitrary custom subclasses.
The four pending persistence policies, live AD, credential/authentication changes and merge are
outside this slice. Unknown data remains preserved or the complete operation refuses.
