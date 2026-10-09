# Portable public AD hierarchy and raw entry persistence

This implements the coordinated integration following the four
[approved persistence contracts](issue-226-persistence-decisions.md). It replaces the
previous BCL-rooted path on Windows as well as Linux. It does not change authentication,
TLS, credentials, privileges or preservation policy, and does not evaluate effective access.

## Public dependency closure

`ActiveDirectorySecurity` and the nine existing AD rule classes keep their
`AdForLinux.DirectoryServices` names and now derive from the portable supporting classes.
Their identity parameters use `AdForLinux.Security.Principal.IdentityReference`.
`Principal.Sid` returns the portable `SecurityIdentifier`; `SidValue` remains available.
Consumers must rebuild against the coordinated type substitution. No second AD hierarchy,
conditional Windows base class or new public companion/helper name is introduced.

The complete declared public/protected manifest check now maps 42 implemented types:
the 29 supporting types, ten AD classes and three AD enums. Together with the 13 unchanged
framework enums, this accounts for the required 55 types. The 39 roots and 702 recorded
declarations remain unchanged. Surface completeness does not erase behavioral limitations.
Protected hooks and virtual dispatch remain covered by the existing facade tests.

The 45 AD constructors and 64 factory combinations now execute against portable AD types
on Linux as well as Windows. Windows still compares against actual Microsoft objects;
native oracle recordings have not been altered. Differential consumers use each
implementation's own identity types rather than passing Microsoft identity objects into
portable rules. The AccountManagement consumer has a controlled entry-backed SID test.

## Reads, assignments and Modify requests

The ObjectSecurity loader captures the entry generation and requested section mask before
reading raw bytes. It attaches a destination-specific raw read baseline and revocable
resolver only after the generation is rechecked. Numeric identities remain data-only.
Path changes, close, disposal and descriptor refresh invalidate old bindings.

Assigning the current object preserves its pending intent. Detached assignment requires
explicit section edits and a loaded destination baseline for those sections. It copies
source data into a detached clone of the destination's retained raw/live state, preserves
other pending destination sections, and binds the replacement to the destination. It never
copies the source resolver, credentials, connections or read authority. Unsupported imports
refuse before publishing the replacement.

Commit prepares one Modify request containing ordinary property deltas and, when needed,
one raw `nTSecurityDescriptor` replacement with the exact edited-section SD-flags control.
It never persists `GetSecurityDescriptorBinaryForm()`'s observable projection. Unchanged
unknown callbacks, zero-mask originals and other raw data remain intact. Clean or reverted
descriptor edits send no security request. A clean initialized descriptor is invalidated
after a successful local no-op commit, without a network bind merely for that no-op.
Direct property-cache writes to `nTSecurityDescriptor` refuse because they lack section intent.

Connection creation and request execution occur outside the identity, facade and entry
publication gates. Generation, descriptor version, assignment and property change ledgers
are checked before sending and again before acknowledging success. Property ledgers are
held through acknowledgement so later deltas cannot be erased. A known server rejection
retains the pending state for retry. A missing response, or a successful response followed
by a local race, retains intent and requires explicit refresh/readback before another send.
An already accepted server operation cannot be rolled back locally. This is local race
protection, not a server-side assertion control or protection against other LDAP writers.

## Separate Add planning

Without an explicitly assigned descriptor, Add omits `nTSecurityDescriptor` and leaves
creation defaults to AD. Complete explicit raw input is currently accepted only when all
four sections are known, owner/group are present, both ACLs are present/non-NULL, and both
ACLs are protected. The planner preserves the supplied bytes and emits no SD-flags control:
that control does not scope LDAP Add. A rejected assignment leaves creation state unchanged.

Omitted/NULL/default-dependent and inheriting explicit descriptors remain a temporary
validation gap, not a permanent Linux limitation. The target remains Microsoft-compatible
explicit creation. Controlled request capture establishes what this implementation sends;
it does not establish server defaults, privilege handling, inheritance, normalization or
readback parity. Those require separately authorized live AD validation.

## Validation and remaining work

The new offline tests capture the production request planner through internal transport
seams. They cover combined property/security commits, same-object and detached assignment,
destination pending edits, cache-off writes, failure/retry, uncertain delivery, raw preservation,
Add omission/guards, read/refresh/send lifecycle races, and peer progress while transport
is blocked. They perform no bind or directory operation. Linux full builds and the selected
offline suites run on .NET 8 and .NET 10; exact published-head Windows results are recorded
in the PR verification checkpoint after the push-triggered workflow completes.

The existing 36 SDDL refusals, eight facade refusals and 41 atomic-failure differences remain
explicit. Public interop companion names/exposure, broader structural or ambiguous ACL
edit-back, unrecorded SDDL boundaries, explicit creation variants and ambient identity
pinning remain dependencies. Detached Persist hooks still require an explicit platform
override; entry persistence now has its own raw-safe path. No live AD validation, merge or
issue closure is part of this slice.
