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
one raw `nTSecurityDescriptor` replacement with the exact net-changed-section SD-flags control.
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


## Production review corrections

The initial integration at `b6a3af040b71c17e271888fa2d9ce3f8f7d40c35` had four
reviewed gaps. The correction is covered by 45 additional offline cases. Three deterministic
registration interleavings, five uncertain-delivery cases, four mixed-section reversions and
two mixed-rights password cases were also run against the prior implementations: all 14 fail.
No native recording was changed or invented for these local request/atomicity tests.

### Atomic property registration

Previously OnPropertyChanged advanced the entry version before registering its property.
A request could snapshot that new version without the property, then acknowledge success
and clear the subsequently registered but unsent edit. Commit, full refresh and partial
refresh reproduced this exact window with controlled scheduling.

Pending-set membership and version publication now happen together under the entry gate,
before any retained-cache reload. Cache reload failures keep the registered edit. Reload
and cache-off commit execute outside the gate; stale reloads cannot replace a cache that
another operation published. Lifecycle pending-set clearing and lazy cache publication use
the same gate. Tests cover normal/cache-off registration, retained wrappers, failed reload,
peer commit progress, existing pending deltas and stale reload publication.

### Explicit uncertain-write recovery

Uncertainty retains the operation kind, binding generation, exact sent attribute set,
security-section mask, captured property ledgers and descriptor version. A descriptor-only
refresh cannot clear uncertainty for an ordinary property write or combined Modify. Readback
must cover every sent attribute and every written security section; full refresh explicitly
requests those attributes, including ones not implied by LDAP's `*`. Production readback
must find the target object. Failed/incomplete readback keeps the gate closed.

A follow-up review found that the requested attribute names/masks alone were being counted
as successful security readback. A returned object can omit `nTSecurityDescriptor` even when
it was requested. Security recovery now requires exactly one returned binary descriptor,
validated by the retained raw parser, with the read SD-flags covering every uncertain written
section. A full or descriptor refresh with missing, null, nonbinary, malformed, multivalued or
insufficiently covered security data throws before publishing any property cache, discarding
security intent, invalidating its origin or clearing uncertainty. The same handle can retry a
valid readback; it cannot replay the uncertain write in between.

Coverage is supplied by the actual read mask, never guessed from component offsets. Valid
absent/NULL ACLs, opaque ACEs, ACL trailers and unexplained descriptor storage are accepted
without normalization. Ordinary attributes omitted by a successful scoped read still mean
absence/deletion; the descriptor-specific requirement does not change that contract. Readback
establishes current data, not proof that the earlier write was accepted. Sixteen additional
offline cases cover full/partial invalid readback, retained state and later recovery, plus raw
absent/NULL/empty/opaque descriptor states. All twelve new rejection cases failed against the
prior implementation. Existing combined-write and password-consumer recovery fixtures now
return actual descriptor bytes instead of treating an empty property collection as readback.

Recovery clears only the captured ledgers after checking their versions, preventing an old
retained wrapper from resending an already accepted Add delta. Partial readback of the exact
sent attribute set can retain unrelated pending edits. A refresh that would discard newer
unsent property or descriptor edits refuses atomically. A changed binding cannot reconcile
the old request implicitly. This is not an assertion that the server accepted a timed-out
Modify; readback establishes the current baseline and never automatically replays its deltas.

**Uncertain Add cannot be automatically reconciled by this handle.** Add supplies no verified
server-generated object identity when its response is lost. A successful search at the same
DN, even with matching attributes and an objectGUID newly observed during readback, cannot
prove that this request created that object. Refresh therefore refuses to adopt it, retains
creation intent and keeps subsequent Add blocked. The caller must verify the outcome
separately and deliberately acquire an existing-entry handle, or establish absence before
constructing a new creation request. This conservative limit prevents duplicate creation and
wrong-object adoption; neither attribute equality nor DN equality is treated as identity proof.

### Net security sections

Historical write intent and retrieved coverage are still validated. The outgoing mask is
then reduced by comparing each retained raw section to its original read baseline. Reverting
Owner while changing Group sends only Group, and likewise for DACL/SACL protection reversions.
SID/ACL bytes include reserved fields, opaque payloads and ACL trailers; associated control
bits are compared too. Physical repacking of fully understood components does not itself
create a section write. Changed global header state or unexplained storage refuses because
it cannot be attributed safely to an SD-flags section. Observable projection is never used
for this comparison.

### AccountManagement change-password consumer

AuthenticablePrincipal.OnAfterSave now edits the entry-bound portable descriptor and uses
CommitChanges, including raw mask preparation, generation/version checks and delivery recovery.
The legacy immediate descriptor replacement bypass has been removed. Detached proposal
planning runs outside security locks; publication checks the captured entry/descriptor state.

ChangePasswordAcl keeps non-change-password rights in matching mixed-rights ACEs. It validates
its proposed DACL replacement through the shared preservation-aware engine and checks that
the retained-layout proposal matches the approved raw components/storage. Unreviewed revisions,
ACL trailers, reserved ACL fields and opaque ACEs refuse rather than disappearing. Descriptor
section-import safeguards can also refuse layouts such as unexplained gaps. These are visible
consumer preservation limits, not claims of Microsoft parity for those inputs. Tests execute
real UserPrincipal.Save over controlled transport, including DACL-only wire masks, unread
DACL refusal, lifecycle races, known rejection/retry and accepted-then-timeout recovery.
