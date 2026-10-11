# Bounded same-domain cross-controller Save(context)

Status: read-only preflight and refusal boundary implemented; cross-controller
execution remains disabled. No live AD operation has been run for this change.

The production preflight now owns one source and one destination LDAP session for
its entire read operation. Each session uses only its context's endpoint and
credentials, disables referrals before binding, and never forwards credentials.
Raw SearchResponse result codes, references and referrals survive to validation;
anything other than a successful, unreferred singleton refuses, including partial
size/time/admin-limit results and response-bearing protocol exceptions. Alias
dereferencing is disabled and the operation has a bounded deadline.

## Current bounded behavior

Read RootDSE freshly on both sessions, require complete naming-context metadata
and domain-scope control support, and read domainDNS objectGUID/objectSid at each
fresh default naming context. Both endpoints must prove the same domain identity.
The source principal is found by its current DN from the verified domain root,
and the destination replica by immutable GUID from its own verified domain root.
Both must match the captured retained GUID/SID and principal's attached GUID.
The destination container is found by DN from the destination domain root and
must supply a valid GUID. Every membership search is a subtree search with the
critical server-side domain-scope control. No text DN suffix, base search at the
candidate DN, cached naming context or independently reopened read is accepted
as domain-membership proof. Subordinate application NCs sharing a suffix cannot
satisfy the required server-scoped membership response.

Source context, destination context and retained entry lifetimes/generations are
captured before opening sessions, rechecked around each request and session open,
and checked together under ordered short-lived gates at final plan publication.
No network operation runs under those gates. Retained cached identity is copied
without lazy loads or cache changes, and rechecked before publication. Missing
cached identity refuses. Session cleanup happens on success and failure. This is
bounded read evidence, not a directory transaction, write-authority proof or
reusable authorization. Directory changes after reads still require identity-safe
write addressing and reconciliation before execution can be enabled.

The plan stores only GUIDs, SID text, DNs and pending Name text. It carries no
owner, credentials, connection, resolver, descriptor, write authority or reusable
authorization token. Pending rename is recorded separately from the replica's
current RDN; ordinary and security edits are not staged, cleared, projected or
transferred during preflight. Execution then refuses before any write, context
switch or binding change, including the formerly misleading same-container case.
The retained DirectoryEntry wrapper and pending principal/entry edits remain.

The existing same-connection MoveTo guard is preserved. The existing Save(context)
catch path now distinguishes an acknowledged forward move from a planned move;
it cannot attempt rollback merely because a target container differed. This does
not establish safe automatic compensation after an uncertain move or write.

## Remaining execution sequence and proof obligations

1. Freeze/check the retained principal identity, entry lifetime/generation,
   pending scalar/extension/SPN edits, property ledger versions and security raw
   intent/provenance. Fresh preflight evidence is not a durable authorization.
   The bounded preflight now owns sessions and checks generations, response
   completeness and server-attested domain membership. An executor must extend
   those checks across writes and publication, rather than reuse a returned plan.
2. Verify destination write targeting against DN reuse. Measure GUID-addressed
   ModifyDN (object and parent) and Modify, or establish an equivalent supported
   atomic identity assertion. A preceding search is not sufficient. Use only the
   destination context's authority; never forward source credentials.
3. Plan pending Name as an escaped new RDN separately from property modifications.
   Keep the current RDN if Name is unchanged. Reject combinations whose ordinary
   or raw security intent cannot be retained faithfully across the move.
4. Track no-send/rejection, acknowledged move, acknowledged scalar write, and
   uncertain delivery separately. Never roll back a merely planned move. A lost
   response quarantines all further writes on the retained wrapper; do not issue
   a compensating move. GUID readback under destination authority must establish
   identity and outcome before any next operation. State needed for this future
   cross-controller quarantine is not implemented by a data-only preflight plan.
5. On verified success, retain the exact DirectoryEntry object, revoke its old
   resolver/lifetime, close source connections, and install destination-owned
   authority coherently. Do not discard pending edits or acknowledge unsent edits.
   Descriptors/snapshots copied from the source never carry authority; stale live
   wrappers must fail after revocation. Context publication follows verified entry
   rebinding; a Context assignment alone is not success.
6. Exercise same/different container, rename, entry/scalar/SPN/security combinations,
   allowed/denied destination credentials, replica absence/conflict, DN reuse,
   rejection, acknowledgement followed by failure, timeout, readback and disposal.
   Compare actual Microsoft behavior where available without weakening the raw
   preservation/refusal boundary to match a destructive native projection.

The [opt-in research probe](../research/cross-dc-save-probe/README.md) is compiled
for .NET 8/10 and prepares narrowly scoped, user-executed measurements of identity
addressing and destination authority on existing fixtures. It neither creates
fixtures nor runs in the offline workflow. Successful probe results are necessary
evidence for the proposed wire forms, not sufficient proof of the full lifecycle.

## Next bounded offline slice and live gate

Offline work can implement an internal executor/state machine behind the existing
unconditional public refusal: freeze edit ledger versions and raw intent; model
not-sent, rejected, acknowledged-move, acknowledged-modify and uncertain outcomes;
permit best-effort compensation only after an acknowledged move and an established
safe target; quarantine ambiguous delivery; reconcile by immutable identity; and
publish a destination-owned binding on the original wrapper only after verified
success. Controlled transports can exercise every transition, edits arriving during
I/O, disposal/rebinding, stale security authority, and cleanup failures. Native
Save(context) moves, then updates, with best-effort compensation; it is not atomic.

The live gate remains separately scoped two-DC authorization on disposable existing
fixtures: measure the exact GUID-addressed ModifyDN object/parent and Modify wire
forms on supported AD/runtime versions; confirm allowed and denied destination
credentials with an independently allowed source; observe same/different containers,
rename plus edits, missing replicas/lag and DN reuse; and verify rejected move,
acknowledged move followed by rejected Modify, uncertain delivery and GUID readback.
Retained-wrapper identity, descriptor authority revocation and pending-edit behavior
must be checked through the public route against native behavior. No live operation
was executed for this slice; the opt-in probe remains preparation only.
