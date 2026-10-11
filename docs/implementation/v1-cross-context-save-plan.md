# Bounded same-domain cross-controller Save(context)

Status: read-only preflight and refusal boundary implemented; cross-controller
execution remains disabled. No live AD operation has been run for this change.

The current preflight is advisory and insufficient to enable execution. Its
generic DirectorySearcher path can hide references or accept partial results;
parsed DN ancestry is not server-attested naming-context membership. Cached NC
discovery, separately reopened reads and absence of an operation-wide generation
check do not establish one stable endpoint/session proof. The unconditional
cross-context refusal must remain until the dedicated response-aware transport
below replaces these assumptions. Do not promote a returned plan to authority.

## Current bounded behavior

Before a persisted principal switches to a different connection context, read
fresh domain GUID/SID through each endpoint's own authority. Read the source
object by its current DN, compare its GUID with the principal's captured identity
and retained entry identity, then locate the destination replica by GUID and
require the same SID. Missing/duplicate/inaccessible replicas refuse; there is no
fallback to a DN-only match. Verify a destination container GUID and its naming
context at parsed RDN boundaries. Referrals are disabled for these proof reads.

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
   A bounded operation session must use each endpoint's own authority, retain
   the exact connections and owner generations, reject non-success/partial or
   referred responses, discover the NC freshly and obtain domain-scope server
   evidence for membership. Check the captured generations again before every
   request and publication. This dedicated transport is not yet implemented.
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
