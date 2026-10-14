# Bounded same-domain cross-controller Save(context)

Status: response-aware preflight and an integrated private scalar executor are
implemented. Public cross-controller execution remains disabled. Live AD
execution proof is still absent.

The production preflight now owns one source and one destination LDAP session for
its entire read operation. A monotonic remaining budget admits each session open,
caps its bind timeout, and is checked after each open, read and final publication.
A source bind that exhausts the budget cannot start a destination bind. Each session uses only its context's endpoint and
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

## Private controlled executor

An internal scalar-only executor now exercises the retained wrapper lifecycle.
It has no default/live transport implementation and no call from public Save.
Only exact UserPrincipal instances with supported nonempty string scalar edits
(including Name) and a clean entry are admitted. Extension, SPN/group, password,
account-control, certificate, logon-hours, deletion and raw/security intent refuse
before sending. These refusals retain intent; unsupported edits are not projected
or silently acknowledged. This narrow scope is not the final compatibility scope.

The executor freezes scalar values and owner generations, reserves the retained
entry and its cached ledgers before preflight, and compares versions and copied
binary cache values. One short-lived operation owns the original source and
destination sessions through preflight, writes, readback and publication. There
is no second destination bind and no API to import a detached plan as authority.
The private slice requires an explicit destination container; it does not open a
separate well-known-container lookup. Source sessions remain read-only, and normal
production sessions cannot dispatch writes. Only an explicitly supplied internal
controlled transport has that capability.

One monotonic deadline starts before owner capture. The remaining budget caps
binds, every search and each controlled write; admission checks it under the same
owner/frozen-state gates used by final publication. Expiry before submission keeps
intent unsent and permits local abandonment. After possible delivery the entry
stays quarantined; a returned success remains acknowledged even if its response
arrived after the deadline. Reconciliation shares the original deadline, cannot
renew it or rebind, and expiry at any read or after source cleanup prevents
publication. Discarding an expired submitted operation closes both sessions but
does not release quarantine. There is no unbounded polling or automatic recovery.

Normal principal/entry mutations, rebinding, Close, refresh and writes refuse while
reserved/quarantined. GUID-addressed ModifyDN and Modify requests are constructed
for a transport supplied only the destination context's settings. No source
credentials, ObjectSecurity or reusable preflight authority cross that boundary.

States distinguish prepared/not-sent, rejected, acknowledged move, acknowledged
Modify, uncertain, readback-verified and published. Execution is single-submit.
An atomic operation admission flag rejects overlapping or reentrant Execute,
Reconcile and Dispose calls without holding owner locks over transport I/O.
Rejected overlapping disposal leaves the active operation and transport intact;
the caller can dispose again after that operation completes.
A rejected first write releases the reservation and retains pending edits; an
acknowledged move followed by rejection or ambiguous delivery stays quarantined.
There is no compensation, retry, or rollback write. Readback cannot acknowledge
unsent scalar edits even if current values happen to match. An uncertain submitted
Modify can reconcile only with complete, unreferred, singleton GUID/SID/domain and
exact value/DN evidence, including a fresh GUID-and-DN proof of the destination
container so a reused parent DN cannot satisfy reconciliation. Reconciliation re-reads RootDSE/domain identity and uses a
critical domain-scope GUID search. Wrong/missing/partial evidence retains quarantine.

Publication closes source connections outside owner locks, then rechecks owners,
ledgers and frozen intent before changing the same entry's endpoint/credentials and
publishing ContextRef. Old property/configuration wrappers and identity resolvers
are revoked. Configuration connection admission rechecks its wrapper under the
entry lifetime gate, lazy property loads pin their binding through schema reads,
and delayed property registration rechecks the captured binding epoch. Tests
overlap these retained-wrapper paths with publication. No replacement Principal.Entry or copied security authority is used.
Source cleanup failure permanently blocks publication for that operation. Disposing
an uncertain/partial executor never unquarantines its wrapper; separately scoped
recovery/new-handle work is required if that executor is discarded.

Retained Children, SchemaFilter and DirectorySearcher handles now capture the entry's
cross-context authority epoch. Publication revokes their provider operations,
including delayed child enumerators and schema-filter writes. Close/refresh do not
change that epoch. Search operations snapshot endpoint credentials before dispatch;
synchronous, paged, attribute-scoped and streaming paths carry that origin through
response decoding and result construction. Schema connection admission and final
result publication recheck the original authority. SearchResult properties and
copied schema arrays remain data; GetDirectoryEntry cannot reacquire a revoked
provider authority. Explicit SearchRoot assignment or a freshly acquired Children
handle obtains the current epoch.

Controlled tests publish while child lookup, search responses, schema decoding and
filter writes are blocked, and before streaming native dispatch. They check stale
refusal with zero destination transport requests, fresh-handle success, preserved
Close/refresh behavior and captured-root behavior on SearchRoot reassignment.

This is controlled executor evidence, not live AD execution readiness. The next
bounded offline gate is independent review of the integrated session/deadline,
publication and retained-handle boundaries, including their concurrency policy.
Unsupported edit families remain separate follow-up work. The exact live gate is
separately authorized two-DC proof of GUID-addressed object/parent ModifyDN and
Modify, DN-reuse resistance, destination-only authority, readback/reconciliation
and ambiguous delivery behavior. A scalar live experiment is not approval to
support other edit families or enable public Save. No real wire transport may be
connected to public Save until those gates are complete.

## Execution contract and proof obligations

1. Freeze/check the retained principal identity, entry lifetime/generation,
   pending scalar/extension/SPN edits, property ledger versions and security raw
   intent/provenance. Fresh preflight evidence is not a durable authorization.
   The integrated controlled operation owns sessions and extends generation,
   response-completeness and domain-membership checks across reads, writes and
   publication; detached plans do not confer execution authority.
2. Verify destination write targeting against DN reuse. Measure GUID-addressed
   ModifyDN (object and parent) and Modify, or establish an equivalent supported
   atomic identity assertion. A preceding search is not sufficient. Use only the
   destination context's authority; never forward source credentials.
3. Plan pending Name as an escaped new RDN separately from property modifications.
   Keep the current RDN if Name is unchanged. Reject combinations whose ordinary
   or raw security intent cannot be retained faithfully across the move.
   The controlled executor compares the effective replica and target DNs before
   ModifyDN; an explicitly assigned unchanged Name does not force a rename.
   Matching GUID-based readback can establish this no-op without acknowledging
   an unsent scalar update. Live two-DC proof remains deferred in issue 230.
4. Track no-send/rejection, acknowledged move, acknowledged scalar write, and
   uncertain delivery separately. Never roll back a merely planned move. A lost
   response quarantines all further writes on the retained wrapper; do not issue
   a compensating move. GUID readback under destination authority must establish
   identity and outcome before any next operation. The integrated controlled
   executor implements these states; its data-only plan carries no quarantine
   authority. No automatic compensation is implemented.
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

## Completed scalar offline boundary and next live gate

The controlled scalar executor now freezes intent and ledger versions, models
not-sent/rejected/acknowledged/uncertain outcomes, quarantines ambiguous delivery,
reconciles immutable identity and publishes destination authority on the original
wrapper only after verified success. Retained child/filter/search handles are
revoked at publication. The schema-filter indexer checks reservation and authority,
reads its backing array and mutates/publishes it within one local critical section;
a refused write cannot change an existing enumerator's array. Ordinary unbound
in-place and bound replacement-array behavior is preserved.

The finite scalar offline authority slice is complete pending final review. The
next meaningful evidence gate is the named two-DC fixture experiment below, not
additional generic offline matrices. The 53 native search/schema comparisons use
detached objects only and do not establish live ADSI or AD behavior. Unsupported
extension/SPN/group, password/account-control, certificate/logon-hours, deletion
and raw/security intent remains refused and requires separate implementation.
Native Save(context) moves then updates and may attempt best-effort compensation;
it is not atomic. This executor deliberately performs no automatic compensation.

The live gate remains separately scoped two-DC authorization on disposable existing
fixtures: measure the exact GUID-addressed ModifyDN object/parent and Modify wire
forms on supported AD/runtime versions; confirm allowed and denied destination
credentials with an independently allowed source; observe same/different containers,
rename plus edits, missing replicas/lag and DN reuse; and verify rejected move,
acknowledged move followed by rejected Modify, uncertain delivery and GUID readback.
Retained-wrapper identity, descriptor authority revocation and pending-edit behavior
require a separately authorized harness and native comparison before any public
route can be enabled. Public cross-DC execution remains unconditionally refused. No live operation
was executed for this slice; the opt-in probe remains preparation only.
