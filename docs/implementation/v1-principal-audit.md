# v1 principal audit: items 1–5

Scope: AccountManagement candidates assigned for this audit. Release/setup,
licensing, broader CI scope and pooling are outside it. Controlled tests do not
establish live AD compatibility. An earlier aborted read-test invocation has
unverified connection/authentication effects; see the
[offline safeguards and evidence limits](../../tests/OFFLINE-TESTING.md).
Items 1–4 are implemented here; item 5 remains open.

## Confirmed and fixed

1. **Authorization groups.** Captured requests from the actual authorization
   query path showed that empty-tokenGroups fallback searched the context OU,
   and both fallback and GC membership supplementation omitted the security bit
   filter. The fallback now searches the domain naming context and combines
   transitive membership with the primary SID under one security-enabled group
   predicate. Token SID and GC supplement queries use the same predicate.
   Ordinary GetGroups container semantics, SID deduplication and existing
   connection/credential routing are unchanged. Controlled tests exercise both
   token-present and token-absent paths and the primary SID arm. They verify
   request contracts, not a real server's membership evaluation.

2. **Effective lockout state.** The old path ignored computed state and did not
   refresh the cached lockout timestamp. It now refreshes only
   msDS-User-Account-Control-Computed and lockoutTime, uses UF_LOCKOUT when the
   computed attribute exists, and retains the domain-duration fallback only
   when it is absent. This follows [Microsoft v9 ADStoreCtx.IsLockedOut](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs).
   Controlled tests cover repeated same-instance reads, nonzero lockoutTime with
   computed zero, computed bit precedence, unrelated bits and preservation of
   an unrelated pending entry property. The DC supplies effective-policy state;
   no client-side fine-grained password-policy simulation was invented. A further
   Close → lockout check → Sid regression ensures the ordinary lazy property
   cache is loaded before targeted refresh, so unrelated attributes remain
   available without discarding staged properties.

3. **Group extension replay.** A successful extension save followed by a simulated
   external update, entry refresh and unrelated save overwrote the external
   value. GroupPrincipal now calls the base OnAfterSave after membership work
   succeeds. The regression verifies no extension write on the second save;
   another test confirms failed-save intent survives refresh and retry.

4. **Computer SPN edits and refresh.** Adding or removing a service name, then
   refreshing the underlying entry before Save, lost the write while the
   principal collection still displayed the edit. Rejection followed by refresh
   and retry lost it too. Both original theory groups are now enabled:
   `Service_names_preserve_edit_intent_across_entry_refresh` and
   `Service_names_retry_preserves_unrelated_refreshed_values`.

   The collection now keeps opt-in operation tracking, preserving the native
   distinction between original slots, removed originals, changed originals and
   inserted values. Detached comparisons inspect the actual Microsoft v9
   collection's tracking for add/remove/clear/index assignment/duplicates,
   cancellation and successful reset. [Microsoft Computer](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Computer.cs)
   retains collection tracking; [SDSUtils](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/SDSUtils.cs)
   defines the removed/changed/inserted conversion order and cache guards.

   A data-only SPN batch is appended to the entry's existing atomic Modify after
   ordinary staged property edits. It does not replace the attribute or install
   principal deltas into the entry cache. Rejected writes therefore leave no
   stale SPN ledger; cancellation or changed intent can be retried without cache
   refresh. Direct entry edits and unrelated refreshed values remain intact.
   The ordinary entry generation and property-version checks cover the SPN
   cache used for planning. Collection acknowledgement consumes only the captured
   operation prefix; later edits remain pending. Acknowledgement occurs before
   post-save work, so a later failure does not replay completed SPN writes.

   SPN persistence now computes set deltas separately from the public list's
   positional tracking. Public Add/index operations still accept duplicates;
   successful creation or update acknowledges canonical unique values and
   normalizes the retained collection. Later edits are rebased by set intent,
   so removing one duplicate cannot delete a value that remains desired.
   When no SPN modification is sent, fresh complete readback must establish the
   guarded result before acknowledgement, even if another attribute is written.
   Cached values alone do not prove persistence. Rejection or incomplete/mismatching
   readback leaves the collection and pending edits unacknowledged.

   An indeterminate delivery retains the existing entry uncertainty gate and the
   captured batch. Only qualifying entry readback can reconcile it. If observed
   values satisfy the submitted SPN operations, the captured prefix is consumed
   without replay, retaining later collection edits. If readback does not
   establish that result, saving refuses and requires explicit outcome checking
   and a fresh principal. This is a preservation boundary, not an assertion of
   native timeout recovery parity. No credentials, owner references or callbacks
   are carried by the batch, and descriptor/entry copies do not transfer it.

   Readback postconditions include principal adds/removes already represented
   by ordinary entry-ledger operations. The scratch cache is not delivery proof:
   coalescing a supplemental operation must not erase its required server result.
   A review regression reproduced false acknowledgement after timeout-before-
   application for both coalesced adds and deletes; matching-result controls and
   mismatching-result refusal now cover both public editing routes together.
   Recovery also requires the SPN attribute in the readback coverage when every
   supplemental operation was guarded away and the request only wrote another
   attribute. An unrequested/missing SPN key is not evidence of server absence.

   Recovery validates raw LDAP response completeness before range-name
   normalization or cache publication. Nonterminal, nonzero-start, malformed and
   conflicting SPN ranges refuse atomically. A single `range=0-*` is accepted,
   including AD's optional empty bare-attribute companion; genuinely absent
   values in a successful singleton response remain a valid deletion result.
   Non-success, missing/duplicate entries and either referral form refuse.
   Raw SearchResponse tests run through the actual loader and recovery path,
   rather than a preassembled property dictionary. No range walk or multi-read
   assembly is used because successive ranges may change during retrieval.

   The earlier set-difference proposal was rejected in review: failed Save →
   cancel edit → retry could publish its stale entry ledger. This implementation
   avoids cache staging and rollback altogether. Tests cover rejection/cancel,
   refresh, external and direct edits, duplicates, clear, edits during a request,
   acknowledgement followed by post-save failure, and uncertain readback.

## Confirmed defect still open

5. **Save(context) across DCs.** The baseline offline same-container reproduction showed
   Context switching to the destination while the same underlying DirectoryEntry
   remains at the source endpoint. A different-container move hits the existing
   low-level connection guard. Equal defaultNamingContext text is insufficient
   stable domain identity proof. The baseline also attempted rollback based on
   a planned move, even if the forward guard rejected before send; that bug is fixed.
   The only remaining skipped test,
   `Cross_dc_same_container_save_requires_rebinding_existing_wrapper`, records
   the unresolved same-container expectation.

   The bounded follow-up now performs read-only domain/replica identity preflight
   under separate endpoint authority and refuses cross-context execution before
   changing Context, the retained wrapper or pending edits. Equal naming-context
   text no longer permits a misleading same-container success. Fresh source GUID
   must match the principal's captured identity, not merely a refreshed entry
   cache. Production preflight now uses operation-owned sessions, fresh RootDSE
   and domain identity, complete raw responses, critical domain-scope membership
   searches and checked owner generations through final publication. Cached NCs
   and textual ancestry are not proof. The existing catch path distinguishes
   acknowledged moves from planned moves. See the
   [concrete execution plan](v1-cross-context-save-plan.md) and compiled,
   [opt-in two-DC probe](../research/cross-dc-save-probe/README.md).

   Preflight and the internal scalar executor now share one retained pair of
   endpoint sessions, frozen intent/version checks and a monotonic deadline from
   bind admission through write admission, GUID readback and same-wrapper
   publication. Controlled tests cover expiry before/after possible delivery,
   stale owners and overlapping retained property/configuration operations.
   It has no live/default mutation transport and is not called by public Save. Unsupported
   extension/SPN/security/specialized intent refuses; the full implementation and
   live two-controller proof remain open. The plan documents the precise subset.

   A safe implementation needs fresh domain GUID/SID proof from each endpoint
   using only that endpoint's supplied authority; source/destination object GUID
   and SID agreement; replication-lag refusal before writing; preservation of
   the existing DirectoryEntry wrapper identity; explicit handling of pending
   Name, ordinary properties and security provenance; checked revocation/rebind;
   and rejection/success/indeterminate outcome accounting. Clearing acknowledged
   scalar intent is not itself evidence of a parity bug. No source credentials
   may be forwarded to a destination, and descriptor copies convey no authority.
   The low-level MoveTo guard is unchanged. No documentation-only narrowing is
   substituted for this missing implementation.

## Validation boundaries

The baseline controlled run reproduced eight failures for items 2–4, with three
controls passing. A separate authorization baseline reproduced both request
defects. Sources and controlled transports establish these local defects; they
do not certify live AD parity. The Windows offline workflow is enabled only for
this audit branch and adds explicit offline filters to its existing execution;
it does not run directory fixtures or change general CI policy.

User-run live validation still needs distribution/security groups inside and
outside a scoped OU, primary and nested memberships, GC/FSP duplicates, actual
lock/unlock and effective fine-grained policies, custom extension external
updates, SPN add/remove/index/clear/duplicate and failed-save retries, and a true
two-DC fixture for move/rebind/replication and failure outcomes. Those operations
require separately scoped authorization. Item 4 has controlled lifecycle and
detached native collection coverage, not live server certification. Item 5's
authority/lifecycle design remains an implementation blocker, not a passed test.
