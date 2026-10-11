# v1 principal audit: items 1–5

Scope: AccountManagement candidates assigned for this audit. Release/setup,
licensing, broader CI scope and pooling are outside it. No live directory was
used or mutated. Items 1–4 are implemented here; item 5 remains open.

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

   An indeterminate delivery retains the existing entry uncertainty gate and the
   captured batch. Only qualifying entry readback can reconcile it. If observed
   values satisfy the submitted SPN operations, the captured prefix is consumed
   without replay, retaining later collection edits. If readback does not
   establish that result, saving refuses and requires explicit outcome checking
   and a fresh principal. This is a preservation boundary, not an assertion of
   native timeout recovery parity. No credentials, owner references or callbacks
   are carried by the batch, and descriptor/entry copies do not transfer it.

   The earlier set-difference proposal was rejected in review: failed Save →
   cancel edit → retry could publish its stale entry ledger. This implementation
   avoids cache staging and rollback altogether. Tests cover rejection/cancel,
   refresh, external and direct edits, duplicates, clear, edits during a request,
   acknowledgement followed by post-save failure, and uncertain readback.

## Confirmed defect still open

5. **Save(context) across DCs.** An offline same-container reproduction shows
   Context switching to the destination while the same underlying DirectoryEntry
   remains at the source endpoint. A different-container move hits the existing
   low-level connection guard. Equal defaultNamingContext text is insufficient
   stable domain identity proof. Current control flow also attempts rollback
   based on a planned move, even if the forward guard rejected before send.
   The only remaining skipped test,
   `Cross_dc_same_container_save_requires_rebinding_existing_wrapper`, records
   the unresolved same-container expectation.

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
