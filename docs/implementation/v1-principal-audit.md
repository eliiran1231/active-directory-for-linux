# v1 principal audit: items 1–5

Scope: AccountManagement candidates assigned for this audit. Release/setup,
licensing, broader CI scope and pooling are outside it. No live directory was
used or mutated. This is a partial fix, not closure of all five items.

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
   no client-side fine-grained password-policy simulation was invented.

3. **Group extension replay.** A successful extension save followed by a simulated
   external update, entry refresh and unrelated save overwrote the external
   value. GroupPrincipal now calls the base OnAfterSave after membership work
   succeeds. The regression verifies no extension write on the second save;
   another test confirms failed-save intent survives refresh and retry.

## Confirmed defects still open

4. **Computer SPN edits and refresh.** Adding or removing a service name, then
   refreshing the underlying entry before Save, loses the write while the
   principal collection still displays the edit. Rejection followed by refresh
   and retry loses it too. The executable reproducers are retained with explicit
   skips in V1PrincipalAuditTests; they are not counted as passing fixes.

   A proposed baseline/set-difference patch was rejected in independent review:
   failed Save → cancel edit → retry without refresh could publish the old entry
   ledger. Set differences also fail to represent native per-slot collection
   tracking. [Microsoft Computer](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Computer.cs)
   retains collection tracking; [SDSUtils](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/SDSUtils.cs)
   applies removed, changed and inserted values separately. A safe fix needs
   explicit accounting for rejected versus acknowledged writes, post-save
   failures and indeterminate delivery. Restoring an old property ledger can
   invalidate uncertain-write reconciliation or discard intervening low-level
   edits. No generic rollback helper or incomplete SPN patch is included.

5. **Save(context) across DCs.** An offline same-container reproduction shows
   Context switching to the destination while the same underlying DirectoryEntry
   remains at the source endpoint. A different-container move hits the existing
   low-level connection guard. Equal defaultNamingContext text is insufficient
   stable domain identity proof. Current control flow also attempts rollback
   based on a planned move, even if the forward guard rejected before send.
   The skipped regression records the unresolved same-container expectation.

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
require separately scoped authorization. Item 4 retry semantics and item 5's
authority/lifecycle design remain implementation blockers, not passed tests.
