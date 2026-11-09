# Principal edits during Save: contract assessment

Assessment date: 2026-11-09. Executable source baseline:
`f56afe482a1d3f03a5506a7c294dbcc5070ea48e`.

## Decision

The four opt-in scalar/extension acknowledgement cases remain contract
diagnostics. Their preservation oracle has not been established as a Microsoft
compatibility requirement. No production change is justified solely by making
those assertions pass.

Same-object synchronous reentrancy is publicly reachable in this implementation;
it is not limited to the internal callback used by the original diagnostics.
That reachability does not itself establish a supported preservation contract.
The practical recommendation is to finish a save before editing that principal
again, including from custom value conversion code. This is usage guidance, not
a newly enforced API restriction or a claim that all Microsoft instance methods
are categorically unsafe.

## Contract and reference implementation

Microsoft's [Principal API documentation source](https://raw.githubusercontent.com/dotnet/dotnet-api-docs/main/xml/System.DirectoryServices.AccountManagement/Principal.xml)
describes saving changes and setting extension attributes. It does not specify
preservation of edits made during a save. No thread-safety or reentrancy guarantee
was found in that type's current documentation. Absence of a guarantee is not
proof that every such use is forbidden.

In the tagged [.NET 8 Principal source](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs#L264)
and [.NET 10 Principal source](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/Principal.cs#L264),
`Save` delegates to the store. Scalar setters mark change flags; extension
setters retain values and mark extension state changed. `ResetAllChangeStatus`
resets current flags without checking per-edit revisions.

The [.NET 8 AD store](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs#L590)
and [.NET 10 AD store](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs#L590)
call that reset after applying changes. This source pattern does not provide the
diagnostics' required revision-aware acknowledgement. It also does not prove
identical Windows runtime results for every interleaving; no Windows or live
directory differential execution was performed here.

Microsoft's [extension conversion](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs#L1177)
accepts object and collection shapes and enumerates caller collections. It
passes values to `DirectoryEntry`; its [property collection](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyValueCollection.cs#L79)
forwards values to ADSI. These sources do not establish that Microsoft's ADSI
path accepts every arbitrary formatter accepted by this port, or invokes it at
the same stage. Debug logging calls are not a supported notification API.

Microsoft's [threading guidance](https://learn.microsoft.com/en-us/dotnet/standard/threading/managed-threading-best-practices#recommendations-for-class-libraries)
warns against assuming instance data is thread-safe by default. That general
guidance does not settle same-thread reentrancy during conversion.

## Actual local call paths

`Principal.Save` is nonvirtual. `OnBeforeSave`, `OnAfterSave` and
`CommitEntryChanges` are `private protected`; an external derived principal
cannot override them. The original `BeforeWrite` callback belongs to an internal
test fixture, not the public directory transport API.

A public extension subclass can nevertheless supply an object through
`ExtensionSet`. After principal intent has been staged, `DirectoryEntry.AddValue`
calls that object's `IFormattable.ToString` or `ToString` while building the LDAP
request. That code can call a public principal setter or an extension wrapper.
Those edits can affect only the principal cache, leaving the captured entry
ledger unchanged. The request can therefore succeed, after which `_pending.Clear`
or the extension clean-up can acknowledge intent that was not in the request.

This path is synchronous and needs no concurrent thread. The entry's existing
version checks protect edits to its own captured ledgers; they do not capture
every principal-level edit. Exposing the underlying entry, or sharing mutable
extension arrays, also means a principal-level gate alone cannot establish
general thread safety.

## Isolated observations

A detached research worktree adds eight opt-in probes: the four original edit
shapes through both ordinary and invariant formatting. The principal is attached
to an isolated fixture, but edits occur through its public setter/extension
wrapper inside the real production serializer. Neither `BeforeWrite` nor
`AfterWrite` injects the edit. Each probe checks that formatting ran exactly
once, the first real request contains the serialized trigger, the initial edit
reaches the controlled server, and both saves return successfully before the
candidate preservation assertion fails.

On both .NET 8 and 10, the guarded principal class reports 571 cases: 558 passed,
12 diagnostic failures and one existing cross-controller skip. The failures
comprise the four original internal-callback observations and eight public
conversion observations. All eight new failures occur at the candidate
preservation assertion, not during setup, formatting or dispatch. These are
project observations, not Microsoft differential results or eight confirmed
compatibility defects. Research probe source and raw TRX remain in the cloud
task; the probes are not added to the normal project or its default test count.

The normal source still has the previously verified default results on each
runtime: 14,139 passed, zero failed, two skips. The research documentation changes
no executable source. No credentials, live directory or native transport were
used for these observations.

## Concrete design choices

| Direction | Benefit | Cost and limit |
| --- | --- | --- |
| Preserve the current contract classification and serialize same-principal use | Smallest compatibility surface; no new acknowledgement promise | Requires callers to avoid edits from conversion callbacks; diagnostics remain unresolved |
| Reject principal API edits while Save is active | Detects many mistakes explicitly | New observable exceptions; every mutator and retained collection needs coverage; a reentrant monitor alone does not reject same-thread reentry; raw entry and array aliases remain separate boundaries |
| Define revision-aware acknowledgement for edits made during Save | Can preserve later setter intent without holding a facade lock during I/O | A deliberate behavior extension requiring consistent snapshots, revisions and failure policy across all save phases; not a minimal parity fix |

If revision-aware acknowledgement is selected deliberately, implement it as an
explicit contract with the following boundaries:

1. Capture immutable intent records under a short private gate after pre-save
   staging. Assign a monotonically increasing revision to each setter operation;
   retain revisions even when a value changes back to its earlier value.
2. Serialize a captured payload outside the gate. User conversion code and LDAP
   I/O must not execute while that gate is held. Preserve newer cache entries
   rather than enumerating mutable live dictionaries during serialization.
3. On definitive success, acknowledge only the captured revision of each
   attribute. A newer scalar or extension record remains pending. Value equality
   alone cannot distinguish a newer edit from the acknowledged one.
4. Keep current not-sent, rejection and uncertain-outcome rules. A newer edit is
   not proof that an earlier submitted write failed. Readback must reconcile the
   earlier operation before another dispatch; raw cache refresh must not silently
   cancel principal intent.
5. Specify separate completion boundaries for scalar/extension writes, group
   membership, deferred password/account work, insert/rollback, and
   `Save(context)`. A successful phase does not turn a later failed phase into an
   atomic server transaction. Preserve existing retry and reconciliation rules.
6. Snapshot mutable wire values without silently breaking the extension API's
   shared-array cache behavior. Setter revisions do not observe arbitrary array
   or custom-object mutation. Such alias mutation must remain outside the new
   guarantee unless a separately specified snapshot/alias policy addresses it.

Acceptance tests would need same/different attributes, equal-value and
change-away-and-back edits, both formatter paths, failures before and after
submission, genuine raw-entry edits, lifecycle changes, and every affected
post-save phase. Passing the current four diagnostics alone would not establish
this larger contract. A fresh Windows comparison could inform policy, but would
still require an explicit supported-usage decision.
