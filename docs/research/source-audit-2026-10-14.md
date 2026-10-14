# Source audit: indexer replacement, custom date finders, persisted Name

Base: `dev` at `9e97cccbb830c2a7d5a4594826a7ebdda8d4c31f` (PR229).
Only offline validation is authorized. No AD connection, provisioning, credentials,
network/permission changes, merge, or release is part of this work.

## Multi-value replacement

[Microsoft v9 OnSetComplete](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices/src/System/DirectoryServices/PropertyValueCollection.cs#L315)
stages delete and append before one CommitIfNotCaching. The port notified the owner
once per delta, causing two independent Modify requests in immediate mode.

The guarded regression intercepts the production write path and rejects any
request containing Add. Before the fix, immediate replacement of A in [A,C]
with B leaves the modeled server at [C]: the delete already committed. The
single-request assertion also observes two requests. After the fix, both deltas
are published under the property change gate, with one version increment and one
owner notification. LDAP Modify now receives the complete replacement atomically.

A definitive rejection retains both deltas for explicit CommitChanges retry.
CollectionBase still rolls back the local index when its completion hook throws;
the local slot and pending server intent are distinct, just as in the existing
collection lifecycle. Successful retry clears the retained wrapper's ledger;
reacquiring Entry.Properties returns server values. Existing acknowledgment gates
remain intact: newer edits prevent acknowledgment, and uncertain requests cannot
be blindly replayed or refreshed over newer edits. Cached and immediate tests
exercise these cases. This is not a general thread-safety guarantee for CollectionBase.

### Duplicate append remains a documented limitation

[IADs::PutEx](https://learn.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iads-putex)
documents ignoring an appended value already present. Plain LDAP Add can reject it.
Replacing A with already-present B therefore remains a parity gap; the new strict
LDAP model proves rejection leaves [A,B] intact and retains the whole request for
retry. It no longer loses A through a separately committed delete.

No duplicate suppression, case folding, whole-attribute replacement, or permissive
modify control was introduced. A retained cache may be stale or ranged; CLR
comparison does not establish the server's schema matching rule. Permissive modify
also suppresses missing-value delete failures. These are wider semantic changes
than batching. Same-value A→A and case-only A→a still emit delete/append.

A follow-up ADSI comparison should use a dedicated existing test object and a
specified multi-valued attribute: A→C, A→A, A→B already present, and case variants,
in cached and immediate modes. Record local retained-wrapper values, exceptions,
CommitChanges retry, and independent readback; include a concurrent external removal
of B and a ranged attribute only with separate explicit authorization. Do not
infer case equality from an unrelated attribute.

## All five protected generic date finders

[Microsoft v9 GetObjectClassPortion](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs#L187)
uses structural class metadata for custom types and rejects missing metadata.
The port's default branch instead selected the built-in user/computer union.

The shared finder now uses the custom type's declared DirectoryObjectClass,
escaping its LDAP value, and rejects a missing declaration before search. Tests
invoke each protected generic finder through reflection and intercept the actual
searcher: custom user, custom computer, inherited-only/missing declaration,
escaped class, and the three built-in types (35 cases). Built-in filter behavior
and result materialization/casting are unchanged. Empty intercepted results keep
native generic result-casting quirks out of this filter regression.

## Ordinary persisted Principal.Name + Save: no behavior change

Offline interception proves the port stages `cn`, then submits a ModifyRequest
on the original DN. A modeled NotAllowedOnRdn response preserves pending Name and
the old DN; this proves request shape and failure handling, not live AD parity.

Microsoft v9 maps PrincipalName to `name` in
[ADStoreCtx_LoadStore](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_LoadStore.cs#L705).
Its StringToLdapConverter assigns the suggested property value.
[ADStoreCtx.Update](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx.cs#L657)
calls [SDSUtils.ApplyChangesToDirectory](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/SDSUtils.cs#L266),
which pushes changes and calls DirectoryEntry.CommitChanges. That path contains no
explicit Rename. Managed source does not establish whether the native ADSI provider
rejects or special-cases this assignment. Neither success nor a required Rename
fix is established here, and the port was not changed on that assumption.

### Exact future comparison and authorization needed

On one named Windows machine with Microsoft packages pinned to 9.0.0 and one
explicit DC, use two pre-existing disposable user objects supplied by the owner,
one per implementation. Pin lookup/readback to the same DC and identify objects
by GUID. Do not use Save(otherContext), cross-controller moves, provisioning,
password changes, or the broad differential suite.

For each library, load the principal, capture GUID/DN/name/cn, set a unique ordinary
Name, call parameterless Save, and capture exception type/HRESULT/extended error,
retained principal Name/DN, underlying entry Path, and independent GUID-based
readback of DN/name/cn. Include an unchanged-Name control on a fresh handle. Stop
on unexpected identity or target changes; restore only a successful rename using
an explicitly authorized cleanup operation, then verify GUID and original DN.

Execution requires explicit authorization for those named existing objects,
write/rename and cleanup operations, DC, machine, and existing authentication
mechanism. It is **not authorized or executed** by this offline task. Two-DC
validation stays deferred in [issue230](https://github.com/eliiran1231/active-directory-for-linux/issues/230);
public cross-DC execution stays disabled. PR229's private unchanged-DN rebinding
fix is separate from this ordinary Save question.

## Offline verification

Use `python tests/test_offline_runner.py`, then the approved
`tests/run-offline-tests.py functional --framework net8.0` and `net10.0` commands.
The new tests live in the already-reviewed detached V1PrincipalAuditTests class;
no allowlist broadening or ad hoc test filter is needed. Local Release solution
build passes; each Linux functional run passes 13,417 tests with the one existing
cross-DC skip. The focused pre-fix run failed three immediate-replacement tests.
The branch-specific Source audit offline workflow builds and runs the guarded
functional group on Linux/Windows and the guarded surface/companion groups on
Windows, on both frameworks. CI must be checked against the published head SHA.
