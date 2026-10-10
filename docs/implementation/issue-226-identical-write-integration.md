# Identical NULL/absent reassignment through entry writes and Microsoft edits

This slice closes a controlled integration loop for the correction independently
reviewed at `99b3bd7dd1a4b68af1980060d817f68156e87d9d`. It adds six core integration
cases and six Windows companion cases. No additional production defect has been
demonstrated; production code, public contracts and preservation guards are unchanged.

## Actual public DirectoryEntry path: six core cases

The two starting descriptors are an absent DACL with an ordinary opposite SACL,
and a protected NULL SACL with an ordinary opposite DACL. Owner/group are numeric
fixture identities. All requests use the existing offline read/transport overrides.
The operations under test use `DirectoryEntry.ObjectSecurity`, public rule and
binary setters, and `DirectoryEntry.CommitChanges`.

Four sequences cover each descriptor with/without a prior owner edit:

1. Initial retained raw bytes equal the fixture. Identical all-section reassignment
   preserves bytes, generation and pending intent; the caller buffer is unchanged.
2. Committing without prior intent emits no request. With prior owner intent it
   emits exactly one descriptor Replace with only the Owner mask and exact retained
   raw bytes. Native live ACL presence/dirty flags are not substituted for wire intent.
3. After acknowledgment and controlled fixture readback, a fresh entry wrapper has
   no pending intent. A peer shares its descriptor; another descriptor retains the
   old ACL references. Identical reassignment keeps generation unchanged and detaches
   the replacement ACLs from the old alias as expected.
4. A real public AddAccessRule/AddAuditRule through the peer advances the entry
   descriptor generation and marks only DACL/SACL. Shared wrappers remain coherent;
   the old alias stays unchanged. Commit sends exactly that target mask, one
   nTSecurityDescriptor Replace, and the expected raw bytes. Owner, group, opposite
   ACL and unrelated control bits remain unchanged.

Two additional compound-failure cases retain the already measured native-accepted
Int8 callback encoding in the opposite ACL. After a prior owner edit and identical
reassignment, a compound binary replacement stages changes before refusing to
discard that unreviewed callback. Tests require complete rollback of raw/live bytes,
intent, generation, descriptor/ACL/engine/provenance references, read origin,
resolver attachment and caller buffers. Both shared wrappers and the old alias
remain coherent. A subsequent real target-ACL edit succeeds; commit sends only
Owner plus the target section, preserving the opposite callback bytes.

On .NET 10, disabling only the previously reviewed production correction makes all six new
entry tests fail. Restoring it passes all six. This negative control establishes
that the integration assertions exercise that fix; it is not a new native mismatch.

## Actual public MicrosoftInterop path: six Windows cases

Four cases use actual MicrosoftSecurityEdit objects exported from public
DirectoryEntry-owned descriptors, for the same two states and prior-owner choices:

- Identical reassignment preserves pending intent. A pre-existing session applies
  as a no-op successfully and is then consumed, proving it was not made stale.
- Another pre-existing Microsoft session attempts an unsupported protection change.
  ApplyTo refuses atomically. Its native edit is restored and the same session then
  applies as a no-op, proving failure neither consumed it nor invalidated provenance.
- A real public portable ACL edit makes another older Microsoft session stale.
  ApplyTo refuses without changing current bytes or pending intent. Public commit
  then emits exactly the target ACL mask plus any still-pending Owner section.

Two attachment cases isolate successful no-op commit acknowledgment: identical
reassignment adds no intent and CommitChanges emits no request, but acknowledgment
revokes the old entry attachment. The old Microsoft edit cannot apply to the old
wrapper. A freshly read wrapper exports a new session that applies successfully.
No credential, security-setting, path or artificial attachment change is used.

The companion assembly intentionally has no core friend access. Test-only reflection
installs the existing read/transport hooks and constructs their empty property
result; it does not invoke mutation or interop internals. All assertions exercise
public entry, snapshot, ExportForEdit and ApplyTo behavior. No product hook or
InternalsVisibleTo grant was added. Actual Microsoft objects run only on Windows.

## Validation and limits

Linux .NET 8/10 each pass 12,990 core, 55 fixture-free consumer, 34 metadata-only
registration and four applicable companion tests; 16 Windows-only companion groups
skip. Full six-project Release rebuild: zero errors and 14 existing xUnit2013
warnings. Exact-head Windows results and artifact links are attached to PR228 after
publication. Existing native recordings and preservation manifests are unchanged.
The new Windows cases are executed public-API integration tests, not fabricated
oracle recordings or assertions that a Linux stand-in is Microsoft behavior.

The fake transport captures exact requests and returns controlled success; it does
not establish real AD server normalization, inheritance recomputation, privileges,
network delivery, concurrent server writes or partial server retrieval semantics.
Strict Microsoft edit-back restrictions remain. Other NULL/absent transitions,
control combinations, raw layouts and alias topologies remain bounded follow-ups.
The 25 initial / 243 directed / overlapping 623 expanded allocation gaps stay frozen
pending a causal model. No live AD, merge, release, security or credential change.
