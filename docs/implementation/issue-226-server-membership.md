# Server-verified single-NC identity scope

Current readiness: [end-to-end inventory](issue-226-remaining-compatibility.md). The portable
AD/entry cutover and public MicrosoftInterop companion are implemented. Descriptions below
of them as future work are historical slice boundaries, not current missing dependencies.
Historical counts are not the latest whole-PR validation or a claim of complete behavior.

This replaces the temporary alphanumeric-only DN guard from `c8f75486`. It implements the
already-approved single-domain resolver boundary; it does not introduce multi-domain routing,
a public DN normalizer, new authentication policy or public persistence cutover.

## Evidence and scope argument

The proof uses these independently checked primary contracts:

- [distinguishedName schema](https://learn.microsoft.com/en-us/windows/win32/adschema/a-distinguishedname):
  the server-maintained attribute has Object(DS-DN) syntax.
- [AD comparison operations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad58bcc9-1ce3-4b4c-98b2-a79b62a39259)
  support equalityMatch for DN syntax; the [DN rule](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f2f43a25-cbe1-4723-b271-9e83737327e8)
  compares the object named, rather than requiring identical client strings.
- [LDAP_SERVER_DOMAIN_SCOPE_OID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ba5f20c6-7753-417c-b93d-e66e722458ed)
  limits a search to the single NC replica containing its search base and suppresses continuation
  references. The control has an empty value and does not produce a response control.
- [RFC 4511 §§4.1.12, 4.5.1.8, 4.5.2](https://www.rfc-editor.org/rfc/rfc4511): an unsupported critical
  control fails the operation; `1.1` requests no attributes; entries and references are followed
  by the final result status. A returned entry may legitimately contain no attributes.

**Inference from those contracts:** after independently verifying the domain NC, a complete,
unique result for `(distinguishedName=<escaped candidate DN>)`, searched from that domain NC
with the critical single-NC control, proves that the candidate names a visible object in that
NC for that operation. The candidate is never the search base. A candidate-rooted Base search
would not establish membership in the intended NC and is not used.

AD evaluates all DN equivalence. The client does not remove marks, fold width/whitespace, apply
.NET culture comparison to candidate DNs, unescape/rewrite them or guess attribute aliases.
Spaces, hyphens, punctuation, Unicode and equivalent DN spellings are no longer refused merely
by a local spelling allowlist. They succeed only when the server supplies the required proof.
This is reliance on the configured directory server's protocol contract, not protection against
a malicious server lying about its own search results.

## Implemented request sequence

1. Capture the entry's options and target under the existing generation check. Reject standard
   GC ports, empty targets and malformed UTF-16 before session creation. Existing explicit
   authenticated-credential requirements for name-based mutation remain in effect.
2. Open the existing bounded independent session, disable referrals and bind using unchanged
   authentication/TLS settings. Read RootDSE and verify one domain crossRef using the existing
   domain systemFlags bit and nCName/NetBIOS/DNS metadata checks. Missing/ambiguous/mismatched
   metadata refuses; there is no parent-domain fallback. Metadata spelling mismatches may still
   conservatively refuse rather than attempt local equivalence.
3. Prove entry membership from the verified domain base: Subtree scope, critical server-side
   `1.2.840.113556.1.4.1339`, exact equality filter with every strict UTF-8 byte RFC4515-escaped,
   SizeLimit 2, and the remaining operation deadline. Request only `1.1` (no attributes).
   Require one complete result with a nonempty protocol DN. No objectGUID/SID read-permission
   requirement is added to the membership query.
4. Search accounts from the same verified base in the same session, with that critical control,
   size bound and decreasing deadline. Each unique mapped account's returned DN also gets the
   same membership proof before its identity is accepted. Missing account attributes remain
   unmapped; existing ambiguity, SID-integrity and foreign-principal checks remain.
5. After all mappings, recheck the original entry DN with the same membership proof. Only then
   can Resolve return. Existing entry-generation checks run around every request and at return;
   facade attachment/version validation still gates local mutation publication.

For one successful unique account mapping this is six searches: RootDSE, crossRef, initial
entry proof, account query, account proof, final entry proof. Duplicate identities share only
operation-local mapping work; no membership/authority cache survives the operation.

## Failure, permissions and races

Zero results cannot distinguish absence, insufficient visibility and another NC. They are
insufficient authority and cause NotSupportedException, not a fallback domain or an invented
mapping. Multiple results, missing protocol DN, non-success completion, continuation references,
size/time truncation and unsupported critical control likewise cannot establish proof. Transport,
authorization and timeout exceptions propagate. Native protocol APIs may throw before the
shared complete-result guard; neither path publishes partial rows. Account lookup never starts
if the initial entry proof fails. A later proof failure discards all prepared mappings, leaving
local descriptor bytes/state/versions/dirty flags unchanged. Every session disposes on exit.

Referrals are disabled for the entire session. A referral result/reference is rejected even if
entries arrived. The domain-scope control has no response echo, so no echo is required and its
absence is not treated as an error. The client never retries without the critical control.

This is point-in-time membership, not snapshot isolation or an LDAP transaction. A move/deletion
visible at a later proof causes refusal; a change after the final proof remains possible. Without
existing immutable-object provenance, deletion/recreation under the same DN is indistinguishable
and is not claimed to be detected. No new GUID attribute requirement is imposed to pretend
otherwise. Entry rebind/Close/Dispose/path changes and facade changes are covered by the existing
local generation/attachment/version checks. These guarantees do not establish a new ambient
identity-pinned mutation policy and do not authorize a future transport write.

## Implementation and verification plan/evidence

The implementation sequence is: extract the complete-result gate without changing its semantics;
replace client DN ancestry with the bounded server proof; retain critical scope on all account
queries; add final entry revalidation; then validate the request/response and failure contracts
using controlled sessions before running both offline runtime matrices.

The prior scope, OID/escape and 449 Unicode/whitespace tests now make server proof failure explicit
instead of claiming those spellings are inherently invalid. Metadata spelling alone never grants
authority. Three temporary space/escape refusals are restored to successful scripted proofs.
The exhaustive ASCII metadata test requires proof regardless of metadata spelling. These are
controlled tests, not an AD matching emulator or fabricated native observations.

51 additional tests cover 20 successful DN/direction cases, two hyphenated-domain/unrelated-Unicode
NC cases, 24 failures at initial/account/final proof phases, three generation races and two malformed
UTF-16 cases. They assert fixed verified bases, exact byte escaping, critical/empty-value controls,
SizeLimit 2, decreasing deadlines, minimal attribute-free results, no fallback, session disposal,
and atomic local state. Failure cases include absence, ambiguity, missing DN, denial, timeout,
referral, truncation and unsupported control. The existing missing-control and metadata-consistency
regressions remain active. No live directory or credentials were used, and no new native oracle
recordings are claimed.

Full Linux .NET 8/10 and exact-published-head Windows offline builds/tests and committed native
oracle freshness comparisons are required before reporting this slice verified. Broader routing,
authorized live AD validation, PrincipalContext integration, and implementation of the
[approved persistence contracts](issue-226-persistence-decisions.md) remain outside this change.
