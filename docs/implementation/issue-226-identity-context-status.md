# Entry-bound identity resolution and raw write preparation — staged dependency

Current readiness: [end-to-end inventory](issue-226-remaining-compatibility.md). The portable
AD/entry cutover and public MicrosoftInterop companion are implemented. Descriptions below
of them as future work are historical slice boundaries, not current missing dependencies.
Historical counts are not the latest whole-PR validation or a claim of complete behavior.

Current integration: [portable public AD cutover and raw persistence](issue-226-entry-persistence-status.md)
supersedes the historical staging statements below about the BCL-rooted AD hierarchy and
unwired DirectoryEntry path. Historical oracle counts and preservation boundaries remain evidence,
not claims of live-directory parity.

This implements the next portable dependency after the NULL-DACL correction. It follows
[D11 and D4](https://github.com/eliiran1231/active-directory-for-linux/blob/ea0786fc3e75658732e7ac15a94134d54e24bf6c/docs/design/acl-decisions.md)
and the [context ownership design](https://github.com/eliiran1231/active-directory-for-linux/blob/ea0786fc3e75658732e7ac15a94134d54e24bf6c/docs/design/context-bound-identity-resolution.md).
The existing BCL-rooted AD class/rule hierarchy and DirectoryEntry security persistence path
remain unchanged. This is not the coordinated public cutover, live AD validation or an
effective-access evaluator.

Latest independent dependency: [the internal PrincipalContext adapter](issue-226-principal-identity-status.md)
now shares the borrowed-owner resolver with entry bindings. It adds no public helper or transport cutover.

## Internal resolver and context lifetime

`DirectoryIdentityResolver` and its factory/binding/translation operations are internal
implementation details. Their earlier public exposure was unapproved and has been removed.
Public `DirectoryEntry.ObjectSecurity` automatically binds its own context; standalone
identity translation has no directory authority. Public context-helper naming/exposure
remains undecided. The historical staging description below does not authorize callers
to depend on the internal helper.

The internal `DirectoryIdentityResolver.ForEntry(entry)` captures a weak, revocable
owner binding without connecting. Its internal translation operations use the library's
AD resolver, and its binding operation attaches resolution to one wrapper.
`DirectoryEntry.ObjectSecurity` automatically acquires this context when loading its
raw descriptor. Ordinary standalone identity `Translate(Type)` remains context-free
and same-kind; no global, AsyncLocal or identity-attached resolver is introduced.

The resolver retains only a weak entry reference and captured generation. Credentials and
connection options are borrowed for an individual operation, never stored in descriptors or
copied to another owner. Each operation opens an independent connection, preserves the existing
authentication/TLS/signing/sealing settings, disables referrals before bind/search, and disposes
the connection afterward. Existing entry search connections are not borrowed or reconfigured.

Username/password/authentication/path changes, referral resets, Close and Dispose revoke old
bindings. Successful descriptor refresh, successful commit and descriptor assignment invalidate
the attachment generation. Failed refresh preserves it; a refresh of unrelated properties does
not expire it. Move/rename paths inherit ResetBinding invalidation. Active independent reads may
finish after revocation, but their results cannot publish. Disposal does not close a connection
under an in-flight lookup; its bounded session disposes on completion. No instantaneous network
cancellation is promised. Reacquisition occurs inside entry loading/assignment; stale wrappers never revive automatically.

Ambient SID-to-name reads are allowed. Name-to-SID used by this resolver requires explicit
nonempty credentials and Basic/Negotiate authentication, followed by a successful session bind.
An ambient identity-pinned mutation lease is not implemented or inferred from a username label
or an options epoch. This conservative boundary remains explicit pending the D11 open decision.

## Lookup and failures

The resolver discovers defaultNamingContext and configurationNamingContext on the same session,
then requires one matching domain crossRef with the domain systemFlags bit, nCName, nETBIOSName
and dnsRoot. It does not derive the domain from a parent OU, hostname label or credential suffix.
Queries stay within this verified domain. Binary SID and UTF-8 text assertions escape every
octet; malformed UTF-16 is rejected before connecting. Names support qualified NetBIOS/DNS-domain
SAM values, bare SAM names in that single domain, and exact UPN matching without UPN-based routing.

The resolver rejects standard GC ports 3268/3269 before opening a session. It verifies the
entry's membership through a server search from the independently verified domain NC, never
from the candidate DN: Subtree scope, a critical single-NC domain-scope control, an exact
strict UTF-8 escaped distinguishedName filter, SizeLimit 2 and the remaining deadline. A unique,
complete result with a protocol DN suffices; the proof requests no attributes (`1.1`) and adds
no objectGUID/SID read-permission requirement. Failure precedes account lookup.

All account searches retain the same critical control/session/base. Returned account DNs get
membership checks, and the original entry is checked again after all mappings, before local
publication. Missing/inaccessible/ambiguous/partial/referral results never become proof or trigger
fallback routing. Existing generation/attachment/version checks remain. The temporary local
CN/OU/DC alphanumeric spelling guard is removed: valid Unicode, spaces, punctuation, hyphens and
equivalent spellings can succeed when AD confirms membership. The client does not normalize DNs.

[Server-membership design, primary evidence, request sequence and controlled verification](issue-226-server-membership.md)
records why this proves current NC membership and its limits. Metadata inconsistencies still
refuse conservatively. It is not snapshot isolation, immutable object identity across same-DN
replacement, a new ambient-authentication policy or transport write authority. No live AD claim
is made by the controlled tests.

Typed access/audit helpers now check retrieved DACL/SACL coverage before preparing a
name-based mutation. Fourteen routes assert zero opened sessions and zero queries for unread
sections, plus unchanged descriptor state. Eleven failed against the prior placement; the
three public routes already rejected early. Later version/context checks remain in place.

The shared connection factory now owns a newly allocated connection through all configuration
steps, including authentication type, signing/sealing and StartTLS, and disposes it if setup
throws. Three controlled lifetime tests cover early/late setup failure, exact exception
propagation and successful ownership transfer. They exercise the actual factory ownership
guard with a disposable fake; they do not require a native LDAP library or a server. TLS and
authentication policy are unchanged.

Queries have a size limit of two to detect ambiguity and share a decreasing operation deadline,
including connection establishment time. Partial/failed/referral responses never become unique
matches. ForeignSecurityPrincipal names are refused; CN/displayName never substitute for an
authoritative account name. No trust traversal, SID-history search, machine-local aliases,
host-relative SDDL authority or fallback endpoint/credentials are introduced.

Operation-local deduplication is the only cache. A missing/hidden account is unmapped within
the available scope; it is not proof of global nonexistence. Single/forced translation throws
the portable IdentityNotMappedException with the original unmapped values. Non-forced collection
translation retains unmapped values in order. Ambiguity throws InvalidOperationException;
unsupported authority/topology throws NotSupportedException; stale context throws
InvalidOperationException and a disposed/collected owner throws ObjectDisposedException.
Transport, denial and timeout errors propagate rather than becoming mapping failures.
These are the explicit AD resolver contract, not claims of universal Windows LSA parity.

## Facade integration and publication

Owner/group reads and selected rule enumeration resolve outside wrapper/shared locks. Only
returned rules are translated; callbacks and excluded inherited/explicit rules cause no lookup.
Virtual rule factories run outside the shared/context gates. Result publication checks the
descriptor version, wrapper attachment and entry generation; a changed view requires retry.

Name-based owner/group, purge and typed/default rule mutations prepare the numeric SID before
publishing state. Public modify hooks still receive the original rule with native lock/dispatch
behavior; an override that declines it performs no lookup. If the concrete base path needs
resolution, it temporarily releases only the library-acquired wrapper write lock, then restores
it and revalidates state. A caller-held protected lock is never silently released: lookup from
that scope refuses before I/O. This is an explicit concurrency boundary, not a native LSA timing
claim. SID-only edits remain offline and usable even after resolution authority expires.

The prepared mapping is scoped to the wrapper and current operation. Final mutation publication
coordinates entry-generation validation with the shared transaction gate, without LDAP or user
callbacks under those gates. Failed resolution/revalidation adds no partial edit or dirty flag.
Descriptor/ACL copies and new wrappers contain no resolver, connection, lease, credential,
mapping cache or source authority. Explicit destination binding does not promote a source read
baseline into destination write authority.

## Safe raw preparation, before transport cutover

An internal read context captures original raw bytes, explicit retrieved sections and non-secret
owner/generation/target-DN provenance. It cannot replace pending edits. Bound wrapper operations
reject unread sections; preparation also catches shared-facade edits outside retrieval coverage.

`RawSecurityWritePreparation` prepares existing-object Modify data from retained raw state,
never from caller-visible normalized serialization. The internal caller must explicitly select
all pending sections without widening them; this does not enable a new public commit-mask policy.
Read-only normalization creates no request/control, reverted raw state is a no-op, and unrelated
ACE contributors, opaque bytes and tails remain intact under the existing preservation checks.
AccessControlSections, DirectoryServices.SecurityMasks and protocol SecurityMasks are converted
deliberately rather than treating all three enums as interchangeable.

Prepared requests revalidate wrapper identity, version, binding generation and destination DN.
They add one Replace nTSecurityDescriptor plus a nonzero SD-flags control, reject duplicate
security modifications/controls and return defensive byte copies. They do not send LDAP or clear
pending state. This is not server-side compare-and-swap: same-section concurrent server changes
still need the separately reviewed persistence contract.

LDAP Add is separate because SD-flags do not scope creation. No explicit descriptor means omit
the attribute. Under the [approved contracts](issue-226-persistence-decisions.md), explicit
creation descriptors remain a temporary unsupported boundary until validated. The staged
helper is not wired into existing Add behavior. The four policy choices are approved; their
public integration and independent native/wire validation remain required before rollout.

## Evidence and remaining scope

Offline tests exercise the actual resolver/parser through controlled read sessions and capture
requests, including duplicate/unmapped/ambiguous/FSP/error cases, escaping and domain qualification.
They exercise real entry rebind/Close/Dispose and controlled public RefreshCache paths, stale
publication races, lock progress, hooks, copy isolation, raw masks and destination checks.
Successful live commit/move and OS authentication continuity are not executed; their invalidation
hooks are source-integrated, not claimed as live evidence. Windows runs continue to replay all
existing native observations. The 36 SDDL refusals, eight facade refusals and 41 atomic-failure
differences are unchanged.

Remaining work includes public PrincipalContext adapter exposure within the approved coherent surface,
native/wire evidence for approved commit
and Add contracts, the coordinated AD/rule/consumer cutover, optional MicrosoftInterop companion,
broader deferred SDDL/facade cases and explicitly authorized AD validation. No live AD bind,
lookup, permission write, credential change, merge or issue closure is part of this slice.
