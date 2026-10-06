# Research: built-in identity resolution through existing directory context

Status: **requested investigation, not adopted or implemented**. PR #225. The library should
ship its AD resolver; callers should not need to implement LDAP lookup themselves. The common
path uses `DirectoryEntry.ObjectSecurity` and the entry's existing binding. Standalone values
require an explicit context/resolver. No new `ActiveDirectoryContext` or `GetAccessControl`
API is implied by illustrative names from discussion. The approved supporting namespace is
`AdForLinux.Security.*` in `AdForLinux.DirectoryServices.dll`; this remains one ACL API.

**Finding:** propagation is practical, but copying connection options into every descriptor
would retain credentials beyond the entry's lifetime. Current credential changes retain the
managed descriptor, while Close/path reset discard the entry's descriptor cache. Existing
entries created from PrincipalContext own independent settings and can survive that context's
disposal. Resolution must distinguish data lifetime from binding authority.

Recommended candidate: a library-owned AD resolver with a **borrowed, revocable owner binding**
for entry-derived descriptors. Snapshot only non-secret provenance; obtain current operation
resources from the owner while its captured binding epoch remains valid. No descriptor-owned
password copy, global resolver, guessed server or silent cross-domain fallback. Expired default
resolution fails, but captured SID/descriptor data and pending SID-based edits remain usable.
This lifecycle recommendation is a reviewable policy, not an already established compatibility
promise. See [offline evidence](../research/identity-context-probe/README.md).

## 1. Actual ownership and binding evidence

All observations below refer to current source, not proposed implementations:

| Source | Verified behavior | Resolver consequence |
|---|---|---|
| [DirectoryEntry](../../src/AdForLinux.DirectoryServices/DirectoryEntry.cs) constructors / GetConnection | Construction stores settings; GetConnection lazily binds and retains a connection; a separate schema connection avoids overlapping requests with asynchronous results | Configuration can be inspected offline. Do not inject lookup searches into a connection already producing results |
| Username / Password / AuthenticationType setters | Changed values clear option overrides, reset Options in place and dispose connections. ResetCredentialBinding preserves managed ObjectSecurity and its dirty state | A retained descriptor can outlive a credential epoch. Do not silently resolve its names under old copied credentials or transparently switch its default authority |
| Path reset / Close / Dispose | ResetBinding and Unbind clear descriptor cache and pending property state; Close leaves entry reusable; Dispose marks it unusable | Retained external descriptor references need their own explicit capability invalidation. Data need not disappear when authority expires |
| Options.Referral / SecurityMasks | Referral changes reset connections. SecurityMasks changes only the stored request mask; default is Owner+Group+Dacl, not Sacl | Referral policy is binding-sensitive. Changing masks must not retroactively mark cached descriptor sections retrieved |
| CreateEntryForDn/CreateEntryForPath | New entries receive credentials or cloned connection options | Existing behavior already creates independently configured entries; do not add another persistent credential copy solely for resolution |
| [LdapConnectionFactory](../../src/AdForLinux.DirectoryServices/Ldap/LdapConnectionFactory.cs) | CreateBound creates/binds a new connection owned by its caller. No connection-pool implementation was found in this checkout | Do not assume a reusable pool/lease manager exists. A future pool must preserve the same owner isolation and invalidation contract |
| [LdapConnectionOptions](../../src/AdForLinux.DirectoryServices/Ldap/LdapConnectionOptions.cs) | Carries credentials, endpoint, TLS/signing/sealing and a 30-second default operation timeout; Clone retains those credentials/settings | A cloned options object is not a safe long-lived descriptor context. Redacted logs must never serialize it |
| [PrincipalContext](../../src/AdForLinux.DirectoryServices.AccountManagement/PrincipalContext.cs) | Explicit endpoint, lazy discovery; CreateDirectoryEntry passes options into a new entry. Dispose releases its search root/retained foreign contexts, not every previously returned entry | A resolver borrowed directly from PrincipalContext dies with it; a resolver borrowed from an independently created entry follows that entry instead |
| [Principal.Save(context)](../../src/AdForLinux.DirectoryServices.AccountManagement/Principal.cs) | Persisted path reuses originalEntry, commits it, then changes ContextRef; rollback restores context reference. Cross-domain persisted moves are rejected | Do not infer that changing ContextRef changed the original entry's credentials. Follow actual entry binding; save/move requires generation revalidation |
| [ForeignPrincipalResolver](../../src/AdForLinux.DirectoryServices.AccountManagement/ForeignPrincipalResolver.cs) | Group-membership resolution can discover trusted domains/GC and create retained foreign contexts with inherited credentials | Not a safe drop-in for ACL name resolution: different scope, lifetime, fallback/error behavior and layering |

The [probe](../research/identity-context-probe/README.md) executes safe configuration/ownership
checks against the real projects. It never calls ObjectSecurity, GetConnection, Bind, Search,
Principal.Save or any live operation. Retention of the actual security object on credential
change is source evidence, not executed on the Linux BCL stub.

## 2. Existing API experience and layering

Illustrative usage with portable identity aliases:

```csharp
using P = AdForLinux.Security.Principal;
// entry already specifies endpoint, credentials and security options.
var security = entry.ObjectSecurity;
var owner = security.GetOwner(typeof(P.NTAccount));
var rules = security.GetAccessRules(true, true, typeof(P.NTAccount));
// Proposed default: built-in resolver borrows this entry's live captured binding.
```

Standalone identities have no directory association; neither their constructor nor an earlier
appearance in a rule attaches one. Candidate overloads/helpers are illustrative, not final:

```csharp
var sid = new P.SecurityIdentifier("S-1-5-21-1-2-3-1001");
var name = sid.Translate(typeof(P.NTAccount), entry); // convenient explicit entry overload
// Equivalent supporting helper, implemented by the library:
var resolver = DirectoryIdentityResolver.ForEntry(entry);
var sameName = sid.Translate(typeof(P.NTAccount), resolver);
// Higher-layer candidate helper, using an existing PrincipalContext:
var contextResolver = principalContext.CreateIdentityResolver();
var otherName = sid.Translate(typeof(P.NTAccount), contextResolver);
```

Intrinsic `Translate(Type)` remains same-kind-only (plus any explicitly specified context-free
well-known mappings); it cannot consult a descriptor it does not own. Cross-kind AD resolution
uses the explicit overload/provider. A descriptor's automatic resolver affects only its own
operations. No global/AsyncLocal/thread-local resolver or identity-to-context attachment.

```text
AccountManagement PrincipalContext (owns its existing credential configuration)
  -> adapter producing low-level resolver capability; checks its own disposal
  -> low-level DirectoryServices resolver/session contract
DirectoryEntry (owns its existing binding configuration)
  -> revocable capability -> built-in AD identity resolver -> LDAP read-only transport
ActiveDirectorySecurity -> capability for its owning entry (no credential copy)
Pure ACL/SID core -> no I/O, no resolver, no AccountManagement dependency
```

DirectoryServices must **not** reference AccountManagement; that would create a project cycle.
Use a narrow internal binding/session abstraction in DirectoryServices, implemented/adapted
from the higher layer through existing friend access. `Translate(Type, PrincipalContext)`
cannot be declared as a low-level instance member without that cycle. An AccountManagement
extension/helper can return the low-level library-owned resolver instead. The optional
`IIdentityResolver` contract is an extension seam, not an obligation to supply an implementation.

Reuse BuildOptions, RootDse reading and request/error handling where appropriate; do not expose
passwords or raw options through the resolver contract. A session should expose a constrained
read operation, effective domain scope, identity of the owner/epoch, and bounded lifetime.
No resolver-owned DirectoryEntry clone merely to keep credentials alive.

## 3. Binding lifetime: proposed borrowed epoch policy

A descriptor holds a weak/revocable reference to an owner-controlled capability plus captured
binding/attachment generations and non-secret domain provenance. A weak owner reference avoids
extending an otherwise unreachable owner's credential lifetime; callers must retain the owner
while requesting directory resolution. Resolution temporarily acquires a strong operation
lease after validating owner state. No persistent connection/credential snapshot lives in the
descriptor or standalone resolver. An intentional detached credential-owning resolver is not
part of this candidate.

| Event | Proposed behavior, pending lifecycle oracle/review |
|---|---|
| Get ObjectSecurity | Normal descriptor read; attach default resolver capability from actual entry. Do not perform name lookup merely to read bytes |
| Retain descriptor; entry remains unchanged | Resolve through captured owner epoch; SID getters and supported raw operations remain offline |
| Change username/password/authentication type, endpoint/path or effective referral policy | Revoke old epoch before rebind; clear resolver caches. Retained default resolver fails stale-context checks rather than changing identity silently. Preserve descriptor data/dirty state where current code does |
| Close | Revoke binding and attachment capability; retained descriptor is usable as data. Reusing entry can bind afresh, but does not revive the old capability |
| Dispose / owner collected | Default resolution fails disposed/expired-owner; no lookup, no fallback. Explicitly known context-free mappings need no owner; ordinary domain lookup does |
| SecurityMasks change | No retroactive retrieval change. Querying unread owner/group/ACL must not fetch it implicitly just to translate names |
| Refresh containing nTSecurityDescriptor, successful commit, move/rename/rebinding | Invalidate prior attachment/read generation along with current cache behavior. Reloaded descriptor gets a fresh capability; stale detached references cannot merge back without validation |
| Credential change while dirty descriptor is still the cached object | Keep pending SID edits. Do not automatically refresh its resolver just because ObjectSecurity returns the same reference. Fresh explicit resolution uses the entry overload/helper; a later intentional reload can create a new default attachment |
| Clone, binary/SDDL construction, Microsoft import/export | Copy data/provenance as allowed, **not** the credential capability. Detached objects need explicit resolution context; export/import does not smuggle credential authority |
| Assign a descriptor to another entry | No transfer of source resolver authority. Snapshot assignment/default reattachment semantics need final review; validate destination and preserve pending intent. Do not silently mutate a shared descriptor's resolver and change what another entry/caller observes |
| PrincipalContext.Dispose | Direct context resolver is revoked. An independently created entry follows its own existing ownership semantics; do not add new durable credential copies to emulate independence |
| Principal.Save(otherContext) / move | Resolver follows the actual entry's binding/generation, not ContextRef alone. No automatic credential/domain escalation through the new context. Failed save retains data and correctly revoked capabilities; no stale session revival |

The assignment row is an important remaining choice: current ObjectSecurity setter stores the
same reference. Attaching a new owner on that shared instance would redirect other callers'
lookups. Prefer an entry-local attachment wrapper/state or an explicitly documented detached
snapshot on assignment, but do not silently change reference/alias semantics before review.
It cannot be solved by setting one mutable `Resolver` field on every descriptor.

Resolution sequence: validate owner/generation -> reserve operation lease -> perform bounded
lookup outside descriptor write lock -> revalidate binding **and** descriptor generation ->
publish result/ACL edit under a coordinated guard. Invalidation must race safely with that
final publication. In-flight network work may already have reached the server; expiry can
reject the result but cannot retroactively erase a sent read. Close/dispose must not race
unsafely with a borrowed raw connection. The offline model demonstrates checks before/after
a fake lookup, **not** thread-safe production leasing or atomic publication.

After credential expiry, callers can still obtain the retained portable SID, then explicitly
resolve it against the desired current entry/context. That avoids discarding dirty descriptor
data or silently renewing its default authority. This policy needs usability/compatibility
review; automatic live rebinding is an alternative with different authority semantics, not
the unannounced default.

## 4. Built-in AD resolution scope

Initial proposed scope: the verified AD **domain naming context** on the explicitly configured
endpoint, with existing authentication/TLS policy. Resolve domain scope from server metadata
on the same authorized connection (RootDSE, naming contexts and configuration crossRef), not
from the object's parent OU, a credential suffix, or a hostname guess. A restricted search
container must not accidentally hide domain identities; if expanding to the domain root is
outside an explicitly configured resolution scope, report that limitation. Application
partitions, ambiguous GC/domain routing and unavailable metadata require explicit scope or
unsupported results rather than guessed defaults.

[objectSid](https://learn.microsoft.com/en-us/windows/win32/adschema/a-objectsid) is binary.
Use a full validated SID and equality filter with **every octet** escaped, e.g. the Everyone
SID produces `(objectSid=\01\01\00\00\00\00\00\01\00\00\00\00)`.
[RFC 4515](https://www.rfc-editor.org/rfc/rfc4515.html) specifies filter assertion escaping;
DN escaping and SID text are not substitutes. The current internal LdapFilter.EscapeBytes
and SidCodec support this primitive. Text values need correct UTF-8 assertion encoding,
including metacharacters and a defined rejection policy for ill-formed UTF-16; the simple
existing helper does not by itself establish that complete contract.

| Input/result | Proposed behavior |
|---|---|
| SID -> account | Search exact objectSid within allowed domain scope; retrieve only SID, account name/class and metadata needed for domain qualification. Require one usable identity, not merely the first row. Do not fabricate a name from CN or displayName |
| `NETBIOS\sam` | Validate/map domain qualifier from trusted crossRef metadata (`nETBIOSName`, `nCName`, `dnsRoot`). Search exact escaped sAMAccountName only in the matching authorized domain |
| DNS-domain-qualified name | Treat separately from NetBIOS input; map using verified dnsRoot/nCName if supported. Never assume the first DNS label is the NetBIOS name |
| UPN | Exact escaped userPrincipalName equality in allowed scope. UPN suffix need not equal the DNS domain and must not select a guessed server. Ambiguity fails |
| Bare SAM name | Only within a documented single effective domain; no machine-local/forest-wide search. Preserve trailing `$` for computer accounts |
| Well-known SID/name | Small explicit, tested context-free table; define canonical/localized name policy. Do not claim every Windows LSA alias or host-local principal is portable. Domain-relative aliases require verified domain SID context |
| Unknown/deleted SID or unreadable identity attributes | Report unmapped **within available scope/visibility**; cannot infer global nonexistence. Keep the original SID available; never drop an ACE |
| Multiple matches / duplicate UPN / conflicting native and foreign entries | Ambiguous result, no first-match choice; refuse mutation/whole translated enumeration by default |
| ForeignSecurityPrincipal | It may carry objectSid but not the authoritative issuing-domain account name. Do not treat its SID-shaped CN as a resolved NTAccount |
| Referral / another domain / forest | No automatic follow-on bind or credential forwarding. Require an explicitly authorized domain/endpoint map or report unsupported/unmapped scope; multiforest/LSA-equivalent trust traversal is deferred |

Microsoft schema documents distinguish
[crossRef](https://learn.microsoft.com/en-us/windows/win32/adschema/c-crossref) and
[nETBIOSName](https://learn.microsoft.com/en-us/windows/win32/adschema/a-netbiosname);
[ForeignSecurityPrincipal](https://learn.microsoft.com/en-us/windows/win32/adschema/c-foreignsecurityprincipal)
is a distinct object class. These support the scope boundaries, not a claim that a domain
LDAP search reproduces Windows LSA translation. SID history matching, service/virtual/local
accounts, implicit GC searches and trust discovery are not initial fallback behavior.

The existing factory maps non-None referral modes to All on Linux. Identity resolution must
therefore **not** blindly reuse a referral-chasing search connection. Use a scoped read session
with referrals disabled before requests (and without changing the entry's existing connection
settings); configure through the existing factory primitives with deliberate bind/search
ordering. A referral becomes a classified scope result. Any explicit routed extension needs
its own endpoint/authentication policy; the caller's entry credentials must not leak to an
unapproved host. Preserve existing certificate/signing/sealing policy; never weaken validation
or mutate process-global LDAP environment settings.

## 5. Lookup triggers and failure-before-mutation

| Operation | Lookup behavior |
|---|---|
| SID numeric/string/binary construction, equality, byte serialization | Offline; never attaches an owner or binds |
| NTAccount construction / rule factory with an NTAccount | Stores an unresolved name; no lookup merely to construct the rule |
| `GetOwner/GetGroup(typeof(portable SecurityIdentifier))` | Offline for retrieved data; missing/unread distinction preserved |
| `GetOwner/GetGroup(typeof(portable NTAccount))` | Built-in resolution through attached capability when needed; absent value is not a query |
| `GetAccessRules/GetAuditRules(..., typeof(portable NTAccount))` | Resolve identities of selected returned rules; deduplicate within the operation; do not include excluded/inherited entries just to resolve them |
| Add/Set/Reset/Remove/Purge with an NTAccount identity, SetOwner/SetGroup | Resolve before publishing any ACL/owner/group change or dirty intent. Validate static inputs first and recheck state after lookup. Existing SID inputs need no identity lookup |
| Serialization and Microsoft value-copy bridges | No incidental lookup. Domain-relative SDDL aliases need explicitly available context, not a guessed directory; Microsoft recipient operations may later do their own translation |
| Standalone `Translate(Type)` | Same-kind or explicitly defined local mapping only; AD translation requires the explicit entry/provider overload |

No network access while holding descriptor write locks. For a multi-identity operation, gather
validated mappings before publication; if any resolution fails, return no partially converted
collection and publish no partial mutation. Do not catch failures and silently substitute
Everyone, remove rules, return an NTAccount containing SID text, or convert missing data into
an empty ACL. Existing binary/opaque preservation, section intent and Add/Modify policies
remain unchanged.

Proposed error categories (public exception types/parameter names still require oracle review):
invalid identity/target type; no context; stale context; disposed owner; unmapped-in-scope;
ambiguous; unsupported topology/alias; bind/authentication failure; access denied; timeout;
transport/TLS/server error. Do not collapse denied access or a network outage into not-found,
and do not retry with anonymous/default/different credentials or another server. An LDAP
search can hide rows through ACL visibility, so a successful zero-result search still does
not prove the identity does not exist. Preserve safe diagnostics without passwords or options
dumps. AccountManagement may wrap errors at its boundary; the low layer must not depend on
PrincipalOperationException types.

## 6. Caches, operation limits and concurrency

Start with operation-local deduplication only: key by validated SID bytes or correctly scoped
name, target identity type and owner/binding epoch. No static cross-context cache. If later
adding a bounded TTL cache, include endpoint/domain/authentication/referral scope and generation
in partitioning, revoke on changes, avoid password-derived keys, and bound negative caching.
Never reuse negative answers across credentials, because directory visibility can differ.
Context-free well-known constants are the only reasonable process-wide immutable table.

Reuse the actual binding timeout (30 seconds by default), plus a total resolution deadline
covering metadata and multiple queries; do not multiply that timeout indefinitely per ACE.
Use size limits sufficient to detect ambiguity (not FindOne), inspect truncation/size-limit
responses, and refuse rather than treat a partial result as unique. Batching an OR filter can
be added with explicit byte/count limits and stable mapping to original identities; it is an
optimization, not required to validate this design. Existing synchronous signatures do not
magically gain cancellation. Cancellation/async overloads are deferred; internal request
abandonment on disposal/deadline must be specified and tested without promising instantaneous
cancellation of a request already sent.

Current DirectoryEntry does not supply a general concurrent lease manager. A narrow resolver
session/epoch mechanism is required; do not claim thread safety from WeakReference or
immutable descriptors alone. An operation-scoped independent lookup connection avoids
interference with active enumeration, but must use the owner's checked binding and be
released promptly. No pool is needed for initial correctness, and a pool must not be invented
as existing infrastructure.

## 7. Evidence and next tests

Executed Linux net8.0/runtime 8.0.0 and net10.0/runtime 10.0.0, SDK 10.0.100:

- Real configuration ownership: changed bind identity resets options in place; old options
  and derived entries retain prior snapshots; Close remains reusable; disposed owners reject
  new options; previously created entry survives PrincipalContext disposal.
- Existing codec/filter exact binary SID and metacharacter fixtures.
- **Model only:** borrowed generation rejects old credentials, simulated invalidation after
  lookup prevents publication, explicit reacquisition works, detached SID data stays usable.

No LDAP success/failure, authentication, server discovery, production epoch hook or actual
security-descriptor lifetime was tested. The model's fake lookup is not the built-in resolver.

| Next evidence | Precise scope |
|---|---|
| Offline request capture | Binary/text escaping, required attributes, domain-scoped bases, referrals disabled, size/deadline limits, 0/1/2 results, hidden attributes, FSP, duplicate UPN and partial results |
| Offline lifecycle integration | Every ResetConnection/Unbind/ResetBinding/Refresh/commit/move/assignment path, credential changes with dirty state, shared descriptor assignment, PrincipalContext vs entry ownership and save rollback |
| Concurrency model then integration | Invalidate before send, during lookup, before publication; dispose with active search; descriptor changes while names resolve; no stale cache or mutation publication |
| Windows oracle | Microsoft DirectoryServices **9.0.0**, net8/net10 separately; record loaded identity/ACL versions. No-directory cases: validation, local well-known values, target types and mutation timing. Domain NTAccount translation needs a real authorized directory/context and may differ intentionally from LSA |
| Controlled read-only AD tests later | Known user/group/computer/UPN, NetBIOS distinct from DNS, renamed/deleted principal, constrained visibility, denied metadata, ambiguous/foreign identities, timeout/referral and credential changes. Use supplied fixtures/accounts with least scope; no permission writes required for this phase |
| Mutation safety | Replay lookup errors before immutable edit publication and request capture; only separately authorized later tests should commit to AD. Samba results remain separate |

Windows [NTAccount source](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.Security.Principal.Windows/src/System/Security/Principal/NTAccount.cs)
uses Windows identity translation machinery, not this proposed LDAP resolver. Pin its errors
and call timing as an oracle, and document intentional topology/name-policy differences rather
than promising all LSA behavior.

The user's offer of computer GitHub access is conditional, **not authorization** to configure
that computer, register a runner, dispatch workflows or connect to AD. No such setup was needed
for these probes. A Windows .NET 8/10 host is needed for the outstanding offline Microsoft
oracle; read-only domain cases additionally require an explicitly scoped directory fixture.
Report those concrete prerequisites when ready, rather than treating general computer access
as approval for all tests.

## 8. Decisions to carry forward

1. Review borrowed-epoch expiry versus automatic rebinding, especially retained dirty objects;
   this draft recommends explicit reacquisition after authority changes.
2. Settle assignment/reference semantics before automatic propagation is implemented. A shared
   descriptor cannot hold one mutable owner resolver without redirecting other callers.
3. Define initial domain/name/well-known scope and error contract; multiforest lookup is not
   implied by a built-in resolver.
4. Approve the final helper/overload and higher-layer adapter shapes. The resolver is shipped
   by the library; callers can use existing DirectoryEntry/PrincipalContext without creating
   their own LDAP implementation.

These are remaining contract choices, not reasons to postpone independent parser, state,
request-capture and oracle design. All production implementation remains outside this PR.
