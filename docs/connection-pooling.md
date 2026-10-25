# LDAP connection pooling

Connections are leased exclusively for an operation, rather than shared concurrently
by directory objects. Public entry/search/principal APIs retain their authentication,
referral and error semantics. There is no fallback from Negotiate to Basic, no
checkout rebind, and no managed replay after an LDAP operation has been sent.

## Eligibility

- Linux explicit nonempty Basic credentials reuse connections with the requested
  referral policy unchanged. Existing OpenLDAP referral authentication behavior is
  preserved; no new rebind callback or credential forwarding is installed.
- Basic with referrals disabled can reuse connections on all supported platforms.
- Windows additionally supports synchronous, fully buffered `DirectorySearcher.FindOne`
  for Base, OneLevel and Subtree with explicit nonempty Basic credentials, normally
  validated LDAPS and External referrals. Non-Base admission requires the FindOne
  request's `SizeLimit=1`. The host must be an explicit ASCII DNS name or canonical
  dotted IPv4 address. Host strings are preserved exactly for keys and native lookup;
  this is not a referral-destination allowlist or a DNS/DC pinning mechanism.
- Windows FindOne reuse excludes paging, asynchronous operations, request controls,
  DirSync, VLV, attribute-scope queries, connection overrides and existing retained
  entry/schema handles. StartTLS, certificate skipping, signing/sealing,
  Subordinate/All referrals, ambiguous host strings and IPv6 use existing fresh paths.
  General Windows referral-enabled entry, FindAll and streaming paths remain fresh
  at acquisition; retained API handles keep their existing ownership semantics.
- Kerberos/Negotiate, anonymous LDAP authentication and credential validation use
  fresh, capacity-accounted connections. Kerberos pooling is deferred to issue #236.

## Isolation and lifecycle

A process-random HMAC key covers exact endpoint, credentials, authentication,
transport, timeout and referral configuration. Entry DNs are not part of that key.
Passwords are not stored as key strings or written to logs. Native referral child
connections remain owned by the parent LDAP handle.

Windows scoped FindOne keys additionally include the effective token instance,
logon identifier, modification identifier, token type and impersonation level.
SID alone is insufficient. The token reader requests query access only and rejects
anonymous, restricted, AppContainer, unreadable and unsupported token contexts.
A rejected context uses a fresh connection with the caller's original explicit
LDAP credentials; it does not substitute a process identity after an access error.

Context checks surround acquisition, request preparation/send, completion and
return. If context changes before send, the unused reusable lease is discarded
and a fresh lease is used once. Context change after send invalidates the lease
without replaying the operation. This is not an atomic guarantee against another
actor mutating a token during a native operation. WinLDAP may independently reconnect
or share native referral sessions; managed no-replay is not native exactly-once.

FindOne owns its scoped lease until the single native response is buffered, then
materializes through a separate fresh schema lease. The preliminary binding-resolution
read preserves the root's referral policy. Size-limit partial results remain
available to the caller, while the failed scoped send is evicted. Disposal,
cancellation, failed initialization, transport failures and abandoned cursors cannot
return an unsafe connection to the idle pool. Identity/configuration changes advance
a generation boundary so outstanding old leases cannot return to current idle state.

Cross-context operations reserve endpoint pairs atomically. Buffered/streaming
search and schema paths explicitly own their leases, including early disposal.
Caller-held retained connections are never silently transferred to the pool.

## Bounds and operational limits

| Limit | Value |
| --- | ---: |
| Managed handles per exact key | 8 |
| Managed handles per process | 64 |
| Waiting acquisitions | 256 |
| Acquisition wait | 30 seconds |
| Idle expiry after return | 60 seconds |

Fresh bypasses count against the same capacity limits. Idle entries are retired on
expiry, failure or freshness changes. Native referral child sockets are outside the
managed-handle cap; these limits do not bound the number of server-selected targets.

## Validation scope

Maintained regressions cover exact key isolation, exclusive leases, cancellation,
capacity, generation transitions, eviction/no managed replay, token decoding and
classification, scoped lifecycle transitions, platform/configuration exclusions and
public FindOne partial-result materialization. Disposable Samba tests exercise real
Linux bind/read and streaming cleanup behavior.

Windows native evidence covers the shared scoped implementation on .NET 8 and 10,
including token changes and Base/OneLevel/Subtree FindOne with External referrals.
Those tests used synthetic loopback LDAPS endpoints and disposable hosted Windows
identities. Remote AD, subordinate/All chasing, multi-hop topologies and broader
transports/operations were not validated. One-off diagnostic harnesses and historical
reports remain on the diagnostic branch; evidence links belong in the PR description.
