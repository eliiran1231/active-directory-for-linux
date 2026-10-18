# LDAP connection lifecycle design (issue 15)

## Audit and integration boundaries

`LdapConnectionFactory.Create` configures Protocols 9.0.0 connections (net8.0 and
net10.0). `CreateBound` owns setup/bind failure cleanup. There are four owners:

* `PrincipalContext` discovery calls own a connection for one request sequence.
  Credential validation also calls the factory, but must always bind afresh.
* `LdapIdentitySearchSession` owns a referral-disabled connection for the full
  domain-discovery and identity-translation sequence.
* `CrossContextSaveSession` owns a referral-disabled preflight connection and
  changes its timeout. Live writes are intentionally disabled in this transport.
* `DirectoryEntry` retains primary and schema connections. Its raw connections
  reach mutations, security persistence, schema caches and ranged reads.
  `DirectorySearcher` borrows them, changes referral/timeout state, and keeps a
  separate copied entry alive for streaming work, including native async Abort.
  Close and even same-value credential setters explicitly invalidate bindings.

The initial pooling boundary is context discovery and identity search sessions.
Cross-context preflight remains directly owned: it retains two simultaneous
sessions and applies a changing remaining deadline at creation. Pooling this path
requires atomic multi-connection reservation or a sequencing redesign; simply
wrapping it would fragment keys and introduce capacity starvation. Retained
entry/searcher connections remain directly owned: treating entry disposal as a
pool return would allow untracked in-flight requests, explicit rebinds, abandoned
page cookies and mutable referral state to escape into another caller. This is a
conservative limitation, not evidence that entry/search workloads are accelerated.
Their existing disposal and offline guards remain intact. No writes are retried.

## ObjectPool evaluation, before implementation

Evaluated Microsoft.Extensions.ObjectPool **8.0.0**, including the official
[package frameworks](https://www.nuget.org/packages/Microsoft.Extensions.ObjectPool/8.0.0),
[versioned DefaultObjectPool source](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/ObjectPool/src/DefaultObjectPool.cs),
and [provider source](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/ObjectPool/src/DefaultObjectPoolProvider.cs).
It is a Microsoft-maintained ASP.NET Core component with compatible net8.0 and
netstandard2.0 assets; this version is a reproducible comparison, not a proposal
to pin the project to an older package. `Get` creates on empty;
`maximumRetained` only bounds returned objects. The provider supports disposable
objects, but neither API supplies bounded acquisition, cancellation, idle ages,
key isolation or registry eviction.

Option A would require an outer capacity reservation system, timestamps, a keyed
registry and shutdown coordination, while the retained queue is not exposed for
age eviction. Option B owns a small keyed idle list and one synchronization gate.
Choose B: adding ObjectPool would duplicate ownership without removing the hard
lifecycle work. No new package dependency.

## Code-level design

`BoundedConnectionPool<TKey,T>` reserves per-key/global capacity under one gate,
creates outside that gate, and returns an exclusive idempotent lease. The cap
includes connections being created and destroyed. Waiting has a monotonic deadline
and cancellation; waiters do not register new keys. Idle slots are timestamped on
return, swept on acquire and by a periodic timer, and never evicted while leased.
Shutdown rejects acquisition and drains idle resources; outstanding leases dispose
on return. Empty key records are removed. Factory failures release reservations.

`LdapConnectionProvider` maps immutable configuration to an opaque keyed HMAC,
with length-delimited inputs including the password and all transport/session
settings. No entry DN appears in the key. Neither keys nor identities are logged.
Only explicit Basic credentials are initially reusable. Ambient/default, anonymous,
Negotiate/Kerberos and other mechanisms use fresh owned connections because their
effective native authentication identity cannot be established reliably here.
Validation bypasses the provider entirely. No checkout rebind or probe is added.

Sessions disable referrals before bind; referral policy participates in the key.
Borrowers cannot return raw connections themselves. Real transport failures mark
the lease unusable; ordinary LDAP operation results do not imply a broken socket.
All acquisition paths retain the pre-native offline guard. Nested discovery is
resolved before acquiring, or after releasing, its outer connection.

Defaults: 8 connections per key, 64 total pool-managed connections, 256 concurrent waiters, 60 seconds idle
from return, 30 seconds acquisition wait, 5-second cleanup interval. These are
internal constructor settings, distinct from operation timeouts. No maximum age
is imposed on active requests. FIFO fairness is not promised. Capacity limits
cover this manager; legacy directly owned connections remain outside its bounds.

Acquisition timeout bounds capacity waiting, not an in-progress native bind. Bind
uses the existing LDAP timeout; native cancellation is not introduced. Cleanup
disposes idle resources synchronously unless an already-running sweep owns them;
that sweep finishes their disposal. Shutdown never closes active caller resources.

## Validation and review

`ConnectionPoolTests` is allowlisted by `tests/run-offline-tests.py`: fake resources
and a monotonic clock cover expiry, hard limits, cancellation, delayed creation,
blocked disposal, failure classification, exact credential-key isolation and
concurrent return/sweep/shutdown. No native LDAP handles are created by these tests.
Independent review caught and corrected capacity accounting for bypassed sessions,
nested preflight starvation, and UTF-8 replacement collisions in malformed UTF-16
credentials. Keys now encode exact UTF-16 units before HMAC hashing.

`ConnectionPoolSambaTests` is deliberately not offline-allowlisted. Disposable CI
compares twenty direct factory/bind/rootDSE operations with the same pooled sequence
and records creation/bind counts and elapsed time. This is a narrow before/after
comparison, not throughput, network-fault, live AD, Kerberos or TLS parity evidence.
Existing Linux/Windows offline workflows and the existing disposable Samba workflow
run for PRs targeting dev. Remaining entry/searcher and cross-context integration
requires its own operation ownership design and tests before issue 15 can close.
