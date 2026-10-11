# Identity completion within explicit authority boundaries

The existing public `DirectoryEntry.ObjectSecurity` path automatically binds a revocable
entry context. `GetOwner`, `GetGroup`, access-rule and audit-rule reads can request
`NTAccount`; owner/group/rule mutations accept names and resolve them before atomic
publication. Numeric identity operations need no lookup. Sixteen additional public-route
cases exercise this actual loader with fake sessions: eight reads across ambient and
explicit contexts, and eight mutations covering explicit names and ambient refusal.
These cases cover `Close` and binary-copy isolation; disposal, rebinding and cross-entry
authority isolation are covered by the older lifetime suites.
Fake sessions prove dispatch, bounded lookup, lifetime and rollback, not working OS auth.

Standalone `IdentityReference.Translate(Type)` still has no authority; same-kind conversion
works and cross-kind conversion refuses. The explicitly approved public helper contract is:

- `DirectoryIdentityResolver.ForEntry(DirectoryEntry)` returns a revocable borrowed context.
- Its existing single and collection `Translate` methods provide explicit standalone mapping.
- `PrincipalContext.CreateIdentityResolver()` exposes the existing context adapter.
- `Bind` remains internal. No provider interface, credential constructor, global/ambient
  authority registration or identity-attached resolver is proposed.

These methods are now public. The sealed resolver has no public constructor; `Bind` and the
borrowed-owner adapter remain internal. See [usage and lifetime](../identity-resolution.md)
and the [compiled consumer example](../examples/IdentityResolverUsage.cs).
Descriptors and values never transfer credentials, connections or context authority through
copies. Existing generation checks must cover both lookup and publication.

The finite internal preparation now extracts the existing server metadata validator and
single-domain account query planner into `AdIdentityDomainMetadata` and `AdIdentityQueryPlan`.
Production `AdIdentityLookup` uses both. Immutable metadata contains only NC, NetBIOS and
DNS strings; a plan contains only the NC/filter and fixed search shape. Neither stores
credentials, connection options, an owner, lease or callback. Execution, deadline/generation
checks, critical domain-scope controls and the three membership proofs remain in the
existing checked session. Metadata does not confer routing authority.

Thirty-eight directed cases pin exact SID, bare/qualified SAM and exact UPN requests,
including alternate UPN suffixes and escaping. Successful single mappings still open one
session and issue six requests to the same endpoint/NCs with the same attributes and
controls. Extra discovered contexts cannot authorize a foreign qualifier or bare-SAM fanout;
duplicate/conflicting crossRefs never select a first match. Incomplete metadata and
application/configuration partitions yield no executable account plan. Existing GC-before-
session, FSP, ambient-mutation, lifecycle and membership tests remain authoritative.

This completes single-domain extraction, not GC or multi-domain routing. The GC port guard
stays in place. Forest-wide GC scope and cross-domain routing need explicit authority decisions;
no discovered host receives forwarded credentials. AccountManagement's foreign-principal
resolver is not a substitute: one-result searches, fallback discovery and retained foreign
contexts do not establish this resolver's uniqueness and borrowed-authority contract.
FSP display names require the authorized issuing context; SID history needs an explicit
matched-versus-current SID contract and must never silently rewrite an ACE SID.

Pinned System.DirectoryServices.Protocols 9 Linux explicit-credential Negotiate behavior
requires separate provider evidence from ambient SASL and Basic over verified TLS. No
BasicAuthFallback or transport/authentication relaxation is enabled. Ambient mutation still
requires proven identity continuity across the actual connection lifecycle; WhoAmI or
before/after username labels alone do not prove reconnect continuity. Live multi-domain,
forest, ticket and reconnect fixtures need separately scoped authorization.
