# Identity completion within explicit authority boundaries

The existing public `DirectoryEntry.ObjectSecurity` path automatically binds a revocable
entry context. `GetOwner`, `GetGroup`, access-rule and audit-rule reads can request
`NTAccount`; owner/group/rule mutations accept names and resolve them before atomic
publication. Numeric identity operations need no lookup. Sixteen additional public-route
cases exercise this actual loader with fake sessions: ambient and explicit reads, explicit
name mutations, ambient mutation refusal, disposal/rebinding lifetime and copy isolation.
Fake sessions prove dispatch, bounded lookup, lifetime and rollback, not working OS auth.

Standalone `IdentityReference.Translate(Type)` still has no authority; same-kind conversion
works and cross-kind conversion refuses. The minimum helper contract under review is:

- `DirectoryIdentityResolver.ForEntry(DirectoryEntry)` returns a revocable borrowed context.
- Its existing single and collection `Translate` methods provide explicit standalone mapping.
- `PrincipalContext.CreateIdentityResolver()` exposes the existing context adapter.
- `Bind` remains internal. No provider interface, credential constructor, global/ambient
  authority registration or identity-attached resolver is proposed.

These names/signatures are a **proposal awaiting user approval**, not exported by this slice.
Descriptors and values never transfer credentials, connections or context authority through
copies. Existing generation checks must cover both lookup and publication.

Internal work can proceed without this decision: classify bounded unique results, verify
per-domain naming contexts/crossRefs, retain generation/revocation tests, and model routing
without enabling it. The GC port guard stays until a bounded, verified per-domain planner
exists. Forest-wide GC scope and cross-domain routing need explicit authority decisions;
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
