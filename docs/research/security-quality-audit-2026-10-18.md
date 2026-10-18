# Security and code-quality source audit — 2026-10-18

Base: freshly fetched `dev`, `6a609b22fa17b94f7b79004934964ffffbb45177`,
including merged PRs 229 and 231. No AGENTS.md or checkout-local skills were
present; `tests/OFFLINE-TESTING.md` supplied test admission instructions.
This is a bounded source review and offline regression exercise, not a complete
penetration test, certification, or claim of zero vulnerabilities.

## Confirmed findings and fixes

| Finding | Severity / preconditions | Evidence and affected code | Fix / residual risk |
| --- | --- | --- | --- |
| Cached search failure can become apparently successful partial results on reuse | Medium result-integrity defect; a streaming search fails after yielding a prefix, and the caller catches the error then re-enumerates or materializes the same collection. Security impact depends on using that partial set for a security decision; no direct privilege escalation demonstrated. | `SearchResultCollection.ReplayableSearchResults.TryGet`: neither records a terminal error nor disposes the cursor on `MoveNext`/`Current` failure. Iterator termination then allows `Count`/replay to accept the prefix. It also repeatedly disposes completed cursors. | Retain the original exception after the cached prefix; complete/dispose once on success, failure or explicit disposal. Tests cover both failure sites, replay, `Count` and repeated completed enumeration. Explicit disposal and cached snapshots keep their existing semantics. Cleanup exceptions can still mask the initial failure on the first call, as in the existing forward-only path. |
| Foreign context can be created after owner disposal | Low; concurrent `Dispose` and foreign-domain resolution, after local discovery is cached. | `PrincipalContext.GetForeignDomainContext` checked disposal before waiting for `_foreignContextLock`; disposal could clear the cache before the waiting caller repopulated it with a credential-bearing child. Deterministic monitor/worker regression fails on base. | Recheck disposal under the same lock as cache publication. This closes this specific lifecycle race, not a promise that all principal APIs are thread-safe. |
| Foreign principal read/discovery failure leaks its owned entry | Low resource-exhaustion risk; repeated SID-read or issuer-discovery failure. | `ForeignPrincipalResolver.ResolveOrCreateFallback` performed those operations before its cleanup `try`. Two controlled failure regressions leave the entry undisposed on base. | Enclose the entire owned-entry resolution in cleanup protection. Preserve ownership transfer to the unknown-principal fallback and existing exception translation. Other group-traversal exceptional cleanup deserves follow-up. |
| Offline CI does not cover the new audit branch | Low assurance gap, not a runtime exploit. | `source-audit-offline.yml` only admitted the previous fix branch. | Add this branch to the existing Linux/Windows, .NET 8/10 matrix. No live workflow, credentials, test allowlist or admission guard changes. |

No new high-severity vulnerability was established. Public details here describe
the bounded findings above; this is not evidence that high-severity bugs cannot exist.

## Inspected coverage and retained boundaries

| Area | Inspected evidence / assessment | Limitations and residual risk |
| --- | --- | --- |
| LDAP filters and DNs | AccountManagement `IdentityFilter`, `LdapFilter`, QBE translator, advanced/date filters and `Principal.EscapeRdnValue`; DirectoryServices `AdIdentityQueryPlan`, `AdIdentityLookup`, `LdapDistinguishedName`, `LdapPath`. Literal assertion inputs escape LDAP metacharacters; identity resolver uses strict UTF-8 octet escaping. RDN escaping handles separators, leading hash, edge spaces and NUL; DN splitting accounts for escaped-backslash parity. | QBE wildcard semantics and public date-filter normalization are deliberate compatibility behavior. Raw filters, RDN syntax and extension attribute names are caller/developer-controlled syntax, not safe slots for arbitrary untrusted strings. Serverless paths containing slash, IPv6 parsing and malformed Unicode outside the strict resolver merit dedicated compatibility cases; no speculative parser rewrite was made. |
| Authentication and TLS | `LdapConnectionFactory`, `LdapConnectionOptions`, `DirectoryEntry.BuildOptions`, `PrincipalContext` validation/options and password configuration. Bind/setup failures dispose owned connections; Negotiate is not silently downgraded to Basic. Default credential validation tries SSL simple bind then signed/sealed Negotiate. Password operations retain their protected-transport checks. | Explicit Basic without TLS remains permitted for API compatibility; deployers must select protected transport. `SkipCertificateCheck` remains an explicit unsafe option; Linux requires prior process configuration and does not change it at runtime. Native certificate validation, GSSAPI, channel binding and server policy were not tested. No credentials/settings changed. |
| Credentials and logging | Credential cloning/scope, password staging, resolver leases and exception translation reviewed; no production console/logger sink found. Resolver wrappers borrow weak owners and short-lived operations hold credentials only for the operation. | Managed immutable credential/password strings cannot be reliably zeroed; owner contexts retain them for reuse. Server error messages can include directory data and are propagated for compatibility; application logging needs its own redaction policy. No memory-dump or secret-history scan performed. |
| Resolver authority and referrals | `DirectoryIdentityResolver`, `IdentityResolverBinding`, `IdentityContextLifetime`, identity session/domain metadata and AccountManagement binding. Generation checks surround I/O/publication; explicit domain membership queries and critical domain-scope controls restrict resolver lookup. Identity sessions disable referral chasing before bind and reject returned references. | Ordinary searches retain API referral policy; Linux maps partial chasing modes to All because the native runtime lacks partial modes. Cross-trust credential behavior remains a live/native validation gap. Foreign-principal routing is separate from the strict descriptor resolver. |
| Descriptor parsing and preservation | Core `SecurityDescriptor`, `Acl`, `Ace`, `Sid`, `DescriptorRewriter`, raw-write preparation and entry security persistence; selected facade/SDDL boundaries and existing codec/mutation tests. Bounds/counts are checked before component reads; opaque ACEs, gap/trailing bytes, absent/NULL/empty ACL distinctions are retained. Ambiguous unsafe relocation refuses rather than guessing. | Large facade/SDDL implementation was sampled, not line-by-line formally verified or newly fuzzed. Deliberate portable preservation can differ from Microsoft's observable projection; no normalization rewrite. Hostile large inputs and parser/native conversion limits remain areas for further resource-bound testing. |
| Mutation atomicity and concurrency | Entry commit snapshots, property version gates, retained uncertain-write state, principal/SPN acknowledgment and private cross-context executor inspected; PR231 atomic replacement kept intact. Commit gates prevent concurrent commit and avoid blind replay of uncertain writes. | Principal Save can involve multiple operations; it is not a distributed transaction. CollectionBase and all public wrappers are not generally thread-safe. Duplicate-value replacement remains the documented ADSI/LDAP parity gap. Public cross-DC Save stays disabled; two-DC work remains deferred in [issue 230](https://github.com/eliiran1231/active-directory-for-linux/issues/230). |
| Disposal and search resource bounds | Entry/session ownership, `SearchResultCollection`, producer cleanup, principal search cursor, foreign contexts/resolution and group recursion inspected. Confirmed fixes above have controlled offline tests. | `StreamingSearchResultSource` has an unbounded producer queue; stalled consumers and broad/large directory searches can consume substantial memory, even with `CacheResults=false`. Backpressure must be designed with native callbacks/cancellation rather than added casually. Callers should bound searches and dispose collections. |
| Dependencies and CI | All project package references, solution build and all four workflows reviewed. NuGet `list package --vulnerable --include-transitive --format json` against `https://api.nuget.org/v3/index.json` reported no vulnerable packages on this date. Compatibility dependencies remain pinned at their existing versions. Offline runner tests exercise exact admission and guard behavior. | Advisory results cover the restored NuGet graph, not the OS/OpenLDAP/GSSAPI stack or unpublished issues. Actions use version tags rather than immutable SHAs; general main CI uses a mutable Samba image. Live differential workflow remains separate, undispatched and subject to its existing lab controls. This review did not validate repository/runner/environment protection settings. |

## Quality assessment

The project has substantial defensive engineering and unusually extensive
compatibility/retained-state tests. It is not uniformly poor code. The main concern
is maintenance complexity at ownership and state-transition boundaries: dense
multi-statement sections, multiple locks/version tokens, and large facade files
make exceptional paths easy to miss. `Principal.cs` exceeds 1,500 lines and
`Security/AccessControl/Acls.cs` exceeds 3,200; size alone is not a vulnerability,
but these need focused review ownership. This patch improves the affected cursor
state transitions and entry ownership boundaries, without broad risky rewrites.

Confidence is strongest in detached descriptor preservation and guarded local
state behavior, weaker in native authentication/referral behavior and multi-server
operation. Production use still needs deployment-specific TLS/authentication and
separately authorized integration validation. The overall posture is promising
but complex and incompletely validated, not production security certification.

## Validation and review

- The six new regression cases fail against the unchanged base production files:
  6 failed, 393 passed, 1 existing cross-DC skip in guarded V1PrincipalAuditTests
  on Linux .NET 8. Original sources were temporarily substituted and fixes restored
  in `finally`; no guard was bypassed.
- The approved offline runner's five Python tests pass. Release solution build
  succeeds; existing compiler/analyzer warnings remain.
- Full guarded Linux functional suites pass on .NET 8 and .NET 10: 13,433 passed
  and one existing cross-DC skip each. The branch-specific GitHub Actions matrix
  must be checked at the published head; final counts and links are recorded
  in the PR. The matrix builds both targets and runs functional tests on Linux and
  Windows plus public-surface and companion groups on Windows.
- Independent review of AccountManagement changes and the search fix/tests was
  performed by separate reviewers. Cleanup-exception masking and unbounded
  streaming were identified as residual risks and retained above.
- No live AD integration, password/credential changes, security-setting changes,
  two-DC tests, merge or release were performed. Offline admission guards and
  allowlists remain enabled and unchanged.
