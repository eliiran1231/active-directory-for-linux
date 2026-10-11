# Microsoft companion: supported export-only contract

On 2026-10-11 the user explicitly chose Microsoft conversion to be export only and asked
for the edit-back code to be removed. This supersedes the 2026-10-09 bidirectional contract.
The optional package remains `AdForLinux.DirectoryServices.MicrosoftInterop`, targeting
`net8.0-windows` and `net10.0-windows`, with an exact matching core version and pinned
Microsoft `System.DirectoryServices` 9.0.0. No package release is part of this change.

## Public surface

Only `MicrosoftConversions` and `SecurityDescriptorSnapshot` are exported. Both retain
`SupportedOSPlatform("windows")`; native construction has runtime Windows checks.

| Extension | Portable input | Result |
| --- | --- | --- |
| `ToMicrosoftObject` | `SecurityIdentifier` | Microsoft `SecurityIdentifier` |
| `ToMicrosoftObject` | `NTAccount` | Microsoft `NTAccount` |
| `ToMicrosoftObject` | `IdentityReference` | Microsoft `IdentityReference` |
| `ToMicrosoftObject` | `ActiveDirectoryAccessRule` | Microsoft AD access rule, preserving known subtype |
| `ToMicrosoftObject` | `ActiveDirectoryAuditRule` | Microsoft AD audit rule |
| `ToMicrosoftObjects` | `IdentityReferenceCollection` | Read-only list of Microsoft identities |
| `ToMicrosoftObjects` | `AuthorizationRuleCollection` | Read-only list of Microsoft rules |
| `ToMicrosoftObject` | `ActiveDirectorySecurity` | Independent Microsoft AD descriptor |
| `CaptureSnapshot` | `ActiveDirectorySecurity` | Immutable data-only snapshot |

The snapshot has no public constructor. Its read-only properties are `RetrievedSections`
and `PendingWriteSections`. `GetRawBinaryForm`, `GetOriginalBinaryForm` and
`GetObservableBinaryForm` return defensive byte copies. `ToMicrosoftObject` returns a
fresh independent Microsoft descriptor. A snapshot is not an edit token or write authority.

The nine extensions and exact exported types are pinned by companion API tests.
There are no `ToPortableObject`/`ToPortableObjects`, `ExportForEdit`, `MicrosoftSecurityEdit`
or `ApplyTo` APIs. The import-specific entry points, baseline/session tokens and value-diff
ACL reconciliation were removed, including the core/facade path used only by edit-back.

## Preservation and dependency boundaries

Export validates complete retrieved coverage, raw layout and every raw contributor before
constructing a Microsoft descriptor. It then inspects actual serialized output against the
verified observable projection. Unsupported flags, unexplained storage, opaque data or
field/subtype loss still refuse. Identity/rule output inspection captures fields solely to
validate one-way exports; it does not construct or return portable objects from Microsoft input.
No names are resolved. Raw write bytes are never replaced by observable/native copies.

The core friend boundary supplies data snapshots and strict export validation. Snapshot
source-wrapper IDs, attachment stamps and edit baselines were removed. Ordinary descriptor
mutation generations, contributor mapping, identity attachment/lifetime checks, raw read
origins and persistence checks remain because portable mutation and writes still need them.
The named friend relationship and package version pinning are unchanged, not a new security
boundary. Core and AccountManagement do not reference/load the companion or Microsoft
DirectoryServices dependency on Linux.

## Coverage migration

Tests for removed edit-session consumption, retry, stale sessions and diff-specific
mask/deletion/insertion planning were retired with that code. Preservation tests remain on
the applicable routes: export refusal and source/snapshot immutability, portable owner/group
mutation with shared descriptors, partial retrieval, pending intent and exact fake-transport
entry writes (including refusal of every unread-section edit), lifetime-free exported data and native rule field/subtype equality. The
256-case bounded edit-back worker now probes accepted/refused export targets while proving
source raw/live data, generation, shared wrappers, pending intent and defensive snapshots
remain unchanged. Existing mutation/replay, shared rollback, raw-layout/contained-alias,
identity and persistence suites remain; this removal does not loosen any of their policies.

See the [package guide](../../src/AdForLinux.DirectoryServices.MicrosoftInterop/README.md)
and [compiled export example](../examples/MicrosoftInteropUsage.cs). Exported Microsoft
objects may be edited independently. To edit portable state, use portable APIs directly;
there is no import/apply-back route and no automatic persistence.
