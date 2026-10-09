# PrincipalContext identity adapter — internal dependency

This implements the ownership/layering dependency described by the approved
[context resolver research](https://github.com/eliiran1231/active-directory-for-linux/blob/ea0786fc3e75658732e7ac15a94134d54e24bf6c/docs/design/context-bound-identity-resolution.md#2-existing-api-experience-and-layering)
and [D11](https://github.com/eliiran1231/active-directory-for-linux/blob/ea0786fc3e75658732e7ac15a94134d54e24bf6c/docs/design/acl-decisions.md#d11-identity-resolution-and-ambient-kerberos).
The research's helper names were illustrative. `PrincipalContext.CreateIdentityResolver` is
therefore **internal only** in this slice; it is not a new public API or a claim that public
PrincipalContext/security integration has shipped. Public AD types, Principal.Sid, persistence
and the 55-type required-surface target remain unchanged.

## Ownership and layering

DirectoryServices defines an internal borrowed-owner binding; its existing ForEntry path now
uses the entry implementation. AccountManagement implements the context binding through the
existing friend assembly relationship. DirectoryServices does not reference AccountManagement.
Both routes use the same library-owned resolver, AD session and server-verified membership proof.

The context adapter holds only a weak PrincipalContext reference and a non-secret captured
generation. Capturing it performs no discovery, connection, lookup or SearchRoot creation.
During an operation it borrows BuildOptions and the configured container under the context's
lifetime guard and keeps a strong owner lease only until the operation exits, including failure.
Options/credentials and the independent session are operation-local, never retained in a
resolver or descriptor. No credential-owning DirectoryEntry is created solely for resolution;
existing PrincipalContext search/discovery connections are neither borrowed nor reconfigured.
The session uses the original context's endpoint/port, authentication, TLS, signing/sealing and
credentials. Credential-validation probes do not become implicit resolver identity.

A configured container must pass the existing server-side single-NC membership proof. Only a
null (unspecified) context container selects the same session's independently verified default
domain NC as its target; this does not consult hostname/credential labels, discover a trust,
use a GC or route to another domain. Explicit empty/whitespace containers refuse. Entry-derived
resolvers still require a nonempty entry DN and do not acquire this default-domain behavior.
Standard GC endpoints remain refused before opening a session.

PrincipalContext.Dispose revokes its identity generation before disposing owned resources.
In-flight independent sessions are allowed to unwind and dispose normally; their results cannot
publish after revocation. LDAP runs outside the owner guard, so disposal can progress during a
lookup. A collected context cannot be revived by its resolver. SID values and already prepared
SID edits remain usable offline; cross-kind mapping requires a live valid owner.

An independently created DirectoryEntry retains its existing independent ownership and may
outlive PrincipalContext.Dispose. Its resolver follows that entry, not the disposed context.
Changing a Principal's ContextRef alone does not retarget its actual entry binding.

## Authority isolation

Context resolution does not establish a DirectoryEntry-specific raw read/write origin. The
context binding refuses the internal origin request; it cannot satisfy raw-write preparation
by borrowing another entry's provenance. Descriptor copies and fresh wrappers sharing descriptor
data receive no source binding, credentials, connection or authority. Explicit destination
binding uses only the destination's context and does not fall back to the source.

Ambient SID-to-name lookup remains allowed. Name-to-SID mutation retains the existing explicit
authenticated-credential requirement. No ambient identity-pinning policy is added. The four
open persistence choices (commit masks, same-entry/detached assignment intent, LDAP Add defaults
and ambient mutation validity) and public transport cutover remain paused.

## Controlled verification

24 new offline tests cover configured/default containers, Unicode membership inputs, exact
option borrowing, explicit simple bind, GC/empty-container refusal, failed membership with no
fallback, ambient-read limits, disposal before/during each proof, concurrent disposal progress,
independent entry survival, data-only binary/shared copies, destination binding, raw-origin
refusal, public surface/layering guards, weak owner collection and a temporary operation lease.
The lease regression blocks a real controlled lookup, collects external owner references,
requires the owner to survive during I/O and become collectible after completion while the
resolver remains retained. No test connects to a directory or uses real credentials.

Existing entry resolver, server proof, raw preparation, preservation and native replay tests
remain in the explicit offline filter. Full Linux .NET 8/10 and exact-published-head Windows
builds/tests plus native freshness checks are required before reporting this slice verified.

## Interop review and remaining dependencies

The [interop design](https://github.com/eliiran1231/active-directory-for-linux/blob/ea0786fc3e75658732e7ac15a94134d54e24bf6c/docs/design/acl-microsoft-interop-and-overrides.md)
and [D1/D2/D8 decisions](https://github.com/eliiran1231/active-directory-for-linux/blob/ea0786fc3e75658732e7ac15a94134d54e24bf6c/docs/design/acl-decisions.md)
require detached explicit Microsoft snapshots, a separate provenance-bearing edit-back export,
and an optional companion assembly. They do not finalize companion/package/helper names or
the internal snapshot interface. Current AD rules/security and Principal.Sid still use their
existing hierarchy; silently publishing a converter against that hierarchy would not implement
the future portable AD surface. SID/name snapshot primitives are feasible independently, but
this slice does not invent a public bridge or finalize packaging/interface choices.

Next integration gates are adoption of the context helper's public exposure within the coherent
portable surface; the pending persistence policies before transport cutover; reviewed companion
naming/snapshot interface and measured import/edit-back reconciliation for Microsoft interop;
and separately authorized live AD validation. No claim of full dependency closure is made.
