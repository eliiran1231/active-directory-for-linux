# Opt-in two-controller identity-addressing probe

This is a user-run research tool, not an offline test or a supported cross-DC
`Principal.Save(context)` implementation. It was compiled but not run against AD.
No fixture is created. Use an existing disposable account already replicated to
both controllers and an existing destination container. The user must authorize
the selected operation on those exact objects before running a mutation mode.

Both endpoints use separate explicitly supplied credentials over LDAPS on port
636 with ordinary certificate validation. Referrals are disabled. Source reads
use only source credentials; the destination performs its own reads and optional
write using only destination credentials. Nothing falls back to ambient or source
authority. No credentials or description value are printed.

Set environment variables with prefix `ADFL_CROSS_DC_`:

| Suffix | Required value |
| --- | --- |
| SOURCE_HOST, SOURCE_USER, SOURCE_PASSWORD | Source endpoint and its own read authority |
| DESTINATION_HOST, DESTINATION_USER, DESTINATION_PASSWORD | Destination endpoint and its own authority |
| DOMAIN_GUID, DOMAIN_SID | Independently verified expected domain identity |
| OBJECT_GUID, OBJECT_SID | Independently verified expected disposable account identity |
| CONTAINER_GUID | Existing destination container GUID |
| NEW_RDN | Required only for move; complete escaped RDN, e.g. `CN=probe-next` |
| DESCRIPTION | Required only for Modify; replacement description on the disposable account |

Do not put credentials in command-line arguments or commit environment files.
From the repository root, select exactly one mode:

```sh
dotnet run --project docs/research/cross-dc-save-probe -c Release -f net8.0 -- --read-only
# Only after separately authorizing this exact fixture mutation:
dotnet run --project docs/research/cross-dc-save-probe -c Release -f net8.0 -- --execute-guid-move
dotnet run --project docs/research/cross-dc-save-probe -c Release -f net8.0 -- --execute-guid-modify
```

The read-only mode verifies domain GUID/SID on both endpoints, object GUID/SID
on both replicas, and the destination container. It does not establish permission
to write. Move sends one destination-owned ModifyDN with both the old object and
new parent expressed as `<GUID=...>` using hyphenated GUID text. Modify sends one
destination-owned GUID-addressed description replacement. These precise wire
forms are hypotheses to measure, not a claim that the configured server supports
them. Each successful operation is followed by destination GUID lookup and exact
identity/result checks. JSON lines distinguish preflight, sent operands,
acknowledged result and readback. Preserve output and exit status with the tested
commit/runtime/server versions; do not synthesize observations.

A rejected response is distinct from a missing response. Timeout/transport loss
after submission is reported as uncertain; post-acknowledgement read failure stays
acknowledged. There are no retries, compensating moves, restoration or cleanup
writes. After a mutation the fixture may remain moved/renamed or have its new
description. Resolve uncertain outcomes through separately authorized GUID reads
before another mutation; do not rerun blindly. A read-only rerun may itself refuse
while replication is incomplete. Cleanup belongs to the fixture owner.

Run both mutation modes with a destination account allowed to perform the change,
then, if separately authorized, with a destination account denied that change
while the source account would be allowed. Record whether the request is rejected
without changing the object. This tests authority separation; matching identities
and a successful reader bind are not write-authority evidence.

Remaining tests before public execution can be enabled include DN-reuse races,
replication lag, retained-wrapper provenance/revocation, pending Name and direct
property/security intent, a rejected move, an acknowledged move followed by failed
Modify, and a lost-response outcome. Controlled tests do not replace these live
server observations. This probe alone does not validate the full wrapper lifecycle
or Microsoft `Save(context)` parity.

Protocol references: [MS-ADTS Modify DN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/95fe5b94-859b-4001-a3e8-a98d6a417546)
defines old DN, new RDN and new parent as inputs; [extended-DN search control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/57056773-932c-4e55-9491-e13f49ba580c)
describes returned extended DNs. Neither returned extended-DN support nor equal
naming-context text is treated here as measured GUID-addressed write support.
