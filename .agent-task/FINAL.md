# Issue 45 handoff

## Implemented

- `GetGroups(context)` now resolves the principal SID in the target domain so
  foreign-security-principal membership is queried with the target-store DN.
- Group results are rooted at the explicitly configured context container.
- `GetAuthorizationGroups()` resolves token SIDs through the forest global
  catalog and supplements them with transitive SID/FSP membership searches.
- Added Samba coverage for explicit-container, default-container, and
  no-argument `GetGroups()` behavior.
- Added Windows differential coverage using an isolated base OU, plus an
  optional two-domain trust test driven by `AD_SECOND_*` settings.

## Validation

- Focused Samba test passed on .NET 10.
- Live Windows AD container differential passed on .NET 8 and .NET 10 with
  `AD_BASE_DN=OU=Issue45,OU=AoTesting,DC=adlab,DC=local`.
- The two-domain differential was not run because this worker has no configured
  `AD_SECOND_HOST` / `AD_SECOND_BASE_DN` trust lab.

## Environment note

Microsoft's no-argument `GetGroups()` requires forest locator discovery and
fails on this non-domain-joined runner even though explicit LDAPS contexts work.
That overload is therefore covered by the Samba regression; the live AD
differential covers both explicitly scoped and base-container context overloads.
