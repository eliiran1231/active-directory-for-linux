# Issue 38 validation

## Contract

- A domain `PrincipalContext` without an explicit container exposes `Container == null`.
- Domain-wide queries use `defaultNamingContext`.
- New users and groups use the Users DN from `wellKnownObjects`.
- New computers use the Computers DN from `wellKnownObjects`.
- The returned DNs are used verbatim, so renamed or moved well-known containers work.

## Evidence

- `dotnet build AdForLinux.sln --no-restore` passed for net8.0 and net10.0.
- Focused Samba functional tests passed on net8.0 and net10.0 (3 tests per framework).
- Live Windows AD differential test passed on net8.0 and net10.0 with
  `AD_BASE_DN=OU=Issue38,OU=AoTesting,DC=adlab,DC=local`; temporary objects were
  created only in that isolated OU.
- `git diff --check` passed.

The live differential test intentionally validates default-context public state and
domain-root query behavior without creating objects in the domain's shared default
Users or Computers containers. Default creation placement for all three principal
types is covered against the Samba AD fixture.
