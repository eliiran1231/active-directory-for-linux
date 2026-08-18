# Issue 44 validation

Implemented the custom-principal extension compatibility contract:

- added the protected-internal `Principal.ContextRaw` surface;
- retained `DirectoryPropertyAttribute.Context` values;
- kept `Principal.ToString()` name-based and corrected persisted `Name` reads;
- moved `GetAuthorizationGroups()` to `UserPrincipal`;
- honored declared object class and RDN metadata during creation;
- constrained custom QBE and identity lookup by declared object class;
- materialized QBE results as the requested custom principal type; and
- allowed external subclasses to rely on attribute-based defaults instead of
  inaccessible abstract implementation members.

Validation completed on .NET 8 and .NET 10:

- solution Release build;
- focused functional surface/filter tests;
- Microsoft differential surface tests; and
- live Windows AD differential creation, property round-trip, identity lookup,
  QBE, custom result materialization, and `ToString()` tests under
  `OU=Issue44,OU=AoTesting,DC=adlab,DC=local`.

The live AD schema's `inetOrgPerson` class has a `CN` RDN. Non-`CN` metadata is
therefore covered at the extension metadata/construction-selection layer using
the standard `organizationalUnit`/`OU` pair rather than by creating an invalid
user-class DN on this server.
