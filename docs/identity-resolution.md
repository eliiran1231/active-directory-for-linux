# Explicit portable identity translation

Use the approved helper for standalone SID/name lookup with an existing entry or context.
Normal `DirectoryEntry.ObjectSecurity` operations already use their entry context.

```csharp
using AdForLinux.DirectoryServices;
using AdForLinux.Security.Principal;

// entry is an existing caller-owned DirectoryEntry.
var resolver = DirectoryIdentityResolver.ForEntry(entry);
var sid = (SecurityIdentifier)resolver.Translate(
    new NTAccount("EXAMPLE", "alice"), typeof(SecurityIdentifier));

// Or borrow an existing PrincipalContext:
var contextResolver = context.CreateIdentityResolver();
var name = (NTAccount)contextResolver.Translate(sid, typeof(NTAccount));

var inputs = new IdentityReferenceCollection { sid };
var partial = resolver.Translate(inputs, typeof(NTAccount));
var complete = resolver.Translate(inputs, typeof(NTAccount), forceSuccess: true);
```

Factories perform no connection or lookup. Keep the original owner alive: the helper holds
a weak revocable binding. Cross-kind operations borrow that owner's existing configuration
for an operation-local checked session. Closing, rebinding, refreshing the entry descriptor
or disposing the owner invalidates cross-kind use; reacquire a helper explicitly afterward.
Same-kind conversion and empty collections remain offline, even after revocation.

The collection overload preserves input order and takes a snapshot. Its default
`forceSuccess=false` retains unmapped input identities in their original positions;
`true` throws `IdentityNotMappedException` containing the unmapped inputs. The single-value
overload throws for an unmapped identity. Transport, timeout, ambiguity and lifetime failures
propagate instead of masquerading as unmapped results.

Returned identities contain data only. Their own `Translate(Type)` method does not inherit
this helper, and identity/descriptor copies or Microsoft export do not carry resolver access,
credentials or connection ownership. The sealed helper has no public constructor, credential
options, provider interface or public `Bind` operation.

The existing verified single-domain boundary remains: GC/cross-forest routing, foreign
issuing-domain lookup and ambient name-to-SID mutation without identity proof are not enabled.
Name-to-SID translation still requires explicit authenticated owner credentials. This helper
does not select authentication modes or weaken TLS, signing, sealing or referral policy.

[Compiled public consumer example](examples/IdentityResolverUsage.cs) ·
[Current identity boundaries](implementation/issue-226-identity-next.md)
