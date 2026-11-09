# PrincipalSearcher native limit after failure

The retained `DirectorySearcher` returned by `PrincipalSearcher.GetUnderlyingSearcher`
exposes an established Microsoft compatibility quirk: `PrincipalSearcher.FindOne`
temporarily sets SizeLimit=1, and a failure before native query acceptance leaves
that value in place. A subsequent FindAll therefore uses 1 until the caller changes
the retained configuration. This is public state, not evidence of a server-side
write or a measured lost result.

[Issue #203](https://github.com/eliiran1231/active-directory-for-linux/issues/203)
recorded the exact start 7 -> Microsoft 1 versus finally-restored 7 comparison.
Commit `c6229851284eb0ad98580b09fd572c44fc88281b` deliberately removed the finally.
Commit `9999fa4a254afb0e46c695729528d42f44d577e2` inadvertently reversed that decision.
The unchanged live differential case reproduced it at `ba3d0ec` in
[Windows run 42700970079](https://github.com/eliiran1231/active-directory-for-linux/actions/runs/42700970079).
Both runtime targets use Microsoft packages 9.0.0; they are not separate versions
of the Microsoft API. The supplied run result was 1,397 passed / 1 failed / 2 skipped per
runtime, with successful per-run OU cleanup. GitHub job metadata independently
confirms both target steps failed and cleanup succeeded.

## Restore at acceptance, not unconditionally or after eager conversion

[Microsoft ADStoreCtx.Query](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADStoreCtx_Query.cs)
sets the limit, obtains the native result collection and constructs ADEntriesSet,
then restores the previous limit. There is no finally. The
[ADEntriesSet constructor](https://github.com/dotnet/runtime/blob/v9.0.0/src/libraries/System.DirectoryServices.AccountManagement/src/System/DirectoryServices/AccountManagement/AD/ADEntriesSet.cs)
does not advance rows or materialize principals. Those operations occur later.

Our low-level FindOne converts returned rows/schema eagerly. Restoring only after
it returns would leave 1 after a later conversion failure too. An internal,
per-call acceptance callback lets the high-level PrincipalSearcher restore its
limit after an accepted response, before eager controls/schema/row conversion.
The restoration closure is idempotent. Public DirectorySearcher.FindOne supplies
no callback and keeps its existing request-only one-result limit behavior.

| Stage | Retained PrincipalSearcher native SizeLimit |
| --- | --- |
| Preparation before temporary override fails | Existing caller state |
| Acquisition or query fails before acceptance | 1 |
| Accepted empty or successful result | Previous caller limit |
| Accepted response followed by schema, conversion or principal-attachment failure | Previous caller limit |
| Successful FindOne after an earlier failed FindOne | Restores the now-retained 1 unless caller reset it |
| FindAll alone fails | Existing caller limit; it installs no temporary override |

Protocols and context-scoped paths notify after accepted response/authority
validation. Neutral unpaged searches notify at an accepted terminal envelope,
after the remaining budget check. Neither schema conversion nor control parsing
can postpone restoration beyond that boundary. Leases/cursors retain their
existing ownership, invalidation and disposal paths.

Native ASQ notifies after its response status is accepted. An unsupported native
ASQ response never notifies: fallback first acquires the complete reference list,
then restores before per-DN enumeration. This describes the project's emulation
boundary, not an independent Microsoft ASQ timing result.

## Evidence limits and validation

The live test remains unchanged. Recording tests cover early query/acquisition
failure, exception identity/mapping, retained state through retries/FindAll,
explicit reset, empty success, accepted SizeLimitExceeded responses, schema/value
conversion/principal-attachment failure, neutral equivalents, unsupported-ASQ
fallback, exact request limits and complete resource cleanup. No live AD or
credentials are needed for these tests.

The initial ASQ fixture attempted to decode a response control through the SDK's
native BER utility, which could not load the host's missing 2.5 soname. That was a
fixture/dependency failure, not an AD result or production defect. The corrected
offline fallback case uses the actual unsupported-control LDAP result path and
needs no BER library. Native-ASQ successful-response decoding and the Windows
context-scoped branch remain source-reviewed, not newly executed here.

ADSI native query setup and a Protocols terminal response are not identical
boundaries. Malformed filters and native ASQ semantic-control errors may be
reported at different stages. This focused correction does not claim complete
ADSI setup/enumeration parity or change those error-timing contracts. No fresh
Microsoft/AD execution is performed by the offline checks; the corrected head
still needs the separately authorized Windows differential run.
