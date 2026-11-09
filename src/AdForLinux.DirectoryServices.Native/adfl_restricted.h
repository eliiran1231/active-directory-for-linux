#ifndef ADFL_RESTRICTED_H
#define ADFL_RESTRICTED_H
#include "adfl_native.h"
/* Only present in the administrator-admitted restricted private composition.
 * Caller must retain the verified deployment, verify the exact typed sealed
 * configuration, and serialize its lifetime with all native calls. Source paths
 * are recipes, not identity/reuse evidence. Generic APIs stay disabled. */
ADFL_API int adfl_restricted_authority_resolve_from(const adfl_native_profile *,
    const adfl_credential_source *, adfl_cancelled_fn, void *, adfl_authority **);
ADFL_API int adfl_restricted_authority_bind(adfl_authority *,
    const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_bound_session **);
#endif
