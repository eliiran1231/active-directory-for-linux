/* Isolated-lab shared bridge ONLY. Resolving/binding here performs real auth.
 * Never shipped as production libadfl_native: production probe remains closed. */
#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <sasl/sasl.h>
#include <pthread.h>
#include <string.h>

static adfl_native_ops lab_ops;
static pthread_once_t lab_once = PTHREAD_ONCE_INIT;
static int lab_probe(void *state, adfl_native_capabilities *caps) {
    int rc = adfl_system_ops.probe(state, caps);
    if (!rc && caps->reviewed_build) caps->authority_binding_enforced = 1;
    return rc;
}
static void initialize(void) {
    lab_ops = adfl_system_ops;
    lab_ops.probe = lab_probe; /* Sole dependency substitution; static lifetime. */
}
ADFL_API int adfl_lab_resolve_from(const adfl_native_profile *profile,
    const adfl_credential_source *source, adfl_cancelled_fn cancelled,
    void *state, adfl_authority **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    if (!profile || !source || !profile->host || strcmp(profile->host,"127.0.0.1") ||
        profile->port != 10389 || profile->tls || profile->referrals ||
        profile->signing != 1 || profile->sealing != 1 || source->kind != ADFL_SOURCE_FILE ||
        !source->absolute_path || (strcmp(source->absolute_path,"/run/adfl/client-a.ccache") &&
                                  strcmp(source->absolute_path,"/run/adfl/client-b.ccache")))
        return ADFL_INVALID;
    if (pthread_once(&lab_once, initialize)) return ADFL_UNSUPPORTED;
    return adfl_resolve_from_with(&lab_ops,NULL,profile,source,cancelled,state,out);
}
/* Caller retains session and serializes verification with disposal. The shared
 * session busy bit additionally prevents overlapping request/cursor operations.
 * Identity verification is part of lab startup and can block; worker supervision
 * supplies the external deadline. Never print identities, tokens or diagnostics. */
ADFL_API int adfl_lab_verify(adfl_bound_session *session, unsigned expected_identity) {
    static const char *const expected[] = {
        "dn:uid=client-a,dc=adfl,dc=test", "dn:uid=client-b,dc=adfl,dc=test"
    };
    if (!session || expected_identity < 1 || expected_identity > 2) return ADFL_INVALID;
    if (pthread_once(&lab_once, initialize)) return ADFL_UNSUPPORTED;
    if (!session->authority || session->authority->ops != &lab_ops ||
        strcmp(session->authority->target,"127.0.0.1") || session->port != 10389)
        return ADFL_INVALID;
    if (atomic_load(&session->retired)) return ADFL_SESSION_RETIRED;
    int free = 0;
    if (!atomic_compare_exchange_strong(&session->busy,&free,1)) return ADFL_BUSY;
    int status = ADFL_BIND_FAILED;
    sasl_ssf_t ssf = 0;
    struct berval *identity = NULL;
    LDAPControl *empty[] = {NULL};
    if (ldap_get_option(session->ldap,LDAP_OPT_X_SASL_SSF,&ssf) == LDAP_OPT_SUCCESS && ssf >= 56) {
        int rc = ldap_whoami_s(session->ldap,&identity,empty,empty);
        const char *wanted = expected[expected_identity-1];
        if (rc == LDAP_SUCCESS && identity && identity->bv_val &&
            identity->bv_len == strlen(wanted) && !memcmp(identity->bv_val,wanted,identity->bv_len))
            status = ADFL_OK;
    }
    if (identity) ber_bvfree(identity);
    if (status != ADFL_OK) atomic_store(&session->retired,1);
    atomic_store(&session->busy,0);
    return status;
}
