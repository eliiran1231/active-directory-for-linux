/* Dedicated private composition entry points. Built only by the pinned restricted
 * recipe; generic adfl_authority_resolve/open and system probe remain disabled.
 * The admitted worker must verify the administrator-owned artifact receipt and
 * exact typed configuration bytes before invoking this source-only API. */
#define _GNU_SOURCE
#include "adfl_native_internal.h"
#include "adfl_restricted.h"
#include <sasl/sasl.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static adfl_native_ops restricted_ops;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static int composition_probe(void *state, adfl_native_capabilities *caps) {
    int rc = adfl_system_ops.probe(state,caps);
    /* This table exists only in the artifact whose recipe owns private static
     * LDAP/Cyrus/MIT, guarded GSSAPI, and unavailable runtime module loading.
     * Version metadata remains a compatibility check, not provenance proof. */
    if (!rc && caps->reviewed_build) caps->authority_binding_enforced = 1;
    caps->compatible_session_reuse = 0;
    return rc;
}
static void initialize(void) { restricted_ops = adfl_system_ops; restricted_ops.probe = composition_probe; }
static int profile_supported(const adfl_native_profile *p) {
    return p && p->host && p->port > 0 && p->port <= 65535 &&
        p->timeout_seconds >= 1 && p->timeout_seconds <= 3600 &&
        !p->tls && !p->referrals && p->signing == 1 && p->sealing == 1;
}
static int sealed_profile(int descriptor, int empty) {
    int owned = fcntl(descriptor,F_DUPFD_CLOEXEC,6);
    if (owned < 0) return 0;
    int seals = fcntl(owned,F_GET_SEALS);
    struct stat st;
    int required = F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
    int valid = seals >= 0 && (seals & required) == required && !fstat(owned,&st) &&
        S_ISREG(st.st_mode) && (empty ? st.st_size == 0 : st.st_size > 0 && st.st_size <= 32768);
    close(owned); return valid;
}
static int inherited_policy(void) {
    const char *config = getenv("KRB5_CONFIG"), *mechs = getenv("GSS_MECH_CONFIG");
    const char *noinit = getenv("LDAPNOINIT");
    return noinit && !strcmp(noinit,"1") && config && !strcmp(config,"/proc/self/fd/4") &&
        mechs && !strcmp(mechs,"/proc/self/fd/5") && sealed_profile(4,0) && sealed_profile(5,1);
}
ADFL_API int adfl_restricted_authority_resolve_from(const adfl_native_profile *p,
    const adfl_credential_source *source, adfl_cancelled_fn cancelled, void *state, adfl_authority **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    if (!profile_supported(p) || !source || source->kind != ADFL_SOURCE_FILE || adfl_source_validate(source))
        return ADFL_UNSUPPORTED;
    if (!inherited_policy() || pthread_once(&once,initialize)) return ADFL_UNSUPPORTED;
    return adfl_resolve_from_with(&restricted_ops,NULL,p,source,cancelled,state,out);
}
ADFL_API int adfl_restricted_authority_bind(adfl_authority *authority,
    const adfl_native_profile *p, adfl_cancelled_fn cancelled, void *state, adfl_bound_session **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    if (!profile_supported(p) || !inherited_policy() || pthread_once(&once,initialize) ||
        !authority || authority->ops != &restricted_ops) return ADFL_UNSUPPORTED;
    adfl_bound_session *session = NULL;
    int rc = adfl_authority_bind(authority,p,cancelled,state,&session);
    if (rc) return rc;
    /* OpenLDAP writes ber_len_t here, not Cyrus sasl_ssf_t. */
    ber_len_t ssf = 0;
    if (ldap_get_option(session->ldap,LDAP_OPT_X_SASL_SSF,&ssf) != LDAP_OPT_SUCCESS || ssf < 56) {
        adfl_session_close(&session); return ADFL_BIND_FAILED;
    }
    if (cancelled && cancelled(state)) { adfl_session_close(&session); return ADFL_CANCELLED; }
    *out = session; return ADFL_OK;
}
