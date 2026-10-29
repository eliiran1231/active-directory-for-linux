#ifndef ADFL_NATIVE_INTERNAL_H
#define ADFL_NATIVE_INTERNAL_H
#include "adfl_native.h"
#include <ldap.h>
#include <stdatomic.h>
#include <stdint.h>

/* Native API dependencies injected into the SAME orchestration in offline tests.
 * Immutable table/state must outlive all authorities and sessions using it.
 * System implementations are private; this header is not the public bridge ABI. */
/* Normalized write recipe; terminal_type also selects the async libldap API. */
typedef struct {
    const char *dn;
    const adfl_modification *changes;
    size_t change_count;
    unsigned timeout_milliseconds;
    int terminal_type;
    const char *new_rdn, *new_superior;
    unsigned delete_old_rdn;
    const adfl_control *controls; size_t control_count;
} adfl_write_request;

typedef struct adfl_native_ops {
    int (*probe)(void *, adfl_native_capabilities *);
    int (*material_new)(void *, void **);
    int (*select_target)(void *, void *, const char *);
    int (*select_default)(void *, void *);
    int (*acquire_selected)(void *, void *);
    void *(*credential)(void *, void *);
    void (*material_free)(void *, void *);
    int (*ldap_create)(void *, const adfl_native_profile *, LDAP **);
    int (*set_credential)(void *, LDAP *, void *);
    int (*bind)(void *, LDAP *, LDAP_SASL_INTERACT_PROC *, void *);
    void (*ldap_close)(void *, LDAP *);
    int (*install_connection_guard)(void *, LDAP *, ldap_conncb *);
    int (*search_start)(void *, LDAP *, const adfl_search_request *, adfl_submitted_fn, void *, int *);
    int (*search_poll)(void *, LDAP *, int, unsigned, void **);
    int (*result_emit)(void *, LDAP *, void *, adfl_result_fn, void *);
    void (*result_free)(void *, void *);
    void (*abandon)(void *, LDAP *, int);
    uint64_t (*monotonic_ms)(void *);
    int (*page_start)(void *, LDAP *, const adfl_search_request *, unsigned, const adfl_bytes *, adfl_submitted_fn, void *, int *);
    int (*message_poll)(void *, LDAP *, int, unsigned, void **); /* native message type, 0 timeout, -1 error */
    int (*message_emit)(void *, LDAP *, void *, int, adfl_result_fn, void *);
    int (*page_cookie)(void *, LDAP *, void *, int *, adfl_bytes *); /* malloc-owned output */
    int (*write_start)(void *, LDAP *, const adfl_write_request *, adfl_submitted_fn, void *, int *, int *);

    int (*set_source)(void *, void *, const adfl_credential_source *);
    int (*check_source)(void *, void *, const adfl_credential_source *);
} adfl_native_ops;
struct adfl_authority {
    atomic_uint references;
    const adfl_native_ops *ops;
    void *state, *material;
    char *target;
};
struct adfl_bound_session {
    adfl_authority *authority;
    LDAP *ldap;
    ldap_conncb connection_guard;
    atomic_uint connection_count;
    atomic_int retired, busy;
    atomic_uint references;
    unsigned port;
    unsigned context_lifetime;
};
unsigned adfl_system_bound_lifetime(LDAP *);
int adfl_system_search_policy(LDAP *, unsigned);
int adfl_system_search_start(void *, LDAP *, const adfl_search_request *, adfl_submitted_fn, void *, int *);
int adfl_system_search_poll(void *, LDAP *, int, unsigned, void **);
int adfl_system_result_emit(void *, LDAP *, void *, adfl_result_fn, void *);
void adfl_system_result_free(void *, void *);
void adfl_system_abandon(void *, LDAP *, int);
uint64_t adfl_system_monotonic_ms(void *);
void adfl_session_retain(adfl_bound_session *);
void adfl_session_release(adfl_bound_session *);
int adfl_system_page_start(void *, LDAP *, const adfl_search_request *, unsigned, const adfl_bytes *, adfl_submitted_fn, void *, int *);
int adfl_system_message_poll(void *, LDAP *, int, unsigned, void **);
int adfl_system_message_emit(void *, LDAP *, void *, int, adfl_result_fn, void *);
int adfl_system_page_cookie(void *, LDAP *, void *, int *, adfl_bytes *);
int adfl_system_write_start(void *, LDAP *, const adfl_write_request *, adfl_submitted_fn, void *, int *, int *);
int adfl_controls_valid(const adfl_control *, size_t);
int adfl_controls_copy(const adfl_control *, size_t, adfl_control **);
void adfl_controls_free(adfl_control *, size_t);
int adfl_controls_build(const adfl_control *, size_t, LDAPControl *, LDAPControl ***);
void adfl_controls_release(LDAPControl **, size_t);
extern const adfl_native_ops adfl_system_ops;
int adfl_resolve_with(const adfl_native_ops *, void *, const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_authority **);
int adfl_source_validate(const adfl_credential_source *);
int adfl_source_matches(const adfl_credential_source *, const char *full_cache_name);
int adfl_resolve_from_with(const adfl_native_ops *, void *, const adfl_native_profile *, const adfl_credential_source *,
    adfl_cancelled_fn, void *, adfl_authority **);
int adfl_open_with(const adfl_native_ops *, void *, const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_bound_session **);
#endif
