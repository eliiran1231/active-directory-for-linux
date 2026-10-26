#ifndef ADFL_NATIVE_INTERNAL_H
#define ADFL_NATIVE_INTERNAL_H
#include "adfl_native.h"
#include <ldap.h>
#include <stdatomic.h>
#include <stdint.h>

/* Native API dependencies injected into the SAME orchestration in offline tests.
 * Immutable table/state must outlive all authorities and sessions using it.
 * System implementations are private; this header is not the public bridge ABI. */
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
    int (*search_start)(void *, LDAP *, const adfl_search_request *, int *);
    int (*search_poll)(void *, LDAP *, int, unsigned, void **);
    int (*result_emit)(void *, LDAP *, void *, adfl_result_fn, void *);
    void (*result_free)(void *, void *);
    void (*abandon)(void *, LDAP *, int);
    uint64_t (*monotonic_ms)(void *);
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
    unsigned port;
};
int adfl_system_search_start(void *, LDAP *, const adfl_search_request *, int *);
int adfl_system_search_poll(void *, LDAP *, int, unsigned, void **);
int adfl_system_result_emit(void *, LDAP *, void *, adfl_result_fn, void *);
void adfl_system_result_free(void *, void *);
void adfl_system_abandon(void *, LDAP *, int);
uint64_t adfl_system_monotonic_ms(void *);
extern const adfl_native_ops adfl_system_ops;
int adfl_resolve_with(const adfl_native_ops *, void *, const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_authority **);
int adfl_open_with(const adfl_native_ops *, void *, const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_bound_session **);
#endif
