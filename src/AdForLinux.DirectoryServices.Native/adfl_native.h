#ifndef ADFL_NATIVE_H
#define ADFL_NATIVE_H

/* Experimental Linux binding/search seam. No raw LDAP handle is exposed.
 * Real resolution is gated off before credentials; every logical operation must resolve afresh. */
#include <stddef.h>
#if defined(__GNUC__)
#define ADFL_API __attribute__((visibility("default")))
#else
#define ADFL_API
#endif
#ifdef __cplusplus
extern "C" {
#endif

typedef struct adfl_authority adfl_authority;
typedef struct adfl_bound_session adfl_bound_session;
typedef int (*adfl_cancelled_fn)(void *state);
typedef struct {
    const char *host;                 /* exact DNS hostname, not URI or discovery */
    unsigned port;
    unsigned timeout_seconds;
    unsigned referrals;              /* only None (0) supported; never coerced */
    unsigned tls;                    /* unsupported until channel binding reviewed */
    unsigned signing;
    unsigned sealing;
} adfl_native_profile;

enum adfl_status {
    ADFL_OK = 0, ADFL_UNSUPPORTED = 1, ADFL_INVALID = 2,
    ADFL_CANCELLED = 3, ADFL_RESOLVE_FAILED = 4, ADFL_BIND_FAILED = 5,
    ADFL_TARGET_MISMATCH = 6, ADFL_NO_MEMORY = 7,
    /* Internal resolution results: absence of selection differs from no tickets
     * for an authoritatively selected principal. Only the first may fall back. */
    ADFL_NO_SELECTION = 8, ADFL_SELECTED_CACHE_MISSING = 9,
    ADFL_SESSION_RETIRED = 10, ADFL_BUSY = 11, ADFL_REQUEST_FAILED = 12,
    ADFL_TIMEOUT = 13, ADFL_RESULT_REJECTED = 14
};

typedef struct {
    int openldap_version;
    int cyrus_major, cyrus_minor, cyrus_step;
    int reviewed_build;
    int authority_binding_enforced;   /* pre-auth proof; real backend remains 0 */
    int request_transport;            /* search dispatch implemented; not an enablement gate */
    int compatible_session_reuse;     /* always 0: no mutable-cache proof */
} adfl_native_capabilities;

typedef struct {
    const char *base_dn, *filter;
    const char *const *attributes;    /* NULL-terminated; NULL = all attributes */
    int scope;                       /* 0 base, 1 one-level, 2 subtree */
    unsigned timeout_milliseconds, size_limit, types_only;
} adfl_search_request;

enum adfl_result_event {
    ADFL_ENTRY_BEGIN = 1, ADFL_ATTRIBUTE_BEGIN, ADFL_ATTRIBUTE_VALUE, ADFL_ATTRIBUTE_END,
    ADFL_ENTRY_CONTROL, ADFL_ENTRY_END, ADFL_REFERENCE_BEGIN, ADFL_REFERENCE_URL,
    ADFL_REFERENCE_CONTROL, ADFL_REFERENCE_END, ADFL_RESULT_CODE, ADFL_MATCHED_DN,
    ADFL_DIAGNOSTIC, ADFL_REFERRAL_URL, ADFL_RESULT_CONTROL
};
/* All pointers are borrowed only during callback. Copy before returning. A nonzero
 * return aborts conversion; no partial result is published and session retires. */
typedef int (*adfl_result_fn)(void *state, int event, const char *name,
                              const void *bytes, size_t length, int number);
ADFL_API int adfl_session_search(adfl_bound_session *, const adfl_search_request *,
    adfl_cancelled_fn, void *, adfl_result_fn, void *);

/* Reads library version metadata only; no credential/cache/network operations. */
ADFL_API int adfl_native_probe(adfl_native_capabilities *out);
/* Explicit credential operations: NOT executed by the offline demonstration.
 * Acquisition reads the caller's configured cache collection when actually used.
 * No passwords, default client keytab, environment mutation or login are used. */
ADFL_API int adfl_authority_resolve(const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_authority **);
ADFL_API int adfl_authority_bind(adfl_authority *, const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_bound_session **);
ADFL_API int adfl_operation_open(const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_bound_session **);
/* Each successful bind retains its authority. LDAP/SASL closes before GSS release.
 * Callers exclusively own each pointer variable; close clears it, so repeats are safe. */
ADFL_API void adfl_authority_close(adfl_authority **);
ADFL_API void adfl_session_close(adfl_bound_session **);

#ifdef __cplusplus
}
#endif
#endif
