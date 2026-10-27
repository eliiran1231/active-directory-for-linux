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

/* Transfer a source reference, never credential bytes or a captured identity.
 * Only absolute FILE paths and DIR collections can cross this worker seam. */
typedef struct { unsigned kind; const char *absolute_path; } adfl_credential_source;
enum adfl_source_kind { ADFL_SOURCE_FILE = 1, ADFL_SOURCE_DIR = 2 };

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
    int request_transport;            /* request adapters implemented; not an enablement gate */
    int compatible_session_reuse;     /* always 0: no mutable-cache proof */
} adfl_native_capabilities;

typedef struct { const void *data; size_t length; } adfl_bytes;
typedef struct {
    const char *oid;
    unsigned critical;
    adfl_bytes value;
    unsigned has_value; /* distinguishes omitted value from present empty bytes */
} adfl_control;

typedef struct {
    const char *base_dn, *filter;
    const char *const *attributes;    /* NULL-terminated; NULL = all attributes */
    int scope;                       /* 0 base, 1 one-level, 2 subtree */
    unsigned timeout_milliseconds, size_limit, types_only;
    const adfl_control *controls;
    size_t control_count;
    unsigned server_time_limit_seconds; /* LDAP wire limit, separate from client budget */
} adfl_search_request;

/* Control events use number bit0=critical, bit1=value present. */
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

/* Streaming callbacks are synchronous and borrowed per read. Earlier accepted
 * entry/reference messages may already have been published when a later read fails.
 * The caller must serialize read/next_page/close on each cursor. Native retention
 * permits closing the original session owner while its cursor remains alive.
 * Budgets bound pre-submit checks and result polling; OpenLDAP async socket writes
 * do not yet have a proven hard send deadline (NETWORK_TIMEOUT is connect-only). */
typedef struct adfl_search_cursor adfl_search_cursor;
enum adfl_cursor_kind { ADFL_CURSOR_ENTRY = 1, ADFL_CURSOR_REFERENCE = 2, ADFL_CURSOR_PAGE_END = 3 };
ADFL_API int adfl_cursor_open(adfl_bound_session *, const adfl_search_request *, unsigned page_size,
    adfl_cancelled_fn, void *, adfl_search_cursor **);
ADFL_API int adfl_cursor_read(adfl_search_cursor *, unsigned remaining_milliseconds,
    adfl_cancelled_fn, void *, adfl_result_fn, void *, int *kind, int *has_more);
/* Compatibility entry point: server limit must equal the initial request.
 * has_more describes the server cookie even at the total entry limit; callers
 * must drain PAGE_END then close, never start a zero-size continuation. */
ADFL_API int adfl_cursor_next_page_with_limit(adfl_search_cursor *, unsigned remaining_milliseconds,
    unsigned server_time_limit_seconds, adfl_cancelled_fn, void *);
ADFL_API int adfl_cursor_next_page(adfl_search_cursor *, unsigned remaining_milliseconds,
    adfl_cancelled_fn, void *);
ADFL_API void adfl_cursor_close(adfl_search_cursor **);

typedef struct {
    int operation;                    /* 0 add, 1 delete, 2 replace */
    const char *attribute;
    const adfl_bytes *values;
    size_t value_count;
} adfl_modification;
typedef struct {
    const char *dn;
    const adfl_modification *changes;
    size_t change_count;
    unsigned timeout_milliseconds;
    const adfl_control *controls;
    size_t control_count;
} adfl_modify_request;
/* Request controls are server-side. Values are borrowed for the call. */
typedef struct {
    const char *dn;
    const adfl_modification *attributes; /* operation must be 0 (add) */
    size_t attribute_count;
    unsigned timeout_milliseconds;
    const adfl_control *controls;
    size_t control_count;
} adfl_add_request;
typedef struct {
    const char *dn; unsigned timeout_milliseconds;
    const adfl_control *controls; size_t control_count;
} adfl_delete_request;
typedef struct {
    const char *dn, *new_rdn, *new_superior; /* NULL superior preserves current parent */
    unsigned delete_old_rdn, timeout_milliseconds;
    const adfl_control *controls; size_t control_count;
} adfl_modify_dn_request;
enum adfl_submission { ADFL_NOT_SENT = 0, ADFL_OUTCOME_UNKNOWN = 1, ADFL_COMPLETED = 2 };
/* Invoked synchronously immediately before native dispatch, after allocation.
 * Nonzero refuses dispatch. Must not throw across the unmanaged boundary. */
typedef int (*adfl_submitted_fn)(void *);
ADFL_API int adfl_session_modify(adfl_bound_session *, const adfl_modify_request *,
    adfl_cancelled_fn, void *, adfl_submitted_fn, void *, adfl_result_fn, void *, int *disposition);

ADFL_API int adfl_session_add(adfl_bound_session *, const adfl_add_request *,
    adfl_cancelled_fn, void *, adfl_submitted_fn, void *, adfl_result_fn, void *, int *disposition);
ADFL_API int adfl_session_delete(adfl_bound_session *, const adfl_delete_request *,
    adfl_cancelled_fn, void *, adfl_submitted_fn, void *, adfl_result_fn, void *, int *disposition);
ADFL_API int adfl_session_modify_dn(adfl_bound_session *, const adfl_modify_dn_request *,
    adfl_cancelled_fn, void *, adfl_submitted_fn, void *, adfl_result_fn, void *, int *disposition);

/* Must equal 4 before passing any request/profile structure across the ABI. */
ADFL_API unsigned adfl_native_abi_version(void);

/* Reads library version metadata only; no credential/cache/network operations. */
ADFL_API int adfl_native_probe(adfl_native_capabilities *out);
/* Explicit credential operations: NOT executed by the offline demonstration.
 * Acquisition reads the caller's configured cache collection when actually used.
 * No passwords, default client keytab, environment mutation or login are used. */
ADFL_API int adfl_authority_resolve(const adfl_native_profile *, adfl_cancelled_fn, void *, adfl_authority **);
ADFL_API int adfl_authority_resolve_from(const adfl_native_profile *, const adfl_credential_source *,
    adfl_cancelled_fn, void *, adfl_authority **);
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
