#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

int adfl_system_search_start(void *state, LDAP *ld, const adfl_search_request *r, int *message_id) {
    (void)state;
    return ldap_search_ext(ld, r->base_dn, r->scope, r->filter, (char **)r->attributes,
        (int)r->types_only, NULL, NULL, NULL, (int)r->size_limit, message_id);
}
int adfl_system_search_poll(void *state, LDAP *ld, int message_id, unsigned milliseconds, void **out) {
    (void)state;
    struct timeval timeout = {(long)(milliseconds / 1000), (long)(milliseconds % 1000) * 1000};
    LDAPMessage *message = NULL;
    int rc = ldap_result(ld, message_id, LDAP_MSG_ALL, &timeout, &message);
    *out = message;
    if (rc <= 0) return rc;
    return rc == LDAP_RES_SEARCH_RESULT ? 1 : -1;
}
static int controls(adfl_result_fn emit, void *state, LDAPControl **values, int event) {
    for (size_t i = 0; values && values[i]; i++)
        if (emit(state, event, values[i]->ldctl_oid, values[i]->ldctl_value.bv_val,
                 values[i]->ldctl_value.bv_len, values[i]->ldctl_iscritical)) return 1;
    return 0;
}
static char *copy_name(const struct berval *value) {
    if (value->bv_len > SIZE_MAX - 1 || (value->bv_len &&
        (!value->bv_val || memchr(value->bv_val, 0, value->bv_len)))) return NULL;
    char *copy = malloc((size_t)value->bv_len + 1);
    if (!copy) return NULL;
    if (value->bv_len) memcpy(copy, value->bv_val, value->bv_len);
    copy[value->bv_len] = 0; return copy;
}
static int emit_entry(LDAP *ld, LDAPMessage *entry, adfl_result_fn emit, void *state) {
    char *dn = NULL, *name = NULL;
    BerElement *cursor = NULL;
    struct berval attribute = {0}, native_dn = {0}, *values = NULL;
    LDAPControl **entry_controls = NULL;
    int rc = 1;
    /* Use public LDAP decoders with explicit error returns. A NULL attribute
     * from the legacy iterator cannot distinguish exhaustion from decode failure. */
    if (ldap_get_dn_ber(ld, entry, &cursor, &native_dn) != LDAP_SUCCESS) goto done;
    dn = copy_name(&native_dn);
    if (!dn || emit(state, ADFL_ENTRY_BEGIN, dn, NULL, 0, 0)) goto done;
    for (;;) {
        if (ldap_get_attribute_ber(ld, entry, cursor, &attribute, &values) != LDAP_SUCCESS) goto done;
        if (!attribute.bv_val) break;
        name = copy_name(&attribute);
        if (!name || emit(state, ADFL_ATTRIBUTE_BEGIN, name, NULL, 0, 0)) goto done;
        for (size_t i = 0; values && values[i].bv_val; i++)
            if (emit(state, ADFL_ATTRIBUTE_VALUE, NULL, values[i].bv_val, values[i].bv_len, 0)) goto done;
        if (values) { ber_memfree(values); values = NULL; }
        if (emit(state, ADFL_ATTRIBUTE_END, NULL, NULL, 0, 0)) goto done;
        free(name); name = NULL;
    }
    if (ldap_get_entry_controls(ld, entry, &entry_controls) != LDAP_SUCCESS ||
        controls(emit, state, entry_controls, ADFL_ENTRY_CONTROL) ||
        emit(state, ADFL_ENTRY_END, NULL, NULL, 0, 0)) goto done;
    rc = 0;
done:
    if (entry_controls) ldap_controls_free(entry_controls);
    if (values) ber_memfree(values); // vector only; values borrow the LDAPMessage
    free(name);
    if (cursor) ber_free(cursor, 0);
    free(dn);
    return rc;
}
static int emit_reference(LDAP *ld, LDAPMessage *reference, adfl_result_fn emit, void *state) {
    char **urls = NULL; LDAPControl **reference_controls = NULL; int rc = 1;
    if (ldap_parse_reference(ld, reference, &urls, &reference_controls, 0) != LDAP_SUCCESS ||
        emit(state, ADFL_REFERENCE_BEGIN, NULL, NULL, 0, 0)) goto done;
    for (size_t i = 0; urls && urls[i]; i++)
        if (emit(state, ADFL_REFERENCE_URL, urls[i], NULL, 0, 0)) goto done;
    if (controls(emit, state, reference_controls, ADFL_REFERENCE_CONTROL) ||
        emit(state, ADFL_REFERENCE_END, NULL, NULL, 0, 0)) goto done;
    rc = 0;
done:
    if (urls) ldap_memvfree((void **)urls);
    if (reference_controls) ldap_controls_free(reference_controls);
    return rc;
}
int adfl_system_result_emit(void *unused, LDAP *ld, void *value, adfl_result_fn emit, void *state) {
    (void)unused;
    LDAPMessage *message = value;
    char *matched = NULL, *diagnostic = NULL, **referrals = NULL;
    LDAPControl **result_controls = NULL;
    int code = LDAP_OTHER, rc = 1;
    if (ldap_parse_result(ld, message, &code, &matched, &diagnostic, &referrals, &result_controls, 0) != LDAP_SUCCESS)
        goto done;
    for (LDAPMessage *entry = ldap_first_entry(ld, message); entry; entry = ldap_next_entry(ld, entry))
        if (emit_entry(ld, entry, emit, state)) goto done;
    for (LDAPMessage *reference = ldap_first_reference(ld, message); reference; reference = ldap_next_reference(ld, reference))
        if (emit_reference(ld, reference, emit, state)) goto done;
    if (emit(state, ADFL_RESULT_CODE, NULL, NULL, 0, code) ||
        emit(state, ADFL_MATCHED_DN, matched, NULL, 0, 0) ||
        emit(state, ADFL_DIAGNOSTIC, diagnostic, NULL, 0, 0)) goto done;
    for (size_t i = 0; referrals && referrals[i]; i++)
        if (emit(state, ADFL_REFERRAL_URL, referrals[i], NULL, 0, 0)) goto done;
    if (controls(emit, state, result_controls, ADFL_RESULT_CONTROL)) goto done;
    rc = 0;
done:
    if (matched) ldap_memfree(matched);
    if (diagnostic) ldap_memfree(diagnostic);
    if (referrals) ldap_memvfree((void **)referrals);
    if (result_controls) ldap_controls_free(result_controls);
    return rc;
}
void adfl_system_result_free(void *state, void *message) { (void)state; if (message) ldap_msgfree(message); }
void adfl_system_abandon(void *state, LDAP *ld, int id) { (void)state; (void)ldap_abandon_ext(ld, id, NULL, NULL); }
uint64_t adfl_system_monotonic_ms(void *state) {
    (void)state; struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return UINT64_MAX;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
