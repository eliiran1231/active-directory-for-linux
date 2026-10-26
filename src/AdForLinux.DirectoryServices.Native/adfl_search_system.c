#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

int adfl_system_search_start(void *state, LDAP *ld, const adfl_search_request *r,
    adfl_submitted_fn ready, void *ready_state, int *message_id) {
    (void)state; LDAPControl **server = NULL; LDAPControl *client[] = {NULL};
    int rc = adfl_controls_build(r->controls, r->control_count, NULL, &server);
    if (rc != LDAP_SUCCESS) return rc;
    if (ready(ready_state)) rc = LDAP_USER_CANCELLED;
    else rc = ldap_search_ext(ld, r->base_dn, r->scope, r->filter, (char **)r->attributes,
        (int)r->types_only, server, client, NULL, (int)r->size_limit, message_id);
    adfl_controls_release(server, r->control_count); return rc;
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
                 values[i]->ldctl_value.bv_len, (values[i]->ldctl_iscritical ? 1 : 0) | (values[i]->ldctl_value.bv_val ? 2 : 0))) return 1;
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

int adfl_system_page_start(void *state, LDAP *ld, const adfl_search_request *r,
                           unsigned page_size, const adfl_bytes *cookie, adfl_submitted_fn ready, void *ready_state, int *message_id) {
    /* This bounds connection setup only, not a proven hard socket-write deadline. */
    struct timeval budget = {(long)(r->timeout_milliseconds / 1000), (long)(r->timeout_milliseconds % 1000) * 1000};
    if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &budget) != LDAP_OPT_SUCCESS) return LDAP_LOCAL_ERROR;
    if (!page_size) return adfl_system_search_start(state, ld, r, ready, ready_state, message_id);
    LDAPControl *page = NULL; LDAPControl *client[] = {NULL};
    struct berval value = {cookie->length, (char *)cookie->data};
    int rc = ldap_create_page_control(ld, (ber_int_t)page_size, &value, 1, &page);
    if (rc != LDAP_SUCCESS) return rc;
    LDAPControl **controls = NULL;
    rc = adfl_controls_build(r->controls, r->control_count, page, &controls);
    if (rc != LDAP_SUCCESS) { ldap_control_free(page); return rc; }
    if (ready(ready_state)) rc = LDAP_USER_CANCELLED;
    else rc = ldap_search_ext(ld, r->base_dn, r->scope, r->filter, (char **)r->attributes,
        (int)r->types_only, controls, client, NULL, (int)r->size_limit, message_id);
    adfl_controls_release(controls, r->control_count); ldap_control_free(page); return rc;
}
int adfl_system_message_poll(void *state, LDAP *ld, int message_id, unsigned milliseconds, void **out) {
    (void)state;
    struct timeval timeout = {(long)(milliseconds / 1000), (long)(milliseconds % 1000) * 1000};
    LDAPMessage *message = NULL;
    int rc = ldap_result(ld, message_id, LDAP_MSG_ONE, &timeout, &message);
    *out = message;
    return rc;
}
int adfl_system_message_emit(void *unused, LDAP *ld, void *message, int kind, adfl_result_fn emit, void *state) {
    if (!message || ldap_msgtype(message) != kind) return 1;
    switch (kind) {
        case LDAP_RES_SEARCH_ENTRY: return emit_entry(ld, message, emit, state);
        case LDAP_RES_SEARCH_REFERENCE: return emit_reference(ld, message, emit, state);
        case LDAP_RES_SEARCH_RESULT:
        case LDAP_RES_ADD:
        case LDAP_RES_DELETE:
        case LDAP_RES_MODDN:
        case LDAP_RES_MODIFY: return adfl_system_result_emit(unused, ld, message, emit, state);
        default: return 1;
    }
}
int adfl_system_page_cookie(void *unused, LDAP *ld, void *message, int *code, adfl_bytes *out) {
    (void)unused;
    LDAPControl **controls = NULL, *page = NULL;
    struct berval cookie = {0}; ber_int_t count = 0;
    int rc = 1;
    *out = (adfl_bytes){0};
    if (ldap_parse_result(ld, message, code, NULL, NULL, NULL, &controls, 0) != LDAP_SUCCESS) goto done;
    for (size_t i = 0; controls && controls[i]; i++) {
        if (!controls[i]->ldctl_oid) goto done;
        if (!strcmp(controls[i]->ldctl_oid, LDAP_CONTROL_PAGEDRESULTS)) {
            if (page) goto done;
            page = controls[i];
        }
    }
    /* An LDAP error response may legitimately omit the page response control. */
    if (!page) { rc = *code == LDAP_SUCCESS ? 1 : 0; goto done; }
    if (ldap_parse_pageresponse_control(ld, page, &count, &cookie) != LDAP_SUCCESS || count < 0 ||
        (cookie.bv_len && !cookie.bv_val)) goto done;
    if (*code == LDAP_SUCCESS && cookie.bv_len) {
        void *copy = malloc(cookie.bv_len);
        if (!copy) goto done;
        memcpy(copy, cookie.bv_val, cookie.bv_len);
        out->data = copy; out->length = cookie.bv_len;
    }
    rc = 0;
done:
    if (cookie.bv_val) ber_memfree(cookie.bv_val);
    if (controls) ldap_controls_free(controls);
    return rc;
}
int adfl_system_write_start(void *unused, LDAP *ld, const adfl_write_request *r,
                             adfl_submitted_fn submitted, void *submit_state, int *disposition, int *message_id) {
    (void)unused; LDAPControl *client[] = {NULL};
    /* This bounds connection setup only, not a proven hard socket-write deadline. */
    struct timeval budget = {(long)(r->timeout_milliseconds / 1000), (long)(r->timeout_milliseconds % 1000) * 1000};
    if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &budget) != LDAP_OPT_SUCCESS) return LDAP_LOCAL_ERROR;
    LDAPMod **mods = calloc(r->change_count + 1, sizeof(*mods));
    if (!mods) return LDAP_NO_MEMORY;
    LDAPControl **server = NULL;
    int rc = adfl_controls_build(r->controls, r->control_count, NULL, &server);
    if (rc != LDAP_SUCCESS) goto done;
    rc = LDAP_NO_MEMORY;
    for (size_t i = 0; i < r->change_count; i++) {
        mods[i] = calloc(1, sizeof(*mods[i]));
        if (!mods[i]) goto done;
        mods[i]->mod_type = (char *)r->changes[i].attribute;
        mods[i]->mod_op = r->changes[i].operation | LDAP_MOD_BVALUES;
        mods[i]->mod_bvalues = calloc(r->changes[i].value_count + 1, sizeof(struct berval *));
        if (!mods[i]->mod_bvalues) goto done;
        for (size_t j = 0; j < r->changes[i].value_count; j++) {
            struct berval *value = malloc(sizeof(*value));
            if (!value) goto done;
            /* OpenLDAP rejects NULL bv_val even for an empty binary value. */
            static char empty_value;
            *value = (struct berval){r->changes[i].values[j].length,
                r->changes[i].values[j].length ? (char *)r->changes[i].values[j].data : &empty_value};
            /* A zero-length value still has a descriptor, distinct from no values. */
            mods[i]->mod_bvalues[j] = value;
        }
    }
    if (submitted(submit_state)) { rc = LDAP_USER_CANCELLED; goto done; }
    *disposition = ADFL_OUTCOME_UNKNOWN;
    switch (r->terminal_type) {
        case LDAP_RES_MODIFY: rc = ldap_modify_ext(ld, r->dn, mods, server, client, message_id); break;
        case LDAP_RES_ADD: rc = ldap_add_ext(ld, r->dn, mods, server, client, message_id); break;
        case LDAP_RES_DELETE: rc = ldap_delete_ext(ld, r->dn, server, client, message_id); break;
        case LDAP_RES_MODDN: rc = ldap_rename(ld, r->dn, r->new_rdn, r->new_superior,
            (int)r->delete_old_rdn, server, client, message_id); break;
        default: rc = LDAP_PARAM_ERROR; break;
    }
done:
    for (size_t i = 0; i < r->change_count && mods[i]; i++) {
        if (mods[i]->mod_bvalues) {
            for (size_t j = 0; mods[i]->mod_bvalues[j]; j++) free(mods[i]->mod_bvalues[j]);
            free(mods[i]->mod_bvalues);
        }
        free(mods[i]);
    }
    adfl_controls_release(server, r->control_count); free(mods); return rc;
}
