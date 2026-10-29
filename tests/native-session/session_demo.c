#include "adfl_native_internal.h"
#include <sasl/sasl.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Recording native dependencies, not a second pool/binder implementation.
 * Tests call adfl_open_with/adfl_resolve_with/adfl_authority_bind from the real
 * adapter. NO system resolution, credential acquisition or LDAP bind is called. */
struct fixture {
    atomic_int created, selected, defaults, acquired, freed, connections, closed, installs, binds;
    atomic_int identity, expected_identity, cancelled, fail_bind_at;
    atomic_int sends, wire_sent, polls, results, results_freed, abandons, clock;
    unsigned expected_server_limit, expected_size_limit, last_page_size;
    int always_more, excess_entry;
    int reconnect_on_send, disconnect_on_poll, pending_forever, cancel_on_send, partial_result;
    int late_result, slow_conversion, root_reply, wrong_write_tag, expect_controls, cancel_prepare;
    atomic_int source_sets, source_checks; unsigned source_kind; char source_path[4097];
    const char *selected_source_override; int cancel_after_source_check;
    int block_phase; /* test-only child process: 1read, 2pre-submit, 3post-submit, 4close */
    int bad_cookie, unexpected_message, modify_send_failure, slow_prepare, reject_submit;
    atomic_int page_sends, modify_sends, submissions, submission_receipts;
    int selection_result, acquire_failure, create_failure, install_failure, probe_rejected, material_failure, untrusted_plugin;
    int cancel_after_select, cancel_after_create, cancel_at_callback;
    int bind_failure, omit_callback, wrong_prompt, cancel_after_bind;
};
struct fake_material { struct fixture *owner; int identity; char target[254]; char cache_name[4110]; int source_checked; atomic_int sessions; };
struct fake_ldap { struct fixture *owner; struct fake_material *credential; char target[254]; char attribute[64]; char base_dn[256]; const adfl_control *controls; size_t control_count; unsigned port; int page, stream_index, modify; ldap_conncb *guard; };
static const adfl_native_profile profile = {"directory.invalid", 389, 5, 0, 0, 1, 1};
static int probe(void *state, adfl_native_capabilities *caps) {
    memset(caps, 0, sizeof(*caps)); caps->reviewed_build = !((struct fixture *)state)->probe_rejected;
    caps->authority_binding_enforced = !((struct fixture *)state)->untrusted_plugin; return ADFL_OK;
}
static int material_new(void *state, void **out) {
    struct fixture *f = state;
    struct fake_material *m = calloc(1, sizeof(*m)); assert(m);
    m->owner = f; atomic_init(&m->sessions, 0); *out = m; atomic_fetch_add(&f->created, 1); return f->material_failure ? ADFL_NO_MEMORY : ADFL_OK;
}
static int set_source(void *state, void *value, const adfl_credential_source *source) {
    struct fixture *f = state; struct fake_material *m = value;
    assert(adfl_source_validate(source) == ADFL_OK);
    f->source_kind = source->kind; strcpy(f->source_path, source->absolute_path);
    int count = snprintf(m->cache_name, sizeof(m->cache_name), "%s%s%s",
        source->kind == ADFL_SOURCE_FILE ? "FILE:" : "DIR::", source->absolute_path,
        source->kind == ADFL_SOURCE_FILE ? "" : "/synthetic-cache");
    assert(count > 0 && (size_t)count < sizeof(m->cache_name));
    atomic_fetch_add(&f->source_sets, 1); return ADFL_OK;
}
static int check_source(void *state, void *value, const adfl_credential_source *source) {
    struct fixture *f = state; struct fake_material *m = value;
    atomic_fetch_add(&f->source_checks, 1);
    if (f->cancel_after_source_check) atomic_store(&f->cancelled, 1);
    m->source_checked = adfl_source_matches(source, f->selected_source_override ? f->selected_source_override : m->cache_name);
    return m->source_checked ? ADFL_OK : ADFL_RESOLVE_FAILED;
}
static int select_target(void *state, void *value, const char *target) {
    struct fixture *f = state; struct fake_material *m = value;
    assert(!strcmp(target, profile.host) || !strcmp(target, "other.invalid"));
    strcpy(m->target, target);
    m->identity = atomic_load(&f->identity); atomic_fetch_add(&f->selected, 1);
    if (f->cancel_after_select) atomic_store(&f->cancelled, 1);
    return f->selection_result;
}
static int select_default(void *state, void *value) {
    (void)value; atomic_fetch_add(&((struct fixture *)state)->defaults, 1); return ADFL_OK;
}
static int acquire_selected(void *state, void *value) {
    struct fake_material *m = value; struct fixture *f = state;
    assert(!m->cache_name[0] || m->source_checked);
    atomic_fetch_add(&f->acquired, 1);
    return f->acquire_failure ? ADFL_RESOLVE_FAILED : ADFL_OK;
}
static void *credential(void *state, void *value) { (void)state; return value; }
static void material_free(void *state, void *value) {
    struct fixture *f = state; struct fake_material *m = value;
    if (m) { assert(atomic_load(&m->sessions) == 0); atomic_fetch_add(&f->freed, 1); free(m); }
}
static int create_session(void *state, const adfl_native_profile *p, LDAP **out) {
    struct fixture *f = state; assert(!p->referrals && !p->tls && p->sealing);
    struct fake_ldap *ld = calloc(1, sizeof(*ld)); assert(ld);
    ld->owner = f; strcpy(ld->target, p->host); ld->port = p->port; *out = (LDAP *)ld; atomic_fetch_add(&f->connections, 1);
    if (f->cancel_after_create) atomic_store(&f->cancelled, 1);
    return f->create_failure ? ADFL_BIND_FAILED : ADFL_OK;
}
static int set_credential(void *state, LDAP *value, void *credential_value) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    struct fake_material *m = credential_value;
    assert(m && m->owner == f); /* direct handle, not a pointer-to-handle */
    assert(ld->credential == NULL);
    if (f->install_failure) return LDAP_OPT_ERROR;
    ld->credential = m; atomic_fetch_add(&m->sessions, 1); atomic_fetch_add(&f->installs, 1);
    return LDAP_OPT_SUCCESS;
}
static int bind_session(void *state, LDAP *value, LDAP_SASL_INTERACT_PROC *callback, void *defaults) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    int ordinal = atomic_fetch_add(&f->binds, 1) + 1;
    assert(ld->guard);
    LDAPURLDesc server = {0}; server.lud_host = ld->target; server.lud_scheme = "ldap"; server.lud_port = (int)ld->port;
    int connected = ld->guard->lc_add(value, (Sockbuf *)ld, &server, NULL, ld->guard);
    if (connected) return connected;
    if (f->omit_callback) return LDAP_SUCCESS;
    sasl_interact_t prompts[2] = {{0}};
    prompts[0].id = f->wrong_prompt ? SASL_CB_PASS : SASL_CB_USER;
    if (f->cancel_at_callback) atomic_store(&f->cancelled, 1);
    int rc = callback(value, LDAP_SASL_QUIET, defaults, prompts);
    if (rc) return rc;
    assert(ld->credential && prompts[0].result && prompts[0].len == 0);
    assert(ld->credential->identity == atomic_load(&f->expected_identity));
    assert(!strcmp(ld->credential->target, ld->target));
    assert(!strcmp(prompts[0].result, ""));
    if (f->cancel_after_bind) atomic_store(&f->cancelled, 1);
    return f->bind_failure || atomic_load(&f->fail_bind_at) == ordinal ? LDAP_INVALID_CREDENTIALS : LDAP_SUCCESS;
}
static void block_dependency(struct fixture *f, int phase) {
    if (f->block_phase == phase) for (;;) pause();
}
static void ldap_close(void *state, LDAP *value) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    if (!ld) return;
    block_dependency(f, 4);
    if (ld->guard) ld->guard->lc_del(value, (Sockbuf *)ld, ld->guard);
    if (ld->credential) atomic_fetch_sub(&ld->credential->sessions, 1);
    atomic_fetch_add(&f->closed, 1); free(ld);
}
static int cancelled(void *state) { return atomic_load(&((struct fixture *)state)->cancelled); }
static int install_guard(void *state, LDAP *value, ldap_conncb *guard) {
    (void)state; ((struct fake_ldap *)value)->guard = guard; return LDAP_OPT_SUCCESS;
}
static void record_controls(struct fixture *f, struct fake_ldap *ld, const adfl_control *source, size_t count) {
    LDAPControl **native = NULL;
    assert(adfl_controls_build(source, count, NULL, &native) == LDAP_SUCCESS);
    assert(native && !native[count]); /* explicitly empty rather than inherited defaults */
    for (size_t i = 0; i < count; i++) {
        assert(!strcmp(native[i]->ldctl_oid, source[i].oid));
        assert((unsigned)native[i]->ldctl_iscritical == source[i].critical);
        assert((native[i]->ldctl_value.bv_val != NULL) == (source[i].has_value != 0));
        assert(native[i]->ldctl_value.bv_len == source[i].value.length);
        if (source[i].value.length) assert(!memcmp(native[i]->ldctl_value.bv_val, source[i].value.data, source[i].value.length));
    }
    adfl_controls_release(native, count);
    if (f->expect_controls) {
        const unsigned char bytes[] = {0, 255, 65};
        assert(count == 3 && !strcmp(source[0].oid, "1.2.3") && !strcmp(source[1].oid, "1.2.3"));
        assert(source[0].critical && source[0].has_value && source[0].value.length == 3);
        assert(!memcmp(source[0].value.data, bytes, sizeof(bytes)));
        assert(source[1].has_value && !source[1].value.length && !source[2].has_value);
    }
    ld->controls = source; ld->control_count = count;
}
static int echo_controls(struct fake_ldap *ld, adfl_result_fn emit, void *out) {
    for (size_t i = 0; i < ld->control_count; i++) {
        const adfl_control *c = &ld->controls[i];
        if (emit(out, ADFL_RESULT_CONTROL, c->oid, c->value.data, c->value.length,
            (int)(c->critical | (c->has_value << 1)))) return 1;
    }
    return 0;
}
static int search_start(void *state, LDAP *value, const adfl_search_request *request, adfl_submitted_fn ready, void *ready_state, int *id) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    block_dependency(f, 1);
    assert(request->server_time_limit_seconds == f->expected_server_limit);
    assert(request->size_limit == f->expected_size_limit);
    record_controls(f, ld, request->controls, request->control_count);
    assert(request->scope >= 0 && request->scope <= 2 && !strcmp(request->filter, "(objectClass=*)"));
    assert(strlen(request->base_dn) < sizeof(ld->base_dn));
    strcpy(ld->base_dn, request->base_dn);
    if (f->root_reply) {
        assert(request->scope == 0);
        assert(request->attributes && request->attributes[0] && strlen(request->attributes[0]) < sizeof(ld->attribute));
        strcpy(ld->attribute, request->attributes[0]);
        if (!strcmp(ld->attribute, "*")) {
            const unsigned char prefix[] = {0x30, 0x03, 0x02, 0x01};
            int found = 0;
            for (size_t i = 0; i < request->control_count; i++) {
                const adfl_control *c = &request->controls[i];
                if (strcmp(c->oid, "1.2.840.113556.1.4.801")) continue;
                assert(c->has_value && c->value.length == 5 && !memcmp(c->value.data, prefix, sizeof(prefix)));
                found++;
            }
            assert(found == 1); /* public default-property security policy reached C */
        }
    }
    if (f->cancel_prepare) atomic_store(&f->cancelled, 1);
    if (f->slow_prepare) atomic_fetch_add(&f->clock, 10000);
    if (ready(ready_state)) return LDAP_USER_CANCELLED;
    atomic_fetch_add(&f->sends, 1);
    if (f->reconnect_on_send) {
        LDAPURLDesc server = {0}; server.lud_host = ld->target; server.lud_scheme = "ldap"; server.lud_port = (int)ld->port;
        assert(ld->guard->lc_add(value, (Sockbuf *)ld, &server, NULL, ld->guard) != LDAP_SUCCESS);
        return LDAP_SERVER_DOWN;
    }
    atomic_fetch_add(&f->wire_sent, 1); *id = 17;
    if (f->cancel_on_send) atomic_store(&f->cancelled, 1);
    return LDAP_SUCCESS;
}
static int search_poll(void *state, LDAP *value, int id, unsigned timeout, void **message) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    assert(id == 17 && timeout && timeout <= 50); atomic_fetch_add(&f->polls, 1); *message = NULL;
    if (f->disconnect_on_poll) { ld->guard->lc_del(value, (Sockbuf *)ld, ld->guard); return -1; }
    if (f->pending_forever) return 0;
    if (f->late_result) atomic_fetch_add(&f->clock, 10000);
    *message = malloc(1); assert(*message); atomic_fetch_add(&f->results, 1); return 1;
}
static int result_emit(void *state, LDAP *ld, void *message, adfl_result_fn emit, void *out) {
    (void)ld; assert(message); struct fixture *f = state;
    if (f->root_reply) {
        const char *attribute = ((struct fake_ldap *)ld)->attribute;
        /* This fixture models an LDAP directory without published AD schema. */
        if (!strcmp(attribute, "schemaNamingContext"))
            return emit(out, ADFL_ENTRY_BEGIN, "", NULL, 0, 0) ||
                emit(out, ADFL_ENTRY_END, NULL, NULL, 0, 0) ||
                emit(out, ADFL_RESULT_CODE, NULL, NULL, 0, LDAP_SUCCESS);
        if (!strcmp(attribute, "*")) attribute = "dnsHostName";
        const char *answer = !strcmp(attribute, "dnsHostName") ? "observed-dc.invalid" : "DC=example";
        return emit(out, ADFL_ENTRY_BEGIN, "", NULL, 0, 0) ||
            emit(out, ADFL_ATTRIBUTE_BEGIN, attribute, NULL, 0, 0) ||
            emit(out, ADFL_ATTRIBUTE_VALUE, NULL, answer, strlen(answer), 0) ||
            emit(out, ADFL_ATTRIBUTE_END, NULL, NULL, 0, 0) ||
            emit(out, ADFL_ENTRY_END, NULL, NULL, 0, 0) ||
            emit(out, ADFL_RESULT_CODE, NULL, NULL, 0, LDAP_SUCCESS);
    }
    unsigned char bytes[] = {0, 255, 65};
    if (f->slow_conversion) atomic_fetch_add(&f->clock, 10000);
    if (emit(out, ADFL_ENTRY_BEGIN, ((struct fake_ldap *)ld)->base_dn, NULL, 0, 0) ||
        emit(out, ADFL_ATTRIBUTE_BEGIN, "binary", NULL, 0, 0) ||
        emit(out, ADFL_ATTRIBUTE_VALUE, NULL, bytes, sizeof(bytes), 0) ||
        emit(out, ADFL_ATTRIBUTE_END, NULL, NULL, 0, 0) ||
        emit(out, ADFL_ENTRY_CONTROL, "1.2.3", bytes, sizeof(bytes), 3) ||
        emit(out, ADFL_ENTRY_END, NULL, NULL, 0, 0) ||
        emit(out, ADFL_REFERENCE_BEGIN, NULL, NULL, 0, 0) ||
        emit(out, ADFL_REFERENCE_URL, "ldap://reference.invalid/", NULL, 0, 0) ||
        emit(out, ADFL_REFERENCE_END, NULL, NULL, 0, 0) ||
        emit(out, ADFL_RESULT_CODE, NULL, NULL, 0, f->partial_result ? LDAP_SIZELIMIT_EXCEEDED : LDAP_SUCCESS) ||
        emit(out, ADFL_REFERRAL_URL, "ldap://referral.invalid/", NULL, 0, 0) ||
        emit(out, ADFL_RESULT_CONTROL, "1.2.4", bytes, sizeof(bytes), 2) || echo_controls((struct fake_ldap *)ld, emit, out)) return 1;
    return 0;
}
static void result_free(void *state, void *value) { atomic_fetch_add(&((struct fixture *)state)->results_freed, 1); free(value); }
static void abandon(void *state, LDAP *ld, int id) { (void)ld; assert(id == 17); atomic_fetch_add(&((struct fixture *)state)->abandons, 1); }
static uint64_t clock_ms(void *state) { return (uint64_t)atomic_fetch_add(&((struct fixture *)state)->clock, 10); }
struct fake_message { int kind, page; };
static int page_start(void *state, LDAP *value, const adfl_search_request *r, unsigned size, const adfl_bytes *cookie, adfl_submitted_fn ready, void *ready_state, int *id) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    assert(r->timeout_milliseconds > 0 && r->timeout_milliseconds <= 3600000);
    assert((!strcmp(r->base_dn, "") || !strcmp(r->base_dn, "CN=copied") || !strcmp(r->base_dn, "DC=example")) && !strcmp(r->filter, "(objectClass=*)"));
    if (r->attributes && r->attributes[0]) assert(!strcmp(r->attributes[0], "binary") && !r->attributes[1]);
    if (size && ld->page) {
        const unsigned char expected[] = {0, 255, 80};
        assert(cookie->length == sizeof(expected) && !memcmp(cookie->data, expected, sizeof(expected)));
    } else assert(!cookie->length);
    f->last_page_size = size;
    ld->page++; ld->stream_index = 0; ld->modify = 0;
    atomic_fetch_add(&f->page_sends, 1);
    return search_start(state, value, r, ready, ready_state, id);
}
static int message_poll(void *state, LDAP *value, int id, unsigned timeout, void **message) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    assert(id == 17 && timeout && timeout <= 50); *message = NULL; atomic_fetch_add(&f->polls, 1);
    if (f->disconnect_on_poll) { ld->guard->lc_del(value, (Sockbuf *)ld, ld->guard); return -1; }
    if (f->pending_forever) return 0;
    const int types[] = {LDAP_RES_SEARCH_ENTRY, LDAP_RES_SEARCH_REFERENCE, LDAP_RES_SEARCH_RESULT};
    int type = ld->modify ? ld->modify : types[ld->stream_index++];
    if (f->excess_entry) type = LDAP_RES_SEARCH_ENTRY;
    if (f->unexpected_message) type = LDAP_RES_INTERMEDIATE;
    if (f->wrong_write_tag) type = LDAP_RES_SEARCH_RESULT;
    struct fake_message *m = malloc(sizeof(*m)); assert(m); *m = (struct fake_message){type, ld->page};
    if (f->late_result) { atomic_fetch_add(&f->clock, 10000); atomic_store(&f->cancelled, 1); }
    *message = m; atomic_fetch_add(&f->results, 1); return type;
}
static int message_emit(void *state, LDAP *ld, void *message, int type, adfl_result_fn emit, void *out) {
    (void)state; (void)ld;
    struct fake_message *m = message; assert(type == m->kind);
    const unsigned char binary[] = {0, 255, 65};
    switch (type) {
        case LDAP_RES_SEARCH_ENTRY:
            return emit(out, ADFL_ENTRY_BEGIN, m->page == 1 ? "CN=first" : "CN=second", NULL, 0, 0) ||
                emit(out, ADFL_ATTRIBUTE_BEGIN, "binary", NULL, 0, 0) ||
                emit(out, ADFL_ATTRIBUTE_VALUE, NULL, binary, sizeof(binary), 0) ||
                emit(out, ADFL_ATTRIBUTE_END, NULL, NULL, 0, 0) || emit(out, ADFL_ENTRY_END, NULL, NULL, 0, 0);
        case LDAP_RES_SEARCH_REFERENCE:
            return emit(out, ADFL_REFERENCE_BEGIN, NULL, NULL, 0, 0) ||
                emit(out, ADFL_REFERENCE_URL, "ldap://reference.invalid/", NULL, 0, 0) ||
                emit(out, ADFL_REFERENCE_END, NULL, NULL, 0, 0);
        case LDAP_RES_SEARCH_RESULT:
        case LDAP_RES_ADD:
        case LDAP_RES_DELETE:
        case LDAP_RES_MODDN:
        case LDAP_RES_MODIFY:
            return emit(out, ADFL_RESULT_CODE, NULL, NULL, 0, type != LDAP_RES_SEARCH_RESULT ? LDAP_UNWILLING_TO_PERFORM : LDAP_SUCCESS) ||
                emit(out, ADFL_MATCHED_DN, "DC=example", NULL, 0, 0) ||
                emit(out, ADFL_DIAGNOSTIC, "synthetic complete result", NULL, 0, 0) ||
                emit(out, ADFL_REFERRAL_URL, "ldap://referral.invalid/", NULL, 0, 0) ||
                emit(out, ADFL_RESULT_CONTROL, "1.2.4", binary, sizeof(binary), 2) || echo_controls((struct fake_ldap *)ld, emit, out);
        default: return 1;
    }
}
static int page_cookie(void *state, LDAP *ld, void *message, int *code, adfl_bytes *cookie) {
    (void)ld; struct fixture *f = state; struct fake_message *m = message;
    *cookie = (adfl_bytes){0}; *code = LDAP_SUCCESS;
    if (f->bad_cookie) return 1;
    if (m->page == 1 || f->always_more) {
        const unsigned char bytes[] = {0, 255, 80}; void *copy = malloc(sizeof(bytes)); assert(copy);
        memcpy(copy, bytes, sizeof(bytes)); cookie->data = copy; cookie->length = sizeof(bytes);
    }
    return 0;
}
static int write_start(void *state, LDAP *value, const adfl_write_request *r,
    adfl_submitted_fn submitted, void *submit_state, int *disposition, int *id) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    record_controls(f, ld, r->controls, r->control_count);
    if (r->terminal_type == LDAP_RES_MODIFY) {
    if (r->change_count) {
    assert(r->change_count == 2 && r->changes[0].value_count == 1 && r->changes[0].values[0].length == 0);
    assert(r->changes[1].value_count == 0); /* one empty value differs from deleting the attribute */
    }
    } else if (r->terminal_type == LDAP_RES_ADD) {
        if (r->change_count) {
        assert(r->change_count == 1 && r->changes[0].operation == 0 && r->changes[0].value_count == 1);
        assert(!strcmp(r->changes[0].attribute, "description") && r->changes[0].values[0].length == 0);
        }
    } else if (r->terminal_type == LDAP_RES_MODDN) {
        assert(!strcmp(r->new_rdn, "CN=renamed") && r->delete_old_rdn == 1);
        assert(!r->new_superior || !strcmp(r->new_superior, "OU=other"));
    } else assert(r->terminal_type == LDAP_RES_DELETE && !r->change_count);
    if (f->cancel_prepare) atomic_store(&f->cancelled, 1);
    if (f->slow_prepare) atomic_fetch_add(&f->clock, 10000);
    block_dependency(f, 2);
    if (submitted(submit_state)) return LDAP_USER_CANCELLED;
    block_dependency(f, 3);
    atomic_fetch_add(&f->submission_receipts, 1);
    *disposition = ADFL_OUTCOME_UNKNOWN;
    atomic_fetch_add(&f->modify_sends, 1); atomic_fetch_add(&f->wire_sent, 1);
    if (f->modify_send_failure) return LDAP_SERVER_DOWN;
    ld->modify = r->terminal_type; *id = 17; return LDAP_SUCCESS;
}
static const adfl_native_ops fake_ops = {
    probe, material_new, select_target, select_default, acquire_selected, credential, material_free,
    create_session, set_credential, bind_session, ldap_close, install_guard,
    search_start, search_poll, result_emit, result_free, abandon, clock_ms,
    page_start, message_poll, message_emit, page_cookie, write_start, set_source, check_source
};
static void balanced(struct fixture *f) {
    assert(atomic_load(&f->created) == atomic_load(&f->freed));
    assert(atomic_load(&f->connections) == atomic_load(&f->closed));
    assert(atomic_load(&f->results) == atomic_load(&f->results_freed));
}
static void operation_routing(void) {
    struct fixture f = {0}; adfl_bound_session *first = NULL, *second = NULL, *third = NULL;
    atomic_store(&f.identity, 1); atomic_store(&f.expected_identity, 1);
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &first) == ADFL_OK);
    atomic_store(&f.identity, 2); atomic_store(&f.expected_identity, 2);
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &second) == ADFL_OK);
    assert(first != second && atomic_load(&f.selected) == 2 && atomic_load(&f.acquired) == 2);
    atomic_store(&f.identity, 3); atomic_store(&f.expected_identity, 3);
    adfl_native_profile other = profile; other.host = "other.invalid";
    assert(adfl_open_with(&fake_ops, &f, &other, NULL, NULL, &third) == ADFL_OK);
    assert(atomic_load(&f.selected) == 3);
    adfl_session_close(&first); adfl_session_close(&first);
    assert(atomic_load(&f.freed) == 1);
    adfl_session_close(&second); adfl_session_close(&third); balanced(&f);
}
struct bind_thread { adfl_authority *authority; adfl_bound_session *session; };
static void *parallel_bind(void *arg) {
    struct bind_thread *t = arg;
    assert(adfl_authority_bind(t->authority, &profile, NULL, NULL, &t->session) == ADFL_OK);
    return NULL;
}
static void replacement_and_parallel_ownership(void) {
    struct fixture f = {0}; adfl_authority *authority = NULL;
    atomic_store(&f.identity, 7); atomic_store(&f.expected_identity, 7);
    assert(adfl_resolve_with(&fake_ops, &f, &profile, NULL, NULL, &authority) == ADFL_OK);
    atomic_store(&f.identity, 9); /* external source changes cannot retarget this owner */
    enum { N = 4 }; pthread_t threads[N]; struct bind_thread jobs[N];
    for (int i = 0; i < N; i++) { jobs[i] = (struct bind_thread){authority, NULL}; assert(!pthread_create(&threads[i], NULL, parallel_bind, &jobs[i])); }
    for (int i = 0; i < N; i++) assert(!pthread_join(threads[i], NULL));
    assert(atomic_load(&f.selected) == 1 && atomic_load(&f.acquired) == 1 && atomic_load(&f.installs) == N);
    adfl_session_close(&jobs[0].session);
    assert(adfl_authority_bind(authority, &profile, NULL, NULL, &jobs[0].session) == ADFL_OK);
    adfl_authority_close(&authority); assert(atomic_load(&f.freed) == 0);
    for (int i = 0; i < N; i++) adfl_session_close(&jobs[i].session);
    balanced(&f); assert(atomic_load(&f.freed) == 1);
}
static void fallback_and_failure(void) {
    for (int stage = 0; stage < 12; stage++) {
        struct fixture f = {0}; adfl_bound_session *s = NULL;
        f.selection_result = stage == 0 ? ADFL_SELECTED_CACHE_MISSING : 0;
        f.acquire_failure = stage == 1; f.create_failure = stage == 2;
        f.install_failure = stage == 3; f.bind_failure = stage == 4;
        f.omit_callback = stage == 5; f.wrong_prompt = stage == 6; f.cancel_after_bind = stage == 7;
        f.material_failure = stage == 8; f.cancel_at_callback = stage == 9;
        f.cancel_after_select = stage == 10; f.cancel_after_create = stage == 11;
        assert(adfl_open_with(&fake_ops, &f, &profile, cancelled, &f, &s) != ADFL_OK);
        assert(!s && atomic_load(&f.binds) <= 1 && atomic_load(&f.defaults) == 0);
        balanced(&f);
    }
    struct fixture f = {0}; adfl_bound_session *s = NULL;
    f.selection_result = ADFL_NO_SELECTION;
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
    assert(atomic_load(&f.defaults) == 1);
    adfl_session_close(&s); balanced(&f);
}
static void early_refusal(void) {
    struct fixture f = {0}; adfl_bound_session *s = NULL;
    f.probe_rejected = 1;
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_UNSUPPORTED);
    assert(!atomic_load(&f.created)); f.probe_rejected = 0;
    f.untrusted_plugin = 1; f.omit_callback = 1;
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_UNSUPPORTED);
    assert(!atomic_load(&f.created) && !atomic_load(&f.binds));
    f.untrusted_plugin = 0; f.omit_callback = 0;
    adfl_native_profile p = profile;
    const char *bad_hosts[] = {".", "-directory.invalid", "directory-.invalid", "directory..invalid", "directory.invalid."};
    for (size_t i = 0; i < sizeof(bad_hosts) / sizeof(*bad_hosts); i++) {
        p.host = bad_hosts[i];
        assert(adfl_open_with(&fake_ops, &f, &p, NULL, NULL, &s) == ADFL_INVALID);
    }
    p = profile; p.referrals = 96;
    assert(adfl_open_with(&fake_ops, &f, &p, NULL, NULL, &s) == ADFL_UNSUPPORTED);
    p = profile; p.tls = 1;
    assert(adfl_open_with(&fake_ops, &f, &p, NULL, NULL, &s) == ADFL_UNSUPPORTED);
    atomic_store(&f.cancelled, 1);
    assert(adfl_open_with(&fake_ops, &f, &profile, cancelled, &f, &s) == ADFL_CANCELLED);
    assert(!atomic_load(&f.created));
    adfl_authority *a = NULL;
    assert(adfl_resolve_with(&fake_ops, &f, &profile, NULL, NULL, &a) == ADFL_OK);
    p = profile; p.host = "different.invalid";
    assert(adfl_authority_bind(a, &p, NULL, NULL, &s) == ADFL_TARGET_MISMATCH);
    assert(!atomic_load(&f.connections)); adfl_authority_close(&a); balanced(&f);
}
struct events { int values, references, referrals, controls, code, reject; adfl_bound_session *session; };
static const adfl_search_request request = {"", "(objectClass=*)", NULL, 0, 1000, 0, 0, NULL, 0, 0};
static int receive(void *state, int event, const char *name, const void *bytes, size_t length, int number) {
    struct events *e = state;
    if (e->session) {
        struct events nested = {0};
        assert(adfl_session_search(e->session, &request, NULL, NULL, receive, &nested) == ADFL_BUSY);
        e->session = NULL;
    }
    if (event == ADFL_ATTRIBUTE_VALUE) { assert(length == 3 && ((const unsigned char *)bytes)[1] == 255); e->values++; }
    if (event == ADFL_REFERENCE_URL) { assert(name); e->references++; }
    if (event == ADFL_REFERRAL_URL) { assert(name); e->referrals++; }
    if (event == ADFL_ENTRY_CONTROL || event == ADFL_RESULT_CONTROL) { assert(name && length == 3); e->controls++; }
    if (event == ADFL_RESULT_CODE) e->code = number;
    return e->reject;
}
static void dispatch_ownership(void) {
    struct fixture f = {0}; adfl_bound_session *s = NULL; struct events e = {0};
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
    e.session = s; f.partial_result = 1;
    assert(adfl_session_search(s, &request, NULL, NULL, receive, &e) == ADFL_OK);
    assert(e.values == 1 && e.references == 1 && e.referrals == 1 && e.controls == 2 && e.code == LDAP_SIZELIMIT_EXCEEDED);
    assert(atomic_load(&f.sends) == 1 && atomic_load(&f.results_freed) == 1);
    adfl_session_close(&s); balanced(&f);
    for (int failure = 0; failure < 7; failure++) {
        struct fixture g = {0}; struct events rejected = {0};
        assert(adfl_open_with(&fake_ops, &g, &profile, NULL, NULL, &s) == ADFL_OK);
        g.reconnect_on_send = failure == 0; g.cancel_on_send = failure == 1;
        g.pending_forever = failure == 2; rejected.reject = failure == 3; g.disconnect_on_poll = failure == 4;
        g.late_result = failure == 5; g.slow_conversion = failure == 6;
        int status = adfl_session_search(s, &request, cancelled, &g, receive, &rejected);
        assert(status != ADFL_OK);
        if (failure == 2 || failure == 5 || failure == 6) assert(status == ADFL_TIMEOUT);
        atomic_store(&g.cancelled, 0);
        assert(adfl_session_search(s, &request, NULL, NULL, receive, &rejected) == ADFL_SESSION_RETIRED);
        assert(atomic_load(&g.sends) == 1);
        assert(atomic_load(&g.wire_sent) == (failure == 0 ? 0 : 1));
        assert(atomic_load(&g.abandons) == ((failure == 1 || failure == 2 || failure == 4) ? 1 : 0));
        adfl_session_close(&s); balanced(&g);
    }
    struct fixture h = {0};
    assert(adfl_open_with(&fake_ops, &h, &profile, NULL, NULL, &s) == ADFL_OK);
    atomic_store(&h.cancelled, 1);
    assert(adfl_session_search(s, &request, cancelled, &h, receive, &e) == ADFL_CANCELLED);
    assert(!atomic_load(&h.sends)); adfl_session_close(&s); balanced(&h);
}
static int accept_message(void *state, int event, const char *name, const void *bytes, size_t length, int number) {
    (void)name; (void)bytes; (void)length;
    if (event == ADFL_RESULT_CODE) *(int *)state = number;
    return 0;
}
static int submitted(void *state) {
    struct fixture *f = state; atomic_fetch_add(&f->submissions, 1); return f->reject_submit;
}
static void conversation_size_budget(void) {
    struct fixture f = {0}; adfl_bound_session *s = NULL; adfl_search_cursor *c = NULL;
    adfl_search_request r = request; r.size_limit = f.expected_size_limit = 3; f.always_more = 1;
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
    assert(adfl_cursor_open(s, &r, 2, NULL, NULL, &c) == ADFL_OK);
    for (int page = 0; page < 3; page++) {
        assert(f.last_page_size == (page == 2 ? 1u : 2u));
        for (int expected = 1; expected <= 3; expected++) {
            int kind, more, code;
            assert(adfl_cursor_read(c, 1000, NULL, NULL, accept_message, &code, &kind, &more) == ADFL_OK);
            assert(kind == expected);
            if (expected == 3) assert(more && code == LDAP_SUCCESS);
        }
        int rc = adfl_cursor_next_page(c, 1000, NULL, NULL);
        assert(rc == (page == 2 ? ADFL_INVALID : ADFL_OK));
    }
    assert(atomic_load(&f.page_sends) == 3);
    adfl_cursor_close(&c); adfl_session_close(&s); balanced(&f);
    struct fixture g = {0}; r.size_limit = g.expected_size_limit = 1;
    assert(adfl_open_with(&fake_ops, &g, &profile, NULL, NULL, &s) == ADFL_OK);
    assert(adfl_cursor_open(s, &r, 5, NULL, NULL, &c) == ADFL_OK);
    assert(g.last_page_size == 0); /* RFC permits ignoring control; ordinary search */
    int kind, more, code;
    assert(adfl_cursor_read(c, 1000, NULL, NULL, accept_message, &code, &kind, &more) == ADFL_OK);
    g.excess_entry = 1;
    assert(adfl_cursor_read(c, 1000, NULL, NULL, accept_message, &code, &kind, &more) == ADFL_RESULT_REJECTED);
    assert(!kind && atomic_load(&g.abandons) == 1);
    adfl_cursor_close(&c); adfl_session_close(&s); balanced(&g);
}
static void conversation_ownership(void) {
    struct fixture f = {0}; adfl_bound_session *s = NULL; adfl_search_cursor *c = NULL;
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
    char base[] = "CN=copied"; char filter[] = "(objectClass=*)"; char attr[] = "binary"; const char *attrs[] = {attr, NULL};
    adfl_search_request r = request; r.base_dn = base; r.filter = filter; r.attributes = attrs;
    r.server_time_limit_seconds = f.expected_server_limit = 30;
    assert(adfl_cursor_open(s, &r, 1, NULL, NULL, &c) == ADFL_OK);
    int code = -1;
    assert(adfl_session_search(s, &request, NULL, NULL, accept_message, &code) == ADFL_BUSY);
    adfl_session_close(&s); assert(!atomic_load(&f.closed));
    r.server_time_limit_seconds = 99;
    base[0] = 'X'; filter[1] = 'X'; attr[0] = 'X'; /* all future pages must use owned recipe */
    for (int page = 0; page < 2; page++) {
        for (int expected = 1; expected <= 3; expected++) {
            int kind = 0, more = 0;
            assert(adfl_cursor_read(c, 1000, NULL, NULL, accept_message, &code, &kind, &more) == ADFL_OK);
            assert(kind == expected && more == (expected == 3 && page == 0));
        }
        int kind, more;
        assert(adfl_cursor_read(c, 1000, NULL, NULL, accept_message, &code, &kind, &more) == ADFL_INVALID);
        if (!page) { assert(adfl_cursor_next_page_with_limit(c, 1000, 17, NULL, NULL) == ADFL_INVALID); assert(adfl_cursor_next_page_with_limit(c, 1000, 30, NULL, NULL) == ADFL_OK); }
        else assert(adfl_cursor_next_page(c, 1000, NULL, NULL) == ADFL_INVALID);
    }
    assert(code == LDAP_SUCCESS && atomic_load(&f.binds) == 1 && atomic_load(&f.page_sends) == 2);
    adfl_cursor_close(&c); adfl_cursor_close(&c); balanced(&f);
    for (int failure = 0; failure < 7; failure++) {
        struct fixture g = {0};
        assert(adfl_open_with(&fake_ops, &g, &profile, NULL, NULL, &s) == ADFL_OK);
        assert(adfl_cursor_open(s, &request, 1, NULL, NULL, &c) == ADFL_OK);
        if (failure == 0) { adfl_cursor_close(&c); assert(atomic_load(&g.abandons) == 1); }
        else if (failure >= 5) {
            int kind, more;
            for (int i = 0; i < 3; i++) assert(adfl_cursor_read(c, 1000, NULL, NULL, accept_message, &code, &kind, &more) == ADFL_OK);
            assert(kind == ADFL_CURSOR_PAGE_END && more);
            if (failure == 6) {
                atomic_fetch_add(&g.clock, 1000);
                assert(adfl_cursor_next_page(c, 1000, NULL, NULL) == ADFL_TIMEOUT);
            }
            adfl_cursor_close(&c);
            assert(!atomic_load(&g.abandons) && atomic_load(&g.page_sends) == 1);
        } else {
            g.bad_cookie = failure == 1; g.pending_forever = failure == 2; g.unexpected_message = failure == 3;
            int kind, more; int rc;
            do { rc = adfl_cursor_read(c, failure == 4 ? 1 : 1000, NULL, NULL, accept_message, &code, &kind, &more); } while (!rc);
            assert(rc != ADFL_OK);
            if (failure == 4) assert(!atomic_load(&g.polls));
            adfl_cursor_close(&c);
        }
        assert(adfl_session_search(s, &request, NULL, NULL, accept_message, &code) == ADFL_SESSION_RETIRED);
        adfl_session_close(&s); balanced(&g);
    }
}
static void modify_outcomes(void) {
    adfl_bytes empty = {NULL, 0};
    adfl_modification changes[] = {{2, "description", &empty, 1}, {1, "other", NULL, 0}};
    adfl_modify_request r = {"CN=example", changes, 2, 1000, NULL, 0};
    for (int scenario = 0; scenario < 5; scenario++) {
        struct fixture f = {0}; adfl_bound_session *s = NULL; int disposition = -1, code = -1;
        assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
        f.reject_submit = scenario == 1; f.modify_send_failure = scenario == 2;
        f.pending_forever = scenario == 3; f.slow_prepare = scenario == 4;
        f.late_result = scenario == 0; /* accepted terminal outcome wins over late cancel/deadline */
        int rc = adfl_session_modify(s, &r, cancelled, &f, submitted, &f, accept_message, &code, &disposition);
        assert(disposition == (scenario == 0 ? ADFL_COMPLETED : scenario == 1 || scenario == 4 ? ADFL_NOT_SENT : ADFL_OUTCOME_UNKNOWN));
        if (!scenario) { assert(rc == ADFL_OK && code == LDAP_UNWILLING_TO_PERFORM); }
        else assert(rc != ADFL_OK);
        assert(atomic_load(&f.modify_sends) == (scenario == 1 || scenario == 4 ? 0 : 1));
        assert(atomic_load(&f.submissions) == (scenario == 4 ? 0 : 1));
        adfl_session_close(&s); balanced(&f);
    }
}
static void generic_write_outcomes(void) {
    adfl_bytes empty = {NULL, 0};
    adfl_modification attribute = {0, "description", &empty, 1};
    adfl_add_request add = {"CN=example", &attribute, 1, 1000, NULL, 0};
    adfl_delete_request del = {"CN=example", 1000, NULL, 0};
    adfl_modify_dn_request rename = {"CN=example", "CN=renamed", NULL, 1, 1000, NULL, 0};
    for (int operation = 0; operation < 3; operation++) for (int scenario = 0; scenario < 7; scenario++) {
        struct fixture f = {0}; adfl_bound_session *s = NULL; int disposition = -1, code = -1;
        assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
        f.reject_submit = scenario == 1; f.modify_send_failure = scenario == 2;
        f.pending_forever = scenario == 3; f.slow_prepare = scenario == 4;
        f.wrong_write_tag = scenario == 5; f.late_result = scenario == 0;
        rename.new_superior = scenario == 6 ? "OU=other" : NULL;
        int rc;
        if (operation == 0) rc = adfl_session_add(s, &add, cancelled, &f, submitted, &f, accept_message, &code, &disposition);
        else if (operation == 1) rc = adfl_session_delete(s, &del, cancelled, &f, submitted, &f, accept_message, &code, &disposition);
        else rc = adfl_session_modify_dn(s, &rename, cancelled, &f, submitted, &f, accept_message, &code, &disposition);
        int completed = scenario == 0 || scenario == 6;
        int not_sent = scenario == 1 || scenario == 4;
        assert(disposition == (completed ? ADFL_COMPLETED : not_sent ? ADFL_NOT_SENT : ADFL_OUTCOME_UNKNOWN));
        assert(completed ? rc == ADFL_OK && code == LDAP_UNWILLING_TO_PERFORM : rc != ADFL_OK);
        assert(atomic_load(&f.modify_sends) == !not_sent);
        assert(atomic_load(&f.submissions) == (scenario != 4));
        assert(atomic_load(&s->retired) == (!completed && !not_sent));
        adfl_session_close(&s); balanced(&f);
    }
    struct fixture f = {0}; adfl_bound_session *s = NULL; int disposition = -1, code = -1;
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
    adfl_add_request empty_add = {"CN=example", NULL, 0, 1000, NULL, 0};
    assert(adfl_session_add(s, &empty_add, NULL, NULL, submitted, &f, accept_message, &code, &disposition) == ADFL_OK);
    assert(disposition == ADFL_COMPLETED && code == LDAP_UNWILLING_TO_PERFORM);
    adfl_modify_request empty_modify = {"CN=example", NULL, 0, 1000, NULL, 0};
    assert(adfl_session_modify(s, &empty_modify, NULL, NULL, submitted, &f, accept_message, &code, &disposition) == ADFL_OK);
    assert(disposition == ADFL_COMPLETED && code == LDAP_UNWILLING_TO_PERFORM);
    attribute.operation = 2;
    assert(adfl_session_add(s, &add, NULL, NULL, submitted, &f, accept_message, &code, &disposition) == ADFL_INVALID);
    assert(disposition == ADFL_NOT_SENT);
    rename.delete_old_rdn = 2;
    assert(adfl_session_modify_dn(s, &rename, NULL, NULL, submitted, &f, accept_message, &code, &disposition) == ADFL_INVALID);
    assert(disposition == ADFL_NOT_SENT && atomic_load(&f.submissions) == 2 && atomic_load(&f.modify_sends) == 2);
    adfl_session_close(&s); balanced(&f);
}
struct control_result { int count; };
static int accept_controls(void *state, int event, const char *name, const void *bytes, size_t length, int number) {
    struct control_result *r = state;
    if (event != ADFL_RESULT_CONTROL) return 0;
    if (!strcmp(name, "1.2.4")) return 0;
    if (r->count % 3 == 0) { assert(number == 3 && length == 3 && bytes); }
    if (r->count % 3 == 1) { assert(number == 2 && length == 0); }
    if (r->count % 3 == 2) { assert(number == 0 && length == 0); }
    r->count++; return 0;
}
static void control_ownership(void) {
    unsigned char bytes[] = {0, 255, 65}; char oid[] = "1.2.3";
    adfl_control controls[] = {{oid, 1, {bytes, sizeof(bytes)}, 1}, {"1.2.3", 0, {NULL, 0}, 1}, {"1.2.5", 0, {NULL, 0}, 0}};
    LDAPControl extra = {0}, **native = NULL;
    assert(adfl_controls_build(controls, 3, &extra, &native) == LDAP_SUCCESS);
    assert(native[3] == &extra && !native[4]); adfl_controls_release(native, 3);
    struct fixture f = {.expect_controls = 1}; adfl_bound_session *s = NULL; adfl_search_cursor *cursor = NULL;
    struct control_result result = {0};
    assert(adfl_open_with(&fake_ops, &f, &profile, NULL, NULL, &s) == ADFL_OK);
    adfl_search_request r = request; r.controls = controls; r.control_count = 3;
    assert(adfl_session_search(s, &r, NULL, NULL, accept_controls, &result) == ADFL_OK);
    assert(result.count == 3);
    assert(adfl_cursor_open(s, &r, 1, NULL, NULL, &cursor) == ADFL_OK);
    oid[0] = '9'; bytes[0] = 7; /* every later page must retain original OID/value */
    for (int page = 0; page < 2; page++) {
        for (int i = 0; i < 3; i++) {
            int kind, more;
            assert(adfl_cursor_read(cursor, 1000, NULL, NULL, accept_controls, &result, &kind, &more) == ADFL_OK);
        }
        if (!page) assert(adfl_cursor_next_page(cursor, 1000, NULL, NULL) == ADFL_OK);
    }
    adfl_cursor_close(&cursor); assert(result.count == 9);
    oid[0] = '1'; bytes[0] = 0;
    adfl_delete_request del = {"CN=example", 1000, controls, 3}; int disposition;
    assert(adfl_session_delete(s, &del, NULL, NULL, submitted, &f, accept_controls, &result, &disposition) == ADFL_OK);
    assert(disposition == ADFL_COMPLETED && result.count == 12);
    adfl_control page = {LDAP_CONTROL_PAGEDRESULTS, 0, {NULL, 0}, 0}; r.controls = &page; r.control_count = 1;
    int sends = atomic_load(&f.wire_sent);
    assert(adfl_cursor_open(s, &r, 1, NULL, NULL, &cursor) == ADFL_INVALID && !cursor);
    assert(atomic_load(&f.wire_sent) == sends);
    page.has_value = 0; page.value = (adfl_bytes){bytes, 3};
    assert(adfl_session_search(s, &r, NULL, NULL, accept_controls, &result) == ADFL_INVALID);
    assert(atomic_load(&f.wire_sent) == sends);
    adfl_session_close(&s); balanced(&f);
    for (int streaming = 0; streaming < 2; streaming++) for (int cancellation = 0; cancellation < 2; cancellation++) {
        struct fixture slow = {.slow_prepare = !cancellation, .cancel_prepare = cancellation};
        int expected = cancellation ? ADFL_CANCELLED : ADFL_TIMEOUT;
        assert(adfl_open_with(&fake_ops, &slow, &profile, NULL, NULL, &s) == ADFL_OK);
        if (streaming) assert(adfl_cursor_open(s, &request, 0, cancelled, &slow, &cursor) == expected && !cursor);
        else assert(adfl_session_search(s, &request, cancelled, &slow, accept_controls, &result) == expected);
        assert(!atomic_load(&slow.wire_sent)); adfl_session_close(&s); balanced(&slow);
    }
}
/* Public libldap handle/options only: ldap_initialize does not connect. No
 * bind, request, credential operation or global option mutation occurs here. */
static void search_policy_defaults(void) {
    LDAP *ld = NULL;
    assert(adfl_system_search_policy(NULL, 0) == LDAP_PARAM_ERROR);
    assert(ldap_initialize(&ld, "ldap://directory.invalid:389") == LDAP_SUCCESS && ld);
    for (int attempt = 0; attempt < 2; attempt++) {
        int aliases = LDAP_DEREF_ALWAYS, seconds = 37;
        assert(ldap_set_option(ld, LDAP_OPT_DEREF, &aliases) == LDAP_OPT_SUCCESS);
        assert(ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &seconds) == LDAP_OPT_SUCCESS);
        assert(adfl_system_search_policy(ld, attempt ? 0 : 19) == LDAP_SUCCESS);
        aliases = seconds = -1;
        assert(ldap_get_option(ld, LDAP_OPT_DEREF, &aliases) == LDAP_OPT_SUCCESS);
        assert(ldap_get_option(ld, LDAP_OPT_TIMELIMIT, &seconds) == LDAP_OPT_SUCCESS);
        assert(aliases == LDAP_DEREF_NEVER && seconds == (attempt ? 0 : 19));
    }
    assert(ldap_unbind_ext_s(ld, NULL, NULL) == LDAP_SUCCESS);
}
static void explicit_source_resolution(void) {
    adfl_credential_source file = {ADFL_SOURCE_FILE, "/recording/worker-cache"};
    adfl_credential_source dir = {ADFL_SOURCE_DIR, "/recording/collection"};
    assert(adfl_source_matches(&file, "FILE:/recording/worker-cache"));
    assert(!adfl_source_matches(&file, "FILE:/recording/worker-cache-other"));
    assert(adfl_source_matches(&dir, "DIR::/recording/collection/primary"));
    assert(!adfl_source_matches(&dir, "DIR::/recording/collection-other/cache"));
    assert(!adfl_source_matches(&dir, "DIR::/recording/collection/nested/cache"));
    assert(!adfl_source_matches(&dir, "DIR::/recording/collection/.."));
    assert(!adfl_source_matches(&dir, "FILE:/recording/collection/cache"));
    const char *invalid[] = {"/", "relative", "/a/", "/a//b", "/a/../b", "/./b"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        adfl_credential_source bad = {ADFL_SOURCE_FILE, invalid[i]};
        assert(adfl_source_validate(&bad) == ADFL_INVALID);
    }
    adfl_credential_source memory = {99, "/recording/cache"};
    assert(adfl_source_validate(&memory) == ADFL_UNSUPPORTED);
    adfl_credential_source owned = {ADFL_SOURCE_OWNED, "/proc/self/fd/6"};
    assert(adfl_source_validate(&owned) == ADFL_OK);
    assert(!adfl_source_matches(&owned, "FILE:/proc/self/fd/6"));
    owned.absolute_path = "/recording/cache";
    assert(adfl_source_validate(&owned) == ADFL_INVALID);
    for (int kind = 0; kind < 2; kind++) for (int scenario = 0; scenario < 5; scenario++) {
        struct fixture f = {0}; adfl_authority *a = NULL;
        const adfl_credential_source *source = kind ? &dir : &file;
        f.untrusted_plugin = scenario == 3; f.cancel_after_source_check = scenario == 4;
        f.selection_result = scenario == 1 ? ADFL_NO_SELECTION : ADFL_OK;
        if (scenario == 2) f.selected_source_override = "FILE:/recording/outside";
        int rc = adfl_resolve_from_with(&fake_ops, &f, &profile, source, cancelled, &f, &a);
        if (scenario == 3) {
            assert(rc == ADFL_UNSUPPORTED && !a && !atomic_load(&f.created) && !atomic_load(&f.source_sets));
        } else {
            assert(atomic_load(&f.source_sets) == 1 && atomic_load(&f.source_checks) == 1);
            assert(f.source_kind == source->kind && !strcmp(f.source_path, source->absolute_path));
            if (scenario == 2 || scenario == 4) assert(rc == (scenario == 4 ? ADFL_CANCELLED : ADFL_RESOLVE_FAILED) && !a && !atomic_load(&f.acquired));
            else {
                assert(rc == ADFL_OK && a && atomic_load(&f.acquired) == 1);
                assert(atomic_load(&f.defaults) == (scenario == 1));
            }
        }
        adfl_authority_close(&a); balanced(&f);
    }
}
int main(void) {
    assert(adfl_native_abi_version() == 4);
    explicit_source_resolution();
    search_policy_defaults();
    operation_routing(); replacement_and_parallel_ownership(); fallback_and_failure(); early_refusal(); dispatch_ownership(); conversation_size_budget(); conversation_ownership(); modify_outcomes(); generic_write_outcomes(); control_ownership();
    puts("PASS: actual adapter orchestration; recording native dependencies only; no credentials or network.");
    return 0;
}

#ifdef ADFL_TEST_BRIDGE
/* Exported only by the explicitly built recording test library. The production
 * library has neither factory nor injected-dependency entry points exported. */
static struct fixture managed_fixture = {.root_reply = 1};
ADFL_API int adfl_test_open(const adfl_native_profile *requested, adfl_bound_session **out) {
    return adfl_open_with(&fake_ops, &managed_fixture, requested, NULL, NULL, out);
}
/* Same authority orchestration as production, with recording-only dependencies.
 * Cancellation callbacks are synchronous and never retained. */
ADFL_API int adfl_test_resolve(const adfl_native_profile *requested, adfl_cancelled_fn check,
    void *cancel_state, adfl_authority **out) {
    return adfl_resolve_with(&fake_ops, &managed_fixture, requested, check, cancel_state, out);
}
ADFL_API int adfl_test_resolve_from(const adfl_native_profile *requested, const adfl_credential_source *source,
    adfl_cancelled_fn check, void *cancel_state, adfl_authority **out) {
    return adfl_resolve_from_with(&fake_ops, &managed_fixture, requested, source, check, cancel_state, out);
}
ADFL_API const char *adfl_test_source_path(void) { return managed_fixture.source_path; }
/* Serialize these test scenario transitions with bind calls. Source identity can
 * change while an authority/session exists; expected identity separately asserts
 * which already-resolved resource subsequent binds actually consume. */
ADFL_API int adfl_test_set_identity(int source_identity, int expected_binding_identity) {
    if (source_identity < 0 || expected_binding_identity < 0) return ADFL_INVALID;
    atomic_store(&managed_fixture.identity, source_identity);
    atomic_store(&managed_fixture.expected_identity, expected_binding_identity);
    return ADFL_OK;
}
/* nth=1 fails the next bind, nth=2 its successor, nth=0 clears the injection.
 * Failure occurs after credential installation, exercising partial-bind cleanup. */
ADFL_API int adfl_test_fail_nth_bind(int nth) {
    int bound = atomic_load(&managed_fixture.binds);
    if (nth < 0 || nth > INT_MAX - bound) return ADFL_INVALID;
    atomic_store(&managed_fixture.fail_bind_at, nth ? bound + nth : 0);
    return ADFL_OK;
}
/* Configuration changes only while no fake session is alive. Scenario1 enables
 * cursor+modify fixtures; scenario0 preserves existing RootDSE search fixture. */
ADFL_API int adfl_test_configure(int scenario) {
    if (scenario < 0 || scenario > 1 || atomic_load(&managed_fixture.created) != atomic_load(&managed_fixture.freed)) return ADFL_INVALID;
    managed_fixture.root_reply = scenario == 0; return ADFL_OK;
}
/* Only exported from the recording test library, never the production adapter.
 * A worker-process test sets one phase then exercises the real coordinator. */
ADFL_API int adfl_test_set_block(int phase) {
    if (phase < 0 || phase > 4) return ADFL_INVALID;
    managed_fixture.block_phase = phase; return ADFL_OK;
}
ADFL_API int adfl_test_count(int kind) {
    switch (kind) {
        case 0: return atomic_load(&managed_fixture.sends);
        case 1: return atomic_load(&managed_fixture.closed);
        case 2: return atomic_load(&managed_fixture.freed);
        case 3: return atomic_load(&managed_fixture.results_freed);
        case 4: return atomic_load(&managed_fixture.page_sends);
        case 5: return atomic_load(&managed_fixture.modify_sends);
        case 6: return atomic_load(&managed_fixture.submission_receipts);
        case 7: return atomic_load(&managed_fixture.selected);
        case 8: return atomic_load(&managed_fixture.acquired);
        case 9: return atomic_load(&managed_fixture.binds);
        case 10: return atomic_load(&managed_fixture.source_sets);
        case 11: return (int)managed_fixture.source_kind;
        case 12: return atomic_load(&managed_fixture.source_checks);
        default: return -1;
    }
}
#endif
