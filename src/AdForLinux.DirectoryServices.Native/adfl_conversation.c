#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct adfl_search_cursor {
    adfl_bound_session *session;
    adfl_search_request request;
    unsigned page_size;
    uint64_t start;
    adfl_bytes cookie;
    int message_id, pending, awaiting_page, terminal;
};
static int valid_search(const adfl_search_request *r) {
    return r && r->base_dn && r->filter && r->scope >= 0 && r->scope <= 2 &&
        r->timeout_milliseconds && r->timeout_milliseconds <= 3600000 &&
        r->size_limit <= INT_MAX && r->types_only <= 1;
}
static int remaining(adfl_bound_session *s, uint64_t start, unsigned timeout, unsigned *out) {
    uint64_t now = s->authority->ops->monotonic_ms(s->authority->state);
    if (now == UINT64_MAX || now < start) return ADFL_REQUEST_FAILED;
    if (now - start >= timeout) return ADFL_TIMEOUT;
    *out = timeout - (unsigned)(now - start); return ADFL_OK;
}
static int check(adfl_bound_session *s, adfl_cancelled_fn cancel, void *state) {
    if (atomic_load(&s->retired)) return ADFL_SESSION_RETIRED;
    return cancel && cancel(state) ? ADFL_CANCELLED : ADFL_OK;
}
static int cursor_stop(adfl_search_cursor *c, int rc) {
    if (c->pending) c->session->authority->ops->abandon(c->session->authority->state, c->session->ldap, c->message_id);
    c->pending = 0; c->terminal = 1; c->awaiting_page = 0;
    atomic_store(&c->session->retired, 1); return rc;
}
void adfl_cursor_close(adfl_search_cursor **owner) {
    if (!owner || !*owner) return;
    adfl_search_cursor *c = *owner; *owner = NULL;
    if (!c->terminal) (void)cursor_stop(c, ADFL_CANCELLED);
    free((void *)c->cookie.data);
    free((void *)c->request.base_dn); free((void *)c->request.filter);
    if (c->request.attributes) {
        for (size_t i = 0; c->request.attributes[i]; i++) free((void *)c->request.attributes[i]);
        free((void *)c->request.attributes);
    }
    atomic_store(&c->session->busy, 0);
    adfl_session_release(c->session); free(c);
}
static int cursor_send(adfl_search_cursor *c, unsigned budget, adfl_cancelled_fn cancel, void *state) {
    int rc = check(c->session, cancel, state); unsigned left;
    if (!rc) rc = remaining(c->session, c->start, c->request.timeout_milliseconds, &left);
    if (!rc && !budget) rc = ADFL_TIMEOUT;
    if (rc) return cursor_stop(c, rc);
    adfl_search_request dispatch = c->request;
    dispatch.timeout_milliseconds = budget < left ? budget : left;
    if (c->session->authority->ops->page_start(c->session->authority->state, c->session->ldap,
        &dispatch, c->page_size, &c->cookie, &c->message_id) != LDAP_SUCCESS)
        return cursor_stop(c, ADFL_REQUEST_FAILED);
    c->pending = 1; c->awaiting_page = 0; return ADFL_OK;
}
int adfl_cursor_open(adfl_bound_session *s, const adfl_search_request *r, unsigned page_size,
                     adfl_cancelled_fn cancel, void *state, adfl_search_cursor **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    if (!s || !valid_search(r) || page_size > INT_MAX) return ADFL_INVALID;
    /* Do not reinterpret a logical total size limit as a separate per-page limit. */
    if (page_size && r->size_limit) return ADFL_UNSUPPORTED;
    int rc = check(s, cancel, state), idle = 0;
    if (rc) return rc;
    if (!atomic_compare_exchange_strong(&s->busy, &idle, 1)) return ADFL_BUSY;
    adfl_search_cursor *c = calloc(1, sizeof(*c));
    if (!c) { atomic_store(&s->busy, 0); return ADFL_NO_MEMORY; }
    c->session = s; adfl_session_retain(s); c->page_size = page_size; c->request = *r;
    c->start = s->authority->ops->monotonic_ms(s->authority->state);
    c->request.base_dn = strdup(r->base_dn); c->request.filter = strdup(r->filter); c->request.attributes = NULL;
    if (!c->request.base_dn || !c->request.filter) { rc = ADFL_NO_MEMORY; goto failed; }
    if (r->attributes) {
        size_t count = 0; while (r->attributes[count]) count++;
        if (count > SIZE_MAX / sizeof(char *) - 1) { rc = ADFL_INVALID; goto failed; }
        char **attributes = calloc(count + 1, sizeof(*attributes)); c->request.attributes = (const char *const *)attributes;
        if (!attributes) { rc = ADFL_NO_MEMORY; goto failed; }
        for (size_t i = 0; i < count; i++) if (!(attributes[i] = strdup(r->attributes[i]))) { rc = ADFL_NO_MEMORY; goto failed; }
    }
    if (c->start == UINT64_MAX) { rc = ADFL_REQUEST_FAILED; goto failed; }
    rc = cursor_send(c, r->timeout_milliseconds, cancel, state);
    if (rc) goto failed;
    *out = c; return ADFL_OK;
failed:
    /* Construction failure before send has no outstanding server cursor. */
    c->terminal = 1; adfl_cursor_close(&c); return rc;
}
struct stream_emit {
    adfl_bound_session *session;
    adfl_cancelled_fn cancel; void *cancel_state;
    adfl_result_fn emit; void *emit_state;
    uint64_t start; unsigned budget;
    int stopped, code, code_seen;
};
static int stream_emit(void *state, int event, const char *name, const void *bytes, size_t length, int number) {
    struct stream_emit *e = state; unsigned left;
    e->stopped = check(e->session, e->cancel, e->cancel_state);
    if (!e->stopped) e->stopped = remaining(e->session, e->start, e->budget, &left);
    if (!e->stopped && e->emit(e->emit_state, event, name, bytes, length, number)) e->stopped = ADFL_RESULT_REJECTED;
    if (event == ADFL_RESULT_CODE) { e->code = number; e->code_seen++; }
    return e->stopped;
}
int adfl_cursor_read(adfl_search_cursor *c, unsigned budget, adfl_cancelled_fn cancel, void *state,
                     adfl_result_fn emit, void *emit_state, int *kind, int *has_more) {
    if (!kind || !has_more) return ADFL_INVALID;
    *kind = *has_more = 0;
    if (!c || !emit || c->terminal || c->awaiting_page || !c->pending) return ADFL_INVALID;
    adfl_bound_session *s = c->session; const adfl_native_ops *ops = s->authority->ops;
    /* One clock sample anchors the call and derives its intersection with the
     * original conversation deadline; never add sampling time back to the budget. */
    uint64_t start = ops->monotonic_ms(s->authority->state);
    int rc = check(s, cancel, state);
    if (!rc && (start == UINT64_MAX || start < c->start)) rc = ADFL_REQUEST_FAILED;
    if (!rc && (!budget || start - c->start >= c->request.timeout_milliseconds)) rc = ADFL_TIMEOUT;
    if (rc) return cursor_stop(c, rc);
    unsigned total_left = c->request.timeout_milliseconds - (unsigned)(start - c->start);
    if (budget > total_left) budget = total_left;
    void *message = NULL;
    int type = 0;
    for (;;) {
        unsigned left;
        rc = check(s, cancel, state);
        if (!rc) rc = remaining(s, start, budget, &left);
        if (rc) break;
        type = ops->message_poll(s->authority->state, s->ldap, c->message_id, left < 50 ? left : 50, &message);
        if (type < 0) { rc = ADFL_REQUEST_FAILED; break; }
        if (!type) { if (message) { ops->result_free(s->authority->state, message); message = NULL; } continue; }
        if (!message || (type != LDAP_RES_SEARCH_ENTRY && type != LDAP_RES_SEARCH_REFERENCE && type != LDAP_RES_SEARCH_RESULT)) {
            rc = ADFL_RESULT_REJECTED; break;
        }
        if (type == LDAP_RES_SEARCH_RESULT) c->pending = 0;
        struct stream_emit e = {s, cancel, state, emit, emit_state, start, budget, 0, LDAP_OTHER, 0};
        adfl_bytes cookie = {0}; int page_code = LDAP_OTHER;
        if (type == LDAP_RES_SEARCH_RESULT && c->page_size && ops->page_cookie(s->authority->state, s->ldap, message, &page_code, &cookie))
            rc = ADFL_RESULT_REJECTED;
        if (!rc && ops->message_emit(s->authority->state, s->ldap, message, type, stream_emit, &e))
            rc = e.stopped ? e.stopped : ADFL_RESULT_REJECTED;
        unsigned ignored;
        if (!rc) rc = remaining(s, start, budget, &ignored);
        if (!rc) rc = check(s, cancel, state);
        if (!rc && type == LDAP_RES_SEARCH_RESULT && (e.code_seen != 1 || (c->page_size && e.code != page_code))) rc = ADFL_RESULT_REJECTED;
        if (!rc) {
            *kind = type == LDAP_RES_SEARCH_ENTRY ? ADFL_CURSOR_ENTRY : type == LDAP_RES_SEARCH_REFERENCE ? ADFL_CURSOR_REFERENCE : ADFL_CURSOR_PAGE_END;
            if (*kind == ADFL_CURSOR_PAGE_END) {
                free((void *)c->cookie.data); c->cookie = cookie; cookie = (adfl_bytes){0};
                *has_more = e.code == LDAP_SUCCESS && c->cookie.length != 0;
                c->awaiting_page = *has_more; c->terminal = !*has_more;
                if (e.code == LDAP_UNAVAILABLE || e.code == LDAP_PROTOCOL_ERROR) atomic_store(&s->retired, 1);
            }
        }
        free((void *)cookie.data); break;
    }
    if (message) ops->result_free(s->authority->state, message);
    return rc ? cursor_stop(c, rc) : ADFL_OK;
}
int adfl_cursor_next_page(adfl_search_cursor *c, unsigned budget, adfl_cancelled_fn cancel, void *state) {
    if (!c || c->terminal || !c->awaiting_page || !c->cookie.length) return ADFL_INVALID;
    return cursor_send(c, budget, cancel, state);
}

struct modify_emit { adfl_result_fn emit; void *state; int code, seen; };
static int modify_emit(void *state, int event, const char *name, const void *bytes, size_t length, int number) {
    struct modify_emit *e = state;
    if (event == ADFL_RESULT_CODE) { e->code = number; e->seen++; }
    /* A received terminal write outcome is known even if cancellation arrives
     * while decoding. Do not replace that outcome with a late timeout/cancel. */
    return e->emit(e->state, event, name, bytes, length, number);
}
struct submission_check {
    adfl_bound_session *session; uint64_t start; unsigned budget;
    adfl_cancelled_fn cancel; void *cancel_state;
    adfl_submitted_fn submitted; void *submit_state;
    int invoked, refused;
};
static int submit_checked(void *state) {
    struct submission_check *s = state; unsigned left;
    if (s->invoked++) return s->refused = ADFL_REQUEST_FAILED;
    s->refused = check(s->session, s->cancel, s->cancel_state);
    if (!s->refused) s->refused = remaining(s->session, s->start, s->budget, &left);
    if (!s->refused && s->submitted(s->submit_state)) s->refused = ADFL_RESULT_REJECTED;
    return s->refused;
}
int adfl_session_modify(adfl_bound_session *s, const adfl_modify_request *r,
    adfl_cancelled_fn cancel, void *cancel_state, adfl_submitted_fn submitted, void *submit_state,
    adfl_result_fn emit, void *emit_state, int *disposition) {
    if (!disposition) return ADFL_INVALID;
    *disposition = ADFL_NOT_SENT;
    if (!s || !r || !r->dn || !r->changes || !r->change_count || !submitted || !emit ||
        !r->timeout_milliseconds || r->timeout_milliseconds > 3600000 ||
        r->change_count > SIZE_MAX / sizeof(LDAPMod *) - 1) return ADFL_INVALID;
    const adfl_native_ops *ops = s->authority->ops; void *state = s->authority->state;
    uint64_t start = ops->monotonic_ms(state);
    if (start == UINT64_MAX) return ADFL_REQUEST_FAILED;
    for (size_t i = 0; i < r->change_count; i++) {
        const adfl_modification *m = &r->changes[i];
        if (!m->attribute || !m->attribute[0] || m->operation < 0 || m->operation > 2 ||
            (m->value_count && !m->values) || m->value_count > SIZE_MAX / sizeof(struct berval *) - 1) return ADFL_INVALID;
        for (size_t j = 0; j < m->value_count; j++) if (m->values[j].length && !m->values[j].data) return ADFL_INVALID;
    }
    int rc = check(s, cancel, cancel_state), idle = 0;
    if (rc) return rc;
    if (!atomic_compare_exchange_strong(&s->busy, &idle, 1)) return ADFL_BUSY;
    int id = -1, pending = 0; void *message = NULL;
    struct submission_check submission = {s, start, r->timeout_milliseconds, cancel, cancel_state, submitted, submit_state, 0, 0};
    if (ops->modify_start(state, s->ldap, r, submit_checked, &submission, disposition, &id) != LDAP_SUCCESS) {
        rc = submission.refused ? submission.refused : ADFL_REQUEST_FAILED; goto done;
    }
    if (submission.invoked != 1 || submission.refused || *disposition != ADFL_OUTCOME_UNKNOWN) { rc = ADFL_REQUEST_FAILED; goto done; }
    pending = 1;
    for (;;) {
        unsigned left;
        rc = check(s, cancel, cancel_state);
        if (!rc) rc = remaining(s, start, r->timeout_milliseconds, &left);
        if (rc) break;
        int type = ops->message_poll(state, s->ldap, id, left < 50 ? left : 50, &message);
        if (type < 0) { rc = ADFL_REQUEST_FAILED; break; }
        if (!type) { if (message) { ops->result_free(state, message); message = NULL; } continue; }
        if (type != LDAP_RES_MODIFY || !message) { rc = ADFL_RESULT_REJECTED; break; }
        pending = 0;
        struct modify_emit e = {emit, emit_state, LDAP_OTHER, 0};
        if (ops->message_emit(state, s->ldap, message, type, modify_emit, &e) || e.seen != 1) { rc = ADFL_RESULT_REJECTED; break; }
        *disposition = ADFL_COMPLETED;
        if (e.code == LDAP_PROTOCOL_ERROR || e.code == LDAP_UNAVAILABLE) atomic_store(&s->retired, 1);
        break;
    }
done:
    if (message) ops->result_free(state, message);
    if (rc && *disposition != ADFL_NOT_SENT) {
        atomic_store(&s->retired, 1);
        if (pending) ops->abandon(state, s->ldap, id);
    }
    atomic_store(&s->busy, 0); return rc;
}
