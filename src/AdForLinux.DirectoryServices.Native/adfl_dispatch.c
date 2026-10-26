#include "adfl_native_internal.h"
#include <limits.h>

struct emission {
    adfl_bound_session *session;
    adfl_cancelled_fn cancelled;
    void *cancel_state;
    adfl_result_fn emit;
    void *emit_state;
    int stopped, retire_after_result;
    uint64_t start;
    unsigned timeout;
};
static int deadline(adfl_bound_session *s, uint64_t start, unsigned timeout) {
    uint64_t now = s->authority->ops->monotonic_ms(s->authority->state);
    if (now == UINT64_MAX || now < start) return ADFL_REQUEST_FAILED;
    return now - start >= timeout ? ADFL_TIMEOUT : ADFL_OK;
}
static int emit_checked(void *state, int event, const char *name, const void *bytes, size_t length, int number) {
    struct emission *e = state;
    if (atomic_load(&e->session->retired)) e->stopped = ADFL_SESSION_RETIRED;
    else if (e->cancelled && e->cancelled(e->cancel_state)) e->stopped = ADFL_CANCELLED;
    else e->stopped = deadline(e->session, e->start, e->timeout);
    if (!e->stopped && e->emit(e->emit_state, event, name, bytes, length, number)) e->stopped = ADFL_RESULT_REJECTED;
    if (!e->stopped) e->stopped = deadline(e->session, e->start, e->timeout);
    if (event == ADFL_RESULT_CODE && (number == LDAP_UNAVAILABLE || number == LDAP_PROTOCOL_ERROR))
        e->retire_after_result = 1;
    return e->stopped;
}
int adfl_session_search(adfl_bound_session *s, const adfl_search_request *r,
                       adfl_cancelled_fn cancelled, void *cancel_state, adfl_result_fn emit, void *emit_state) {
    if (!s || !r || !r->base_dn || !r->filter || !emit || r->scope < 0 || r->scope > 2 ||
        !r->timeout_milliseconds || r->timeout_milliseconds > 3600000 || r->size_limit > INT_MAX || r->types_only > 1)
        return ADFL_INVALID;
    if (cancelled && cancelled(cancel_state)) return ADFL_CANCELLED;
    int idle = 0;
    if (!atomic_compare_exchange_strong(&s->busy, &idle, 1)) return ADFL_BUSY;
    int rc = ADFL_OK, message_id = -1, pending = 0, retire_after_result = 0;
    void *message = NULL;
    const adfl_native_ops *ops = s->authority->ops;
    void *state = s->authority->state;
    if (atomic_load(&s->retired)) { rc = ADFL_SESSION_RETIRED; goto done; }
    uint64_t start = ops->monotonic_ms(state);
    if (start == UINT64_MAX) { rc = ADFL_REQUEST_FAILED; goto done; }
    /* Dispatch exactly once. No retry/fallback is permitted after this call. */
    if (ops->search_start(state, s->ldap, r, &message_id) != LDAP_SUCCESS) {
        rc = ADFL_REQUEST_FAILED; goto done;
    }
    pending = 1;
    for (;;) {
        if (atomic_load(&s->retired)) { rc = ADFL_SESSION_RETIRED; break; }
        if (cancelled && cancelled(cancel_state)) { rc = ADFL_CANCELLED; break; }
        uint64_t now = ops->monotonic_ms(state);
        if (now == UINT64_MAX || now < start) { rc = ADFL_REQUEST_FAILED; break; }
        uint64_t elapsed = now - start;
        if (elapsed >= r->timeout_milliseconds) { rc = ADFL_TIMEOUT; break; }
        unsigned remaining = r->timeout_milliseconds - (unsigned)elapsed;
        int result = ops->search_poll(state, s->ldap, message_id, remaining < 50 ? remaining : 50, &message);
        if (result < 0) { rc = ADFL_REQUEST_FAILED; break; }
        if (result == 0) { if (message) { ops->result_free(state, message); message = NULL; } continue; }
        pending = 0;
        rc = deadline(s, start, r->timeout_milliseconds);
        if (rc) break;
        struct emission e = {s, cancelled, cancel_state, emit, emit_state, 0, 0, start, r->timeout_milliseconds};
        if (!message || ops->result_emit(state, s->ldap, message, emit_checked, &e))
            rc = e.stopped ? e.stopped : ADFL_RESULT_REJECTED;
        retire_after_result = e.retire_after_result;
        if (!rc) rc = deadline(s, start, r->timeout_milliseconds);
        if (atomic_load(&s->retired)) rc = ADFL_SESSION_RETIRED;
        if (cancelled && cancelled(cancel_state)) rc = ADFL_CANCELLED;
        break;
    }
done:
    if (message) ops->result_free(state, message);
    if (retire_after_result) atomic_store(&s->retired, 1);
    if (rc) {
        atomic_store(&s->retired, 1);
        if (pending) ops->abandon(state, s->ldap, message_id);
    }
    atomic_store(&s->busy, 0);
    return rc;
}
