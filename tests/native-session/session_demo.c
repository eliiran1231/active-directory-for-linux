#include "adfl_native_internal.h"
#include <sasl/sasl.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Recording native dependencies, not a second pool/binder implementation.
 * Tests call adfl_open_with/adfl_resolve_with/adfl_authority_bind from the real
 * adapter. NO system resolution, credential acquisition or LDAP bind is called. */
struct fixture {
    atomic_int created, selected, defaults, acquired, freed, connections, closed, installs, binds;
    atomic_int identity, expected_identity, cancelled;
    atomic_int sends, wire_sent, polls, results, results_freed, abandons, clock;
    int reconnect_on_send, disconnect_on_poll, pending_forever, cancel_on_send, partial_result;
    int late_result, slow_conversion, root_reply;
    int selection_result, acquire_failure, create_failure, install_failure, probe_rejected, material_failure, untrusted_plugin;
    int cancel_after_select, cancel_after_create, cancel_at_callback;
    int bind_failure, omit_callback, wrong_prompt, cancel_after_bind;
};
struct fake_material { struct fixture *owner; int identity; char target[254]; atomic_int sessions; };
struct fake_ldap { struct fixture *owner; struct fake_material *credential; char target[254]; char attribute[64]; unsigned port; ldap_conncb *guard; };
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
    (void)value; struct fixture *f = state; atomic_fetch_add(&f->acquired, 1);
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
    atomic_fetch_add(&f->binds, 1);
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
    return f->bind_failure ? LDAP_INVALID_CREDENTIALS : LDAP_SUCCESS;
}
static void ldap_close(void *state, LDAP *value) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    if (!ld) return;
    if (ld->guard) ld->guard->lc_del(value, (Sockbuf *)ld, ld->guard);
    if (ld->credential) atomic_fetch_sub(&ld->credential->sessions, 1);
    atomic_fetch_add(&f->closed, 1); free(ld);
}
static int cancelled(void *state) { return atomic_load(&((struct fixture *)state)->cancelled); }
static int install_guard(void *state, LDAP *value, ldap_conncb *guard) {
    (void)state; ((struct fake_ldap *)value)->guard = guard; return LDAP_OPT_SUCCESS;
}
static int search_start(void *state, LDAP *value, const adfl_search_request *request, int *id) {
    struct fixture *f = state; struct fake_ldap *ld = (struct fake_ldap *)value;
    assert(request->scope == 0 && !strcmp(request->filter, "(objectClass=*)"));
    if (f->root_reply) {
        assert(request->attributes && request->attributes[0] && strlen(request->attributes[0]) < sizeof(ld->attribute));
        strcpy(ld->attribute, request->attributes[0]);
    }
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
    if (emit(out, ADFL_ENTRY_BEGIN, "", NULL, 0, 0) ||
        emit(out, ADFL_ATTRIBUTE_BEGIN, "binary", NULL, 0, 0) ||
        emit(out, ADFL_ATTRIBUTE_VALUE, NULL, bytes, sizeof(bytes), 0) ||
        emit(out, ADFL_ATTRIBUTE_END, NULL, NULL, 0, 0) ||
        emit(out, ADFL_ENTRY_CONTROL, "1.2.3", bytes, sizeof(bytes), 1) ||
        emit(out, ADFL_ENTRY_END, NULL, NULL, 0, 0) ||
        emit(out, ADFL_REFERENCE_BEGIN, NULL, NULL, 0, 0) ||
        emit(out, ADFL_REFERENCE_URL, "ldap://reference.invalid/", NULL, 0, 0) ||
        emit(out, ADFL_REFERENCE_END, NULL, NULL, 0, 0) ||
        emit(out, ADFL_RESULT_CODE, NULL, NULL, 0, f->partial_result ? LDAP_SIZELIMIT_EXCEEDED : LDAP_SUCCESS) ||
        emit(out, ADFL_REFERRAL_URL, "ldap://referral.invalid/", NULL, 0, 0) ||
        emit(out, ADFL_RESULT_CONTROL, "1.2.4", bytes, sizeof(bytes), 0)) return 1;
    return 0;
}
static void result_free(void *state, void *value) { atomic_fetch_add(&((struct fixture *)state)->results_freed, 1); free(value); }
static void abandon(void *state, LDAP *ld, int id) { (void)ld; assert(id == 17); atomic_fetch_add(&((struct fixture *)state)->abandons, 1); }
static uint64_t clock_ms(void *state) { return (uint64_t)atomic_fetch_add(&((struct fixture *)state)->clock, 10); }
static const adfl_native_ops fake_ops = {
    probe, material_new, select_target, select_default, acquire_selected, credential, material_free,
    create_session, set_credential, bind_session, ldap_close, install_guard,
    search_start, search_poll, result_emit, result_free, abandon, clock_ms
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
static const adfl_search_request request = {"", "(objectClass=*)", NULL, 0, 1000, 0, 0};
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
int main(void) {
    operation_routing(); replacement_and_parallel_ownership(); fallback_and_failure(); early_refusal(); dispatch_ownership();
    puts("PASS: actual adapter orchestration; recording native dependencies only; no credentials or network.");
    return 0;
}

#ifdef ADFL_TEST_BRIDGE
/* Exported only by the explicitly built recording test library. The production
 * library has neither factory nor injected-dependency entry points exported. */
static struct fixture managed_fixture;
ADFL_API int adfl_test_open(const adfl_native_profile *requested, adfl_bound_session **out) {
    managed_fixture.root_reply = 1;
    return adfl_open_with(&fake_ops, &managed_fixture, requested, NULL, NULL, out);
}
ADFL_API int adfl_test_count(int kind) {
    switch (kind) {
        case 0: return atomic_load(&managed_fixture.sends);
        case 1: return atomic_load(&managed_fixture.closed);
        case 2: return atomic_load(&managed_fixture.freed);
        case 3: return atomic_load(&managed_fixture.results_freed);
        default: return -1;
    }
}
#endif
