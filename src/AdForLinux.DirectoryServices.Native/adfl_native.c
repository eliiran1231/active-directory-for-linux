#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <sasl/sasl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct interaction {
    adfl_authority *authority;
    adfl_cancelled_fn cancelled;
    void *cancel_state;
    int installed, failed;
};
static int cancelled(adfl_cancelled_fn check, void *state) { return check && check(state); }
static int validate(const adfl_native_profile *p) {
    if (!p || !p->host || !p->host[0] || !p->port || p->port > 65535 ||
        !p->timeout_seconds || p->timeout_seconds > 3600) return ADFL_INVALID;
    size_t n = strlen(p->host);
    if (n > 253) return ADFL_INVALID;
    /* A single exact DNS target, no URI escaping, address lists or SRV discovery. */
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p->host[i];
        if (c == '.') {
            if (!label || p->host[i - 1] == '-') return ADFL_INVALID;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) return ADFL_INVALID;
            if ((!label && c == '-') || ++label > 63) return ADFL_INVALID;
        }
    }
    if (!label || p->host[n - 1] == '-') return ADFL_INVALID;
    if (p->referrals || p->tls || (!p->signing && !p->sealing)) return ADFL_UNSUPPORTED;
    return ADFL_OK;
}
static void release(adfl_authority *a) {
    if (atomic_fetch_sub(&a->references, 1) != 1) return;
    a->ops->material_free(a->state, a->material);
    free(a->target); free(a);
}
void adfl_authority_close(adfl_authority **owner) {
    if (owner && *owner) { adfl_authority *a = *owner; *owner = NULL; release(a); }
}
void adfl_session_retain(adfl_bound_session *s) { atomic_fetch_add(&s->references, 1); }
void adfl_session_release(adfl_bound_session *s) {
    if (atomic_fetch_sub(&s->references, 1) != 1) return;
    s->authority->ops->ldap_close(s->authority->state, s->ldap);
    release(s->authority); free(s);
}
void adfl_session_close(adfl_bound_session **owner) {
    if (!owner || !*owner) return;
    adfl_bound_session *s = *owner; *owner = NULL; adfl_session_release(s);
}
int adfl_source_validate(const adfl_credential_source *source) {
    if (!source) return ADFL_INVALID;
    if (source->kind == ADFL_SOURCE_OWNED)
        return source->absolute_path && !strcmp(source->absolute_path, "/proc/self/fd/6") ? ADFL_OK : ADFL_INVALID;
    if (source->kind != ADFL_SOURCE_FILE && source->kind != ADFL_SOURCE_DIR) return ADFL_UNSUPPORTED;
    const char *path = source->absolute_path;
    if (!path || path[0] != '/' || !path[1] || strlen(path) > 4096) return ADFL_INVALID;
    const char *component = path + 1;
    for (const char *p = component;; p++) {
        if (*p != '/' && *p) continue;
        size_t length = (size_t)(p - component);
        if (!length || (length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.')) return ADFL_INVALID;
        if (!*p) break;
        component = p + 1;
    }
    return ADFL_OK;
}
int adfl_source_matches(const adfl_credential_source *source, const char *name) {
    if (adfl_source_validate(source) != ADFL_OK || !name || source->kind == ADFL_SOURCE_OWNED) return 0;
    const char *prefix = source->kind == ADFL_SOURCE_FILE ? "FILE:" : "DIR::";
    size_t prefix_length = strlen(prefix), path_length = strlen(source->absolute_path);
    if (strncmp(name, prefix, prefix_length)) return 0;
    const char *path = name + prefix_length;
    if (source->kind == ADFL_SOURCE_FILE) return !strcmp(path, source->absolute_path);
    if (strncmp(path, source->absolute_path, path_length) || path[path_length] != '/') return 0;
    const char *child = path + path_length + 1;
    return *child && !strchr(child, '/') && strcmp(child, ".") && strcmp(child, "..");
}
static int resolve(const adfl_native_ops *ops, void *state, const adfl_native_profile *p,
                     const adfl_credential_source *source, adfl_cancelled_fn check, void *cancel_state, adfl_authority **out);
int adfl_resolve_with(const adfl_native_ops *ops, void *state, const adfl_native_profile *p,
                     adfl_cancelled_fn check, void *cancel_state, adfl_authority **out) {
    return resolve(ops, state, p, NULL, check, cancel_state, out);
}
int adfl_resolve_from_with(const adfl_native_ops *ops, void *state, const adfl_native_profile *p,
                     const adfl_credential_source *source, adfl_cancelled_fn check, void *cancel_state, adfl_authority **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    int rc = adfl_source_validate(source);
    return rc ? rc : resolve(ops, state, p, source, check, cancel_state, out);
}
static int resolve(const adfl_native_ops *ops, void *state, const adfl_native_profile *p,
                     const adfl_credential_source *source, adfl_cancelled_fn check, void *cancel_state, adfl_authority **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    int rc = validate(p);
    if (rc) return rc;
    if (cancelled(check, cancel_state)) return ADFL_CANCELLED;
    adfl_native_capabilities caps = {0};
    if (ops->probe(state, &caps) || !caps.reviewed_build || !caps.authority_binding_enforced) return ADFL_UNSUPPORTED;
    if (source && (!ops->set_source || !ops->check_source)) return ADFL_UNSUPPORTED;
    adfl_authority *a = calloc(1, sizeof(*a));
    if (!a) return ADFL_NO_MEMORY;
    atomic_init(&a->references, 1); a->ops = ops; a->state = state;
    a->target = strdup(p->host);
    if (!a->target) { free(a); return ADFL_NO_MEMORY; }
    rc = ops->material_new(state, &a->material);
    if (!rc && source) rc = ops->set_source(state, a->material, source);
    if (!rc) rc = ops->select_target(state, a->material, p->host);
    if (rc == ADFL_NO_SELECTION) rc = ops->select_default(state, a->material);
    if (!rc && cancelled(check, cancel_state)) rc = ADFL_CANCELLED;
    if (!rc && source) rc = ops->check_source(state, a->material, source);
    if (!rc && cancelled(check, cancel_state)) rc = ADFL_CANCELLED;
    if (!rc) rc = ops->acquire_selected(state, a->material);
    if (!rc && !ops->credential(state, a->material)) rc = ADFL_RESOLVE_FAILED;
    if (!rc && cancelled(check, cancel_state)) rc = ADFL_CANCELLED;
    if (rc) { release(a); return rc; }
    *out = a; return ADFL_OK;
}
static int interact(LDAP *ld, unsigned flags, void *defaults, void *prompts) {
    (void)flags;
    struct interaction *i = defaults;
    if (cancelled(i->cancelled, i->cancel_state)) { i->failed = 1; return LDAP_USER_CANCELLED; }
    sasl_interact_t *prompt = prompts;
    if (!prompt || prompt->id != SASL_CB_USER || prompt[1].id != SASL_CB_LIST_END) {
        i->failed = 1; return LDAP_PARAM_ERROR;
    }
    adfl_authority *a = i->authority;
    /* Handle VALUE, never &handle. Pinned Cyrus requests USER before GSS init;
     * OpenLDAP has created the SASL context before invoking this callback. */
    if (a->ops->set_credential(a->state, ld, a->ops->credential(a->state, a->material)) != LDAP_OPT_SUCCESS) {
        i->failed = 1; return LDAP_LOCAL_ERROR;
    }
    i->installed = 1;
    prompt->result = ""; prompt->len = 0; /* no delegated authorization identity */
    return LDAP_SUCCESS;
}
static int connected(LDAP *ld, Sockbuf *sb, LDAPURLDesc *server, struct sockaddr *address, ldap_conncb *cb) {
    (void)ld; (void)sb; (void)address;
    adfl_bound_session *s = cb->lc_arg;
    /* OpenLDAP invokes this under native locks. Never reenter LDAP here. */
    if (atomic_fetch_add(&s->connection_count, 1) != 0 || atomic_load(&s->retired) ||
        !server || !server->lud_host || !server->lud_scheme ||
        strcmp(server->lud_scheme, "ldap") || strcmp(server->lud_host, s->authority->target) ||
        server->lud_port != (int)s->port) {
        atomic_store(&s->retired, 1); return LDAP_CONNECT_ERROR;
    }
    return LDAP_SUCCESS;
}
static void disconnected(LDAP *ld, Sockbuf *sb, ldap_conncb *cb) {
    (void)ld; (void)sb;
    atomic_store(&((adfl_bound_session *)cb->lc_arg)->retired, 1);
}
int adfl_authority_bind(adfl_authority *a, const adfl_native_profile *p,
                       adfl_cancelled_fn check, void *cancel_state, adfl_bound_session **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    int rc = validate(p);
    if (rc) return rc;
    if (!a) return ADFL_INVALID;
    if (strcmp(a->target, p->host)) return ADFL_TARGET_MISMATCH;
    if (cancelled(check, cancel_state)) return ADFL_CANCELLED;
    adfl_bound_session *s = calloc(1, sizeof(*s));
    if (!s) return ADFL_NO_MEMORY;
    atomic_init(&s->references, 1);
    s->authority = a; s->port = p->port;
    atomic_init(&s->connection_count, 0); atomic_init(&s->retired, 0); atomic_init(&s->busy, 0);
    s->connection_guard = (ldap_conncb){connected, disconnected, s};
    atomic_fetch_add(&a->references, 1);
    rc = a->ops->ldap_create(a->state, p, &s->ldap);
    if (!rc && a->ops->install_connection_guard(a->state, s->ldap, &s->connection_guard) != LDAP_OPT_SUCCESS)
        rc = ADFL_BIND_FAILED;
    if (!rc && cancelled(check, cancel_state)) rc = ADFL_CANCELLED;
    struct interaction i = {a, check, cancel_state, 0, 0};
    if (!rc && (a->ops->bind(a->state, s->ldap, interact, &i) != LDAP_SUCCESS || !i.installed || i.failed))
        rc = ADFL_BIND_FAILED;
    if (!rc && (atomic_load(&s->connection_count) != 1 || atomic_load(&s->retired))) rc = ADFL_BIND_FAILED;
    if (!rc && a->ops->material_new == adfl_system_ops.material_new)
        s->context_lifetime = adfl_system_bound_lifetime(s->ldap);
    if (cancelled(check, cancel_state)) rc = ADFL_CANCELLED;
    if (rc) { adfl_session_close(&s); return rc; }
    *out = s; return ADFL_OK;
}
ADFL_API int adfl_owned_session_lifetime(adfl_bound_session *session, unsigned *seconds) {
    if (!session || !seconds || !session->context_lifetime) return ADFL_UNSUPPORTED;
    *seconds = session->context_lifetime;
    return ADFL_OK;
}
int adfl_open_with(const adfl_native_ops *ops, void *state, const adfl_native_profile *p,
                   adfl_cancelled_fn check, void *cancel_state, adfl_bound_session **out) {
    if (!out) return ADFL_INVALID;
    *out = NULL;
    adfl_authority *a = NULL;
    int rc = adfl_resolve_with(ops, state, p, check, cancel_state, &a);
    if (!rc) rc = adfl_authority_bind(a, p, check, cancel_state, out);
    adfl_authority_close(&a); return rc;
}
int adfl_authority_resolve(const adfl_native_profile *p, adfl_cancelled_fn c, void *s, adfl_authority **out) {
    return adfl_resolve_with(&adfl_system_ops, NULL, p, c, s, out);
}
int adfl_authority_resolve_from(const adfl_native_profile *p, const adfl_credential_source *source,
    adfl_cancelled_fn c, void *s, adfl_authority **out) {
    return adfl_resolve_from_with(&adfl_system_ops, NULL, p, source, c, s, out);
}
int adfl_operation_open(const adfl_native_profile *p, adfl_cancelled_fn c, void *s, adfl_bound_session **out) {
    return adfl_open_with(&adfl_system_ops, NULL, p, c, s, out);
}
int adfl_native_probe(adfl_native_capabilities *out) {
    return out ? adfl_system_ops.probe(NULL, out) : ADFL_INVALID;
}

/* Harmless ABI handshake: no library initialization or credential access. */
unsigned adfl_native_abi_version(void) { return 4; }
