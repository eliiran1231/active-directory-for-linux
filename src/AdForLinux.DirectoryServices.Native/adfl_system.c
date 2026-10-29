#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <sasl/sasl.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <sys/random.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Final private static linkage only: observe the actual context without changing
 * GSS flags, tokens or framing. No process-global symbol interposition. */
#ifdef ADFL_CAPTURE_CONTEXT_LIFETIME
static _Thread_local struct {
    int active;
    gss_cred_id_t expected;
    LDAP *completed;
    unsigned seconds;
} binding_scope __attribute__((tls_model("initial-exec")));
OM_uint32 __real_gss_init_sec_context(OM_uint32 *, gss_cred_id_t, gss_ctx_id_t *,
    gss_name_t, gss_OID, OM_uint32, OM_uint32, gss_channel_bindings_t,
    gss_buffer_t, gss_OID *, gss_buffer_t, OM_uint32 *, OM_uint32 *);
OM_uint32 __wrap_gss_init_sec_context(OM_uint32 *minor, gss_cred_id_t credential,
    gss_ctx_id_t *context, gss_name_t target, gss_OID mechanism, OM_uint32 flags,
    OM_uint32 requested, gss_channel_bindings_t bindings, gss_buffer_t input,
    gss_OID *actual, gss_buffer_t output, OM_uint32 *returned, OM_uint32 *time_rec) {
    OM_uint32 local_time = 0;
    if (binding_scope.active) binding_scope.seconds = 0;
    OM_uint32 major = __real_gss_init_sec_context(minor, credential, context,
        target, mechanism, flags, requested, bindings, input, actual, output,
        returned, time_rec ? time_rec : &local_time);
    if (binding_scope.active && credential != GSS_C_NO_CREDENTIAL &&
        credential == binding_scope.expected && major == GSS_S_COMPLETE) {
        OM_uint32 query_minor = 0, seconds = 0;
        if (gss_inquire_context(&query_minor, *context, NULL, NULL, &seconds,
                NULL, NULL, NULL, NULL) == GSS_S_COMPLETE && seconds && seconds != GSS_C_INDEFINITE)
            binding_scope.seconds = seconds;
    }
    return major;
}
#endif
unsigned adfl_system_bound_lifetime(LDAP *ld) {
#ifdef ADFL_CAPTURE_CONTEXT_LIFETIME
    unsigned seconds = binding_scope.completed == ld ? binding_scope.seconds : 0;
    memset(&binding_scope, 0, sizeof(binding_scope));
    return seconds;
#else
    (void)ld; return 0;
#endif
}

#ifndef ADFL_REVIEWED_MIT_1_21_3
#error Build requires the reviewed MIT 1.21.3 development package.
#endif
#if LDAP_VENDOR_VERSION != 20608 && LDAP_VENDOR_VERSION != 20610
#error This OpenLDAP header version has not been reviewed for callback credential injection.
#endif
#if SASL_VERSION_MAJOR != 2 || SASL_VERSION_MINOR != 1 || SASL_VERSION_STEP != 28
#error This Cyrus SASL header version has not been reviewed.
#endif

struct material {
    krb5_context context;
    krb5_ccache cache, owned_cache;
    krb5_principal principal;
    krb5_keytab empty_keytab;
    gss_cred_id_t credential;
};
static int probe(void *state, adfl_native_capabilities *out) {
    (void)state;
    memset(out, 0, sizeof(*out));
    LDAPAPIInfo api = {0}; api.ldapai_info_version = LDAP_API_INFO_VERSION;
    if (ldap_get_option(NULL, LDAP_OPT_API_INFO, &api) != LDAP_OPT_SUCCESS) return ADFL_UNSUPPORTED;
    out->openldap_version = api.ldapai_vendor_version;
    sasl_version_info(NULL, NULL, &out->cyrus_major, &out->cyrus_minor, &out->cyrus_step, NULL);
    out->reviewed_build = api.ldapai_vendor_name && !strcmp(api.ldapai_vendor_name, "OpenLDAP") &&
        api.ldapai_vendor_version == LDAP_VENDOR_VERSION &&
        out->cyrus_major == 2 && out->cyrus_minor == 1 && out->cyrus_step == 28;
    if (api.ldapai_extensions) ldap_memvfree((void **)api.ldapai_extensions);
    if (api.ldapai_vendor_name) ldap_memfree(api.ldapai_vendor_name);
    /* Intentionally hard-false, with no environment or caller override. Version
     * strings do not attest the loaded MIT/GSS plugin or guarantee interaction
     * before authentication. Refuse in orchestration BEFORE credential resolution.
     * A post-bind installation check cannot undo wrong-identity authentication. */
    out->authority_binding_enforced = 0;
    out->request_transport = 1; /* implementation exists; binding gate still refuses */
    /* Version is a reviewed-composition gate, not proof of installed GSS plugin
     * identity, callback timing or authentication. Set-option failures stay fatal. */
    return ADFL_OK;
}
static int material_new(void *state, void **out) {
    (void)state;
    struct material *m = calloc(1, sizeof(*m));
    *out = m;
    if (!m) return ADFL_NO_MEMORY;
    return krb5_init_context(&m->context) ? ADFL_RESOLVE_FAILED : ADFL_OK;
}
/* Only the inherited sealed descriptor is accepted. MIT parses the immutable
 * FILE image; all subsequent acquisition/cache writes use private MEMORY state. */
static int import_owned(struct material *m) {
    int fd = fcntl(6, F_DUPFD_CLOEXEC, 7);
    if (fd < 0) return ADFL_RESOLVE_FAILED;
    close(6); /* One import per isolated host; the private MEMORY cache owns future use. */
    struct stat st;
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0 || (seals & required) != required || fstat(fd, &st) ||
        !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 1048576) {
        close(fd); return ADFL_RESOLVE_FAILED;
    }
    char name[64]; snprintf(name, sizeof(name), "FILE:/proc/self/fd/%d", fd);
    krb5_ccache input = NULL;
    krb5_principal principal = NULL;
    char *owned_name = NULL;
    krb5_error_code rc = krb5_cc_resolve(m->context, name, &input);
    if (!rc) rc = krb5_cc_get_principal(m->context, input, &principal);
    if (!rc) rc = krb5_cc_new_unique(m->context, "MEMORY", NULL, &m->owned_cache);
    if (!rc) rc = krb5_cc_initialize(m->context, m->owned_cache, principal);
    if (!rc) rc = krb5_cc_copy_creds(m->context, input, m->owned_cache);
    if (!rc) rc = krb5_cc_get_full_name(m->context, m->owned_cache, &owned_name);
    if (!rc) rc = krb5_cc_set_default_name(m->context, owned_name);
    if (owned_name) krb5_free_string(m->context, owned_name);
    if (principal) krb5_free_principal(m->context, principal);
    if (input) krb5_cc_close(m->context, input);
    close(fd);
    return rc ? ADFL_RESOLVE_FAILED : ADFL_OK;
}
static int set_source(void *state, void *value, const adfl_credential_source *source) {
    (void)state; struct material *m = value;
    if (source->kind == ADFL_SOURCE_OWNED) return import_owned(m);
    size_t length = strlen(source->absolute_path);
    if (length > SIZE_MAX - 6) return ADFL_INVALID;
    char *name = malloc(length + 6);
    if (!name) return ADFL_NO_MEMORY;
    snprintf(name, length + 6, "%s%s", source->kind == ADFL_SOURCE_FILE ? "FILE:" : "DIR:", source->absolute_path);
    /* Context-local source selection; no environment mutation or cache copying. */
    krb5_error_code rc = krb5_cc_set_default_name(m->context, name);
    free(name); return rc ? ADFL_RESOLVE_FAILED : ADFL_OK;
}
static int check_source(void *state, void *value, const adfl_credential_source *source) {
    (void)state; struct material *m = value; char *name = NULL;
    if (krb5_cc_get_full_name(m->context, m->cache, &name)) return ADFL_RESOLVE_FAILED;
    int matches;
    if (source->kind == ADFL_SOURCE_OWNED) {
        char *owned_name = NULL;
        matches = m->owned_cache && !krb5_cc_get_full_name(m->context, m->owned_cache, &owned_name) &&
            !strcmp(name, owned_name);
        if (owned_name) krb5_free_string(m->context, owned_name);
    } else matches = adfl_source_matches(source, name);
    krb5_free_string(m->context, name);
    /* Lexical source check, not a filesystem sandbox, snapshot, or identity proof. */
    return matches ? ADFL_OK : ADFL_RESOLVE_FAILED;
}
static int select_target(void *state, void *value, const char *host) {
    (void)state; struct material *m = value;
    krb5_principal service = NULL;
    krb5_error_code rc = krb5_sname_to_principal(m->context, host, "ldap", KRB5_NT_SRV_HST, &service);
    if (rc) return ADFL_RESOLVE_FAILED;
    rc = krb5_cc_select(m->context, service, &m->cache, &m->principal);
    krb5_free_principal(m->context, service);
    if (rc == KRB5_CC_NOTFOUND) return m->principal || m->cache ? ADFL_SELECTED_CACHE_MISSING : ADFL_NO_SELECTION;
    if (rc || !m->cache || !m->principal) return ADFL_RESOLVE_FAILED;
    return ADFL_OK;
}
static int select_default(void *state, void *value) {
    (void)state; struct material *m = value;
    if (krb5_cc_default(m->context, &m->cache) ||
        krb5_cc_get_principal(m->context, m->cache, &m->principal)) return ADFL_RESOLVE_FAILED;
    return ADFL_OK;
}
static int make_empty_keytab(struct material *m, char name[80]) {
    unsigned char random[16];
    if (getrandom(random, sizeof(random), 0) != (ssize_t)sizeof(random)) return ADFL_RESOLVE_FAILED;
    strcpy(name, "MEMORY:adfl-no-initial-credentials-");
    size_t offset = strlen(name);
    for (size_t i = 0; i < sizeof(random); i++) snprintf(name + offset + 2 * i, 3, "%02x", random[i]);
    if (krb5_kt_resolve(m->context, name, &m->empty_keytab)) return ADFL_RESOLVE_FAILED;
    krb5_kt_cursor cursor;
    if (krb5_kt_start_seq_get(m->context, m->empty_keytab, &cursor)) return ADFL_RESOLVE_FAILED;
    krb5_keytab_entry entry = {0};
    krb5_error_code rc = krb5_kt_next_entry(m->context, m->empty_keytab, &entry, &cursor);
    if (!rc) krb5_free_keytab_entry_contents(m->context, &entry);
    krb5_error_code end = krb5_kt_end_seq_get(m->context, m->empty_keytab, &cursor);
    return rc == KRB5_KT_END && !end ? ADFL_OK : ADFL_RESOLVE_FAILED;
}
static int acquire_selected(void *state, void *value) {
    (void)state; struct material *m = value;
    char *cache_name = NULL, *principal_name = NULL;
    char keytab_name[80];
    gss_name_t desired = GSS_C_NO_NAME, actual = GSS_C_NO_NAME;
    OM_uint32 minor = 0, major, lifetime = 0;
    int rc = ADFL_RESOLVE_FAILED, same = 0;
    if (krb5_cc_get_full_name(m->context, m->cache, &cache_name) ||
        krb5_unparse_name(m->context, m->principal, &principal_name) ||
        make_empty_keytab(m, keytab_name)) goto done;
    gss_buffer_desc name = {strlen(principal_name), principal_name};
    major = gss_import_name(&minor, &name, GSS_KRB5_NT_PRINCIPAL_NAME, &desired);
    if (major != GSS_S_COMPLETE) goto done;
    gss_key_value_element_desc items[] = {{"ccache", cache_name}, {"client_keytab", keytab_name}};
    gss_key_value_set_desc store = {2, items};
    gss_OID_set_desc mechanisms = {1, gss_mech_krb5};
    major = gss_acquire_cred_from(&minor, desired, GSS_C_INDEFINITE, &mechanisms, GSS_C_INITIATE,
                                 &store, &m->credential, NULL, &lifetime);
    if (major != GSS_S_COMPLETE || !lifetime) goto done;
    major = gss_inquire_cred(&minor, m->credential, &actual, NULL, NULL, NULL);
    if (major != GSS_S_COMPLETE) goto done;
    major = gss_compare_name(&minor, desired, actual, &same);
    if (major == GSS_S_COMPLETE && same) rc = ADFL_OK;
    /* The handle references a mutable cache. Name equality is NOT a universal
     * compatibility/freshness proof, and never enables session pooling. */
done:
    if (actual != GSS_C_NO_NAME) gss_release_name(&minor, &actual);
    if (desired != GSS_C_NO_NAME) gss_release_name(&minor, &desired);
    if (cache_name) krb5_free_string(m->context, cache_name);
    if (principal_name) krb5_free_unparsed_name(m->context, principal_name);
    return rc;
}
static void *credential(void *state, void *value) {
    (void)state; return ((struct material *)value)->credential;
}
ADFL_API int adfl_owned_authority_lifetime(adfl_authority *authority, unsigned *seconds) {
    if (!authority || !seconds || authority->ops->material_new != adfl_system_ops.material_new) return ADFL_INVALID;
    *seconds = 0;
    struct material *m = authority->material;
    if (!m || !m->owned_cache || m->credential == GSS_C_NO_CREDENTIAL) return ADFL_UNSUPPORTED;
    OM_uint32 minor = 0, lifetime = 0;
    if (gss_inquire_cred(&minor, m->credential, NULL, &lifetime, NULL, NULL) != GSS_S_COMPLETE ||
        !lifetime || lifetime == GSS_C_INDEFINITE) return ADFL_RESOLVE_FAILED;
    *seconds = lifetime;
    return ADFL_OK;
}
static void material_free(void *state, void *value) {
    (void)state; struct material *m = value;
    if (!m) return;
    OM_uint32 minor;
    if (m->credential != GSS_C_NO_CREDENTIAL) gss_release_cred(&minor, &m->credential);
    if (m->empty_keytab) krb5_kt_close(m->context, m->empty_keytab);
    if (m->cache) krb5_cc_close(m->context, m->cache);
    if (m->owned_cache) krb5_cc_destroy(m->context, m->owned_cache);
    if (m->principal) krb5_free_principal(m->context, m->principal);
    if (m->context) krb5_free_context(m->context);
    free(m);
}
static int create_session(void *state, const adfl_native_profile *p, LDAP **out) {
    (void)state;
    char uri[280]; int protocol = LDAP_VERSION3;
    snprintf(uri, sizeof(uri), "ldap://%s:%u", p->host, p->port);
    if (ldap_initialize(out, uri) != LDAP_SUCCESS) return ADFL_BIND_FAILED;
    struct timeval timeout = {(long)p->timeout_seconds, 0};
    /* No requested policy is weakened: unsupported referrals/TLS have already
     * returned UNSUPPORTED. NOCANON aligns Cyrus's host with target resolution.
     * LDAP_OPT_RESTART is intentionally NOT treated as a reconnect control. */
    if (ldap_set_option(*out, LDAP_OPT_PROTOCOL_VERSION, &protocol) != LDAP_OPT_SUCCESS ||
        ldap_set_option(*out, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != LDAP_OPT_SUCCESS ||
        ldap_set_option(*out, LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON) != LDAP_OPT_SUCCESS ||
        ldap_set_option(*out, LDAP_OPT_NETWORK_TIMEOUT, &timeout) != LDAP_OPT_SUCCESS ||
        ldap_set_option(*out, LDAP_OPT_TIMEOUT, &timeout) != LDAP_OPT_SUCCESS ||
        ldap_set_option(*out, LDAP_OPT_X_SASL_SECPROPS, p->sealing ? "minssf=56,maxssf=256" : "minssf=1,maxssf=256") != LDAP_OPT_SUCCESS)
        return ADFL_BIND_FAILED;
    return ADFL_OK;
}
static int set_credential(void *state, LDAP *ld, void *cred) {
    (void)state;
#ifdef ADFL_CAPTURE_CONTEXT_LIFETIME
    if (binding_scope.active) binding_scope.expected = cred;
#endif
    return ldap_set_option(ld, LDAP_OPT_X_SASL_GSS_CREDS, cred);
}
static int bind_session(void *state, LDAP *ld, LDAP_SASL_INTERACT_PROC *callback, void *defaults) {
    (void)state;
#ifdef ADFL_CAPTURE_CONTEXT_LIFETIME
    if (binding_scope.active) return LDAP_LOCAL_ERROR;
    memset(&binding_scope, 0, sizeof(binding_scope)); binding_scope.active = 1;
#endif
    int rc = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL, LDAP_SASL_QUIET, callback, defaults);
#ifdef ADFL_CAPTURE_CONTEXT_LIFETIME
    binding_scope.active = 0; binding_scope.expected = GSS_C_NO_CREDENTIAL;
    if (rc == LDAP_SUCCESS) binding_scope.completed = ld;
    else memset(&binding_scope, 0, sizeof(binding_scope));
#endif
    return rc;
}
static void ldap_close(void *state, LDAP *ld) {
    (void)state; if (ld) ldap_unbind_ext_s(ld, NULL, NULL);
}
static int install_connection_guard(void *state, LDAP *ld, ldap_conncb *guard) {
    (void)state; return ldap_set_option(ld, LDAP_OPT_CONNECT_CB, guard);
}
const adfl_native_ops adfl_system_ops = {
    probe, material_new, select_target, select_default, acquire_selected, credential, material_free,
    create_session, set_credential, bind_session, ldap_close, install_connection_guard,
    adfl_system_search_start, adfl_system_search_poll, adfl_system_result_emit,
    adfl_system_result_free, adfl_system_abandon, adfl_system_monotonic_ms,
    adfl_system_page_start, adfl_system_message_poll, adfl_system_message_emit,
    adfl_system_page_cookie, adfl_system_write_start, set_source, check_source
};
