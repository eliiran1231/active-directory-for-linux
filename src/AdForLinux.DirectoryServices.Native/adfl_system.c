#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <sasl/sasl.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <sys/random.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    krb5_ccache cache;
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
static int set_source(void *state, void *value, const adfl_credential_source *source) {
    (void)state; struct material *m = value;
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
    int matches = adfl_source_matches(source, name);
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
static void material_free(void *state, void *value) {
    (void)state; struct material *m = value;
    if (!m) return;
    OM_uint32 minor;
    if (m->credential != GSS_C_NO_CREDENTIAL) gss_release_cred(&minor, &m->credential);
    if (m->empty_keytab) krb5_kt_close(m->context, m->empty_keytab);
    if (m->cache) krb5_cc_close(m->context, m->cache);
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
    (void)state; return ldap_set_option(ld, LDAP_OPT_X_SASL_GSS_CREDS, cred);
}
static int bind_session(void *state, LDAP *ld, LDAP_SASL_INTERACT_PROC *callback, void *defaults) {
    (void)state;
    return ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL, LDAP_SASL_QUIET, callback, defaults);
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
