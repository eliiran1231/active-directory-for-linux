/* Actual coordinator + private OpenLDAP/Cyrus; synthetic GSS boundary only. */
#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <openldap.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int peer = -1, wire = -1, calls, names, releases;
static int fake_name, identities[2];
static void *expected;
struct fixture { void *credential; unsigned freed; };
static int probe(void *s, adfl_native_capabilities *c) {
    (void)s; memset(c, 0, sizeof(*c)); c->reviewed_build = 1; c->authority_binding_enforced = 1; return 0;
}
static int material(void *s, void **m) { *m = s; return 0; }
static int select_target(void *s, void *m, const char *h) {
    assert(s == m && !strcmp(h, "directory.invalid")); return 0;
}
static int forbidden_default(void *s, void *m) { (void)s; (void)m; abort(); }
static int acquire(void *s, void *m) { assert(s == m); return 0; }
static void *credential(void *s, void *m) { assert(s == m); return ((struct fixture *)s)->credential; }
static void free_material(void *s, void *m) { assert(s == m); ((struct fixture *)s)->freed++; }
static int create(void *s, const adfl_native_profile *p, LDAP **ld) {
    (void)s; assert(peer == -1); int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    wire = sockets[0]; peer = sockets[1];
    assert(ldap_init_fd(wire, LDAP_PROTO_IPC, "ldap://directory.invalid:389", ld) == LDAP_SUCCESS);
    int version = LDAP_VERSION3;
    assert(p->signing && p->sealing);
    assert(ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS);
    assert(ldap_set_option(*ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) == LDAP_OPT_SUCCESS);
    assert(ldap_set_option(*ld, LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON) == LDAP_OPT_SUCCESS);
    assert(ldap_set_option(*ld, LDAP_OPT_X_SASL_SECPROPS, "minssf=56,maxssf=256") == LDAP_OPT_SUCCESS);
    return 0;
}
/* No connection, name lookup or real credential acquisition can escape. */
int __wrap_connect(int fd, const struct sockaddr *a, socklen_t n) { (void)fd; (void)a; (void)n; abort(); }
int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
    (void)hints; char hostname[256]; assert(gethostname(hostname, sizeof(hostname)) == 0);
    assert(node && !strcmp(node, hostname) && !service);
    *result = NULL; return EAI_NONAME; /* Cyrus local-host discovery: no DNS. */
}
OM_uint32 __wrap_gss_release_cred(OM_uint32 *minor, gss_cred_id_t *credential) {
    (void)minor; (void)credential; fputs("release cred\n",stderr); abort();
}
OM_uint32 __wrap_gss_delete_sec_context(OM_uint32 *minor, gss_ctx_id_t *context, gss_buffer_t output) {
    (void)minor; (void)context; (void)output; fputs("delete context\n",stderr); abort();
}
OM_uint32 __wrap_gss_acquire_cred(OM_uint32 *m, gss_name_t n, OM_uint32 t, gss_OID_set o,
    gss_cred_usage_t u, gss_cred_id_t *c, gss_OID_set *a, OM_uint32 *l) {
    (void)m;(void)n;(void)t;(void)o;(void)u;(void)c;(void)a;(void)l; abort();
}
OM_uint32 __wrap_gss_acquire_cred_from(OM_uint32 *m, gss_name_t n, OM_uint32 t, gss_OID_set o,
    gss_cred_usage_t u, gss_const_key_value_set_t k, gss_cred_id_t *c, gss_OID_set *a, OM_uint32 *l) {
    (void)m;(void)n;(void)t;(void)o;(void)u;(void)k;(void)c;(void)a;(void)l; abort();
}
OM_uint32 __wrap_gss_import_name(OM_uint32 *m, gss_buffer_t b, gss_OID type, gss_name_t *n) {
    (void)type; const char target[] = "ldap@directory.invalid";
    assert(b->length == sizeof(target)-1 && !memcmp(b->value, target, b->length));
    *m = 0; *n = (gss_name_t)&fake_name; names++; return GSS_S_COMPLETE;
}
OM_uint32 __wrap_gss_release_name(OM_uint32 *m, gss_name_t *n) {
    assert(*n == (gss_name_t)&fake_name); *m = 0; *n = GSS_C_NO_NAME; releases++; return GSS_S_COMPLETE;
}
OM_uint32 __wrap_gss_display_status(OM_uint32 *m, OM_uint32 value, int type, gss_OID mech,
    OM_uint32 *context, gss_buffer_t buffer) {
    (void)value;(void)type;(void)mech; *m = 0; *context = 0;
    buffer->value = (void *)"synthetic failure"; buffer->length = 17; return GSS_S_COMPLETE;
}
OM_uint32 __wrap_gss_release_buffer(OM_uint32 *m, gss_buffer_t b) {
    *m = 0; b->value = NULL; b->length = 0; return GSS_S_COMPLETE;
}
OM_uint32 __wrap_gss_init_sec_context(OM_uint32 *m, gss_cred_id_t c, gss_ctx_id_t *context,
    gss_name_t target, gss_OID mech, OM_uint32 flags, OM_uint32 time, gss_channel_bindings_t bindings,
    gss_buffer_t input, gss_OID *actual, gss_buffer_t output, OM_uint32 *returned, OM_uint32 *life) {
    (void)mech;(void)time;(void)bindings;(void)input;(void)actual;(void)life;
    assert((void *)c == expected && target == (gss_name_t)&fake_name);
    assert(*context == GSS_C_NO_CONTEXT && (flags & GSS_C_CONF_FLAG));
    char byte; assert(recv(peer, &byte, 1, MSG_DONTWAIT) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    /* Failure returns no token. Shut down before production cleanup can send
     * its unrelated UnbindRequest; the peer must see EOF and no LDAP bytes. */
    assert(shutdown(wire, SHUT_RDWR) == 0);
    *m = 0; output->value = NULL; output->length = 0; *returned = 0; calls++;
    return GSS_S_FAILURE;
}
int main(void) {
    signal(SIGPIPE, SIG_IGN);
    adfl_native_ops ops = adfl_system_ops;
    ops.probe=probe; ops.material_new=material; ops.select_target=select_target;
    ops.select_default=forbidden_default; ops.acquire_selected=acquire; ops.credential=credential;
    ops.material_free=free_material; ops.ldap_create=create;
    adfl_native_profile p = {.host="directory.invalid", .port=389, .timeout_seconds=2, .signing=1, .sealing=1};
    struct fixture fixtures[2] = {{&identities[0],0},{&identities[1],0}};
    adfl_authority *owners[2] = {NULL,NULL};
    for (int i=0;i<2;i++) assert(adfl_resolve_with(&ops,&fixtures[i],&p,NULL,NULL,&owners[i]) == ADFL_OK);
    /* Interleave two live authorities, including replacement binds per owner. */
    for (int i=0;i<4;i++) {
        expected=fixtures[i%2].credential; int before=calls; adfl_bound_session *session=NULL;
        assert(adfl_authority_bind(owners[i%2],&p,NULL,NULL,&session) == ADFL_BIND_FAILED);
        assert(!session && calls == before+1 && names == calls && releases == calls);
        char byte; assert(recv(peer,&byte,1,MSG_DONTWAIT) == 0); close(peer); peer=-1; wire=-1;
        assert(!fixtures[0].freed && !fixtures[1].freed);
    }
    for (int i=0;i<2;i++) { adfl_authority_close(&owners[i]); assert(fixtures[i].freed==1); }
    puts("PASS: production bind coordinator/private LDAP+Cyrus delivers exact synthetic authority handle to GSS; four failing binds, zero LDAP bytes, owned cleanup. No real GSS/authentication.");
    return 0;
}
