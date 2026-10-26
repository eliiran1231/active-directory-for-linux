/* Metadata-only probe used exclusively by the recording worker executable. */
#define _POSIX_C_SOURCE 200809L
#include <krb5.h>
#include <profile.h>
#include <gssapi/gssapi.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static unsigned profile_reads;
FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode) {
    if (strcmp(path, "/proc/self/fd/4") && strcmp(path, "/proc/self/fd/5")) abort();
    if (strcmp(mode, "r") && strcmp(mode, "r+")) abort();
    if (!strcmp(path, "/proc/self/fd/4")) profile_reads++;
    return __real_fopen(path, mode);
}
/* A profile/metadata check must not load arbitrary modules or contact a peer. */
void *__wrap_dlopen(const char *name, int flags) { (void)name; (void)flags; abort(); }
int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    (void)fd; (void)address; (void)length; abort();
}
int __wrap_getaddrinfo(const char *name, const char *service,
    const struct addrinfo *hints, struct addrinfo **result) {
    (void)name; (void)service; (void)hints; (void)result; abort();
}
__attribute__((visibility("default"))) int adfl_test_private_profile(void) {
    const char *config = getenv("KRB5_CONFIG"), *mechs = getenv("GSS_MECH_CONFIG");
    if (!config || strcmp(config, "/proc/self/fd/4") || !mechs || strcmp(mechs, "/proc/self/fd/5")) return 1;
    krb5_context context = NULL; char *realm = NULL, *selector = NULL; profile_t profile = NULL;
    int rc = 2;
    if (krb5_init_context(&context) || krb5_get_default_realm(context, &realm) ||
        strcmp(realm, "EXAMPLE.INVALID") || krb5_get_profile(context, &profile) ||
        profile_get_string(profile, "plugins", "ccselect", "enable_only", NULL, &selector) ||
        !selector || strcmp(selector, "realm")) goto done;
    OM_uint32 minor; gss_OID_set mechanisms = GSS_C_NO_OID_SET;
    /* Mechanism enumeration, not credential acquisition or context initiation. */
    if (gss_indicate_mechs(&minor, &mechanisms) != GSS_S_COMPLETE || !mechanisms) goto done;
    rc = mechanisms->count && profile_reads ? 0 : 3;
    gss_release_oid_set(&minor, &mechanisms);
done:
    if (selector) profile_release_string(selector);
    if (profile) profile_release(profile);
    if (realm) krb5_free_default_realm(context, realm);
    if (context) krb5_free_context(context);
    return rc;
}
