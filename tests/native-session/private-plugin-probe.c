/* Exercise actual private MIT module entry points; never acquire credentials. */
#include "k5-int.h"
#include "k5-plugin.h"
#include <krb5/ccselect_plugin.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

extern krb5_error_code ccselect_realm_initvt(krb5_context, int, int, krb5_plugin_vtable);
/* Linker traps are defense in depth; archive/bridge symbol checks establish the
 * production build has no loader references, without relying on these traps. */
void *__wrap_dlopen(const char *name, int flags) { (void)name; (void)flags; abort(); }
void *__wrap_dlsym(void *handle, const char *name) { (void)handle; (void)name; abort(); }
int main(int argc, char **argv) {
    assert(argc == 4); /* module, directory, dynamic-profile configuration */
    struct errinfo error = {0};
    struct plugin_file_handle *handle = NULL;
    assert(krb5int_open_plugin(argv[1], &handle, &error) == ENOENT && handle == NULL);
    k5_clear_error(&error);
    const char *directories[] = {argv[2], NULL};
    struct plugin_dir_handle dir = {0};
    assert(krb5int_open_plugin_dirs(directories, NULL, &dir, &error) == 0);
    assert(dir.files && dir.files[0] == NULL);
    krb5int_close_plugin_dirs(&dir); k5_clear_error(&error);
    const char *files[] = {argv[3], NULL}; profile_t dynamic = NULL;
    assert(profile_init_flags(files, PROFILE_INIT_ALLOW_MODULE, &dynamic) == ENOENT && dynamic == NULL);

    krb5_context context = NULL;
    assert(krb5_init_context(&context) == 0);
    /* Register/load the actual built-in realm selector, without calling choose,
     * which would inspect caches. Also exercise the modern dynamic-module path. */
    assert(k5_plugin_register(context, PLUGIN_INTERFACE_CCSELECT, "realm", ccselect_realm_initvt) == 0);
    krb5_plugin_initvt_fn *modules = NULL;
    assert(k5_plugin_load_all(context, PLUGIN_INTERFACE_CCSELECT, &modules) == 0);
    assert(modules && modules[0] == ccselect_realm_initvt && modules[1] == NULL);
    struct krb5_ccselect_vtable_st table = {0};
    assert(modules[0](context, 1, 1, (krb5_plugin_vtable)&table) == 0);
    assert(table.name && strcmp(table.name, "realm") == 0 && table.choose);
    k5_plugin_free_modules(context, modules);
    OM_uint32 minor; gss_OID_set mechanisms = GSS_C_NO_OID_SET;
    assert(gss_indicate_mechs(&minor, &mechanisms) == GSS_S_COMPLETE && mechanisms);
    int has_kerberos = 0;
    assert(gss_test_oid_set_member(&minor, gss_mech_krb5, mechanisms, &has_kerberos) == GSS_S_COMPLETE);
    assert(has_kerberos);
    gss_release_oid_set(&minor, &mechanisms);
    krb5_free_context(context);
    puts("PASS: actual MIT direct/directory/profile/modern plugin paths cannot load modules; built-in realm selector and Kerberos GSS metadata remain available. No credentials/authentication.");
    return 0;
}
