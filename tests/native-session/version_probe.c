#include "adfl_native.h"
#include <stdio.h>
int main(void) {
    if (adfl_native_abi_version() != 3) return 5;
    adfl_native_capabilities c;
    if (adfl_native_probe(&c)) return 1;
    printf("OpenLDAP=%d Cyrus=%d.%d.%d reviewed-build=%d binding-enforced=%d request-transport=%d session-reuse=%d\n",
        c.openldap_version, c.cyrus_major, c.cyrus_minor, c.cyrus_step, c.reviewed_build, c.authority_binding_enforced,
        c.request_transport, c.compatible_session_reuse);
    adfl_native_profile p = {"directory.invalid", 389, 5, 0, 0, 1, 1};
    adfl_bound_session *session = NULL;
    if (adfl_operation_open(&p, NULL, NULL, &session) != ADFL_UNSUPPORTED || session) return 3;
    adfl_credential_source source = {ADFL_SOURCE_FILE, "/adfl-synthetic-not-a-cache"};
    adfl_authority *authority = NULL;
    if (adfl_authority_resolve_from(&p, &source, NULL, NULL, &authority) != ADFL_UNSUPPORTED || authority) return 4;
    puts("Pre-auth gate refuses before native credential resolution. Version metadata only. No native credential acquisition or authentication tested.");
    return c.reviewed_build ? 0 : 2;
}
