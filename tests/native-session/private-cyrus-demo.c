/* Full pinned static Cyrus/plugin guard, no credentials or real GSS calls. */
#include <sasl.h>
#include <gssapi/gssapi.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Linker interception: an unexpected authentication attempt fails the test
 * before the real credential acquisition or context initiation can execute. */
OM_uint32 __wrap_gss_acquire_cred(OM_uint32 *minor, gss_name_t name,
    OM_uint32 time, gss_OID_set mechs, gss_cred_usage_t usage,
    gss_cred_id_t *credential, gss_OID_set *actual, OM_uint32 *lifetime) {
    (void)minor; (void)name; (void)time; (void)mechs; (void)usage;
    (void)credential; (void)actual; (void)lifetime; abort();
}
OM_uint32 __wrap_gss_init_sec_context(OM_uint32 *minor, gss_cred_id_t credential,
    gss_ctx_id_t *context, gss_name_t target, gss_OID mechanism,
    OM_uint32 flags, OM_uint32 time, gss_channel_bindings_t bindings,
    gss_buffer_t input, gss_OID *actual, gss_buffer_t output,
    OM_uint32 *returned_flags, OM_uint32 *lifetime) {
    (void)minor; (void)credential; (void)context; (void)target; (void)mechanism;
    (void)flags; (void)time; (void)bindings; (void)input; (void)actual;
    (void)output; (void)returned_flags; (void)lifetime; abort();
}

int main(void) {
    sasl_callback_t callbacks[] = {{SASL_CB_USER, NULL, NULL}, {SASL_CB_LIST_END, NULL, NULL}};
    assert(sasl_client_init(callbacks) == SASL_OK);
    for (int tls = 0; tls < 2; tls++) {
        sasl_conn_t *connection = NULL;
        assert(sasl_client_new("ldap", "directory.invalid", NULL, NULL, callbacks, 0, &connection) == SASL_OK);
        /* Exercise ordinary and external-protection/no-CI paths. Neither may
         * fall back to ambient acquisition when the credential is missing. */
        sasl_ssf_t external = tls ? 256 : 0;
        assert(sasl_setprop(connection, SASL_SSF_EXTERNAL, &external) == SASL_OK);
        sasl_interact_t *interaction = NULL;
        const char *output = NULL, *mechanism = NULL; unsigned length = 0;
        assert(sasl_client_start(connection, "GSSAPI", &interaction, &output, &length, &mechanism) == SASL_INTERACT);
        assert(interaction && interaction[0].id == SASL_CB_USER && interaction[1].id == SASL_CB_LIST_END);
        interaction[0].result = ""; interaction[0].len = 0;
        assert(sasl_client_start(connection, "GSSAPI", &interaction, &output, &length, &mechanism) == SASL_NOMECH);
        assert(strstr(sasl_errdetail(connection), "ADFL requires an explicit GSS credential"));
        sasl_dispose(&connection);
    }
    sasl_done();
    puts("PASS: full private static Cyrus/plugin requests interaction then refuses missing explicit credentials before GSS, with/without external protection.");
    return 0;
}
