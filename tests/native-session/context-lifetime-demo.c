/* Exercise the production observer with synthetic GSS functions only. */
#define ADFL_CAPTURE_CONTEXT_LIFETIME
#define gss_inquire_context recording_inquire_context
#include "../../src/AdForLinux.DirectoryServices.Native/adfl_system.c"
#include <assert.h>

static OM_uint32 result = GSS_S_COMPLETE, query_result = GSS_S_COMPLETE, lifetime = 42;
static unsigned calls;
OM_uint32 __real_gss_init_sec_context(OM_uint32 *minor, gss_cred_id_t cred,
    gss_ctx_id_t *context, gss_name_t target, gss_OID mechanism, OM_uint32 flags,
    OM_uint32 requested, gss_channel_bindings_t bindings, gss_buffer_t input,
    gss_OID *actual, gss_buffer_t output, OM_uint32 *returned, OM_uint32 *time_rec) {
    (void)minor; (void)cred; (void)target; (void)mechanism; (void)bindings;
    (void)input; (void)actual; (void)output; (void)returned;
    assert(flags == 123 && requested == 7 && time_rec);
    *time_rec = 999; *context = (gss_ctx_id_t)(uintptr_t)2; calls++;
    return result;
}
OM_uint32 recording_inquire_context(OM_uint32 *minor, gss_ctx_id_t context,
    gss_name_t *source, gss_name_t *target, OM_uint32 *seconds, gss_OID *mechanism,
    OM_uint32 *flags, int *local, int *open) {
    (void)minor; (void)source; (void)target; (void)mechanism; (void)flags; (void)local; (void)open;
    assert(context == (gss_ctx_id_t)(uintptr_t)2); *seconds = lifetime; return query_result;
}
static void invoke(gss_cred_id_t cred) {
    OM_uint32 minor = 0; gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    assert(__wrap_gss_init_sec_context(&minor, cred, &context, GSS_C_NO_NAME,
        GSS_C_NO_OID, 123, 7, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
        NULL, GSS_C_NO_BUFFER, NULL, NULL) == result);
}
int main(void) {
    gss_cred_id_t expected = (gss_cred_id_t)(uintptr_t)1;
    binding_scope.active = 1; binding_scope.expected = expected;
    invoke(expected); assert(binding_scope.seconds == 42);
    invoke(GSS_C_NO_CREDENTIAL); assert(binding_scope.seconds == 0);
    lifetime = GSS_C_INDEFINITE; invoke(expected); assert(binding_scope.seconds == 0);
    lifetime = 42; query_result = GSS_S_FAILURE; invoke(expected); assert(binding_scope.seconds == 0);
    query_result = GSS_S_COMPLETE; result = GSS_S_CONTINUE_NEEDED;
    invoke(expected); assert(binding_scope.seconds == 0);
    result = GSS_S_COMPLETE; invoke(expected); assert(binding_scope.seconds == 42);
    binding_scope.active = 0; binding_scope.completed = (LDAP *)(uintptr_t)3;
    assert(adfl_system_bound_lifetime((LDAP *)(uintptr_t)3) == 42);
    assert(adfl_system_bound_lifetime((LDAP *)(uintptr_t)3) == 0);
    assert(calls == 6);
    puts("PASS: actual context observer rejects mismatched, indefinite, failed and incomplete synthetic contexts; no GSS authentication invoked.");
    return 0;
}
