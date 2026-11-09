#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <stdlib.h>
#include <string.h>

int adfl_controls_valid(const adfl_control *controls, size_t count) {
    if ((count && !controls) || count > SIZE_MAX / sizeof(LDAPControl *) - 2 ||
        count > SIZE_MAX / sizeof(adfl_control)) return 0;
    for (size_t i = 0; i < count; i++) {
        const adfl_control *c = &controls[i];
        if (!c->oid || !c->oid[0] || c->critical > 1 || c->has_value > 1 ||
            (!c->has_value && (c->value.length || c->value.data)) || (c->value.length && !c->value.data)) return 0;
    }
    return 1;
}
void adfl_controls_free(adfl_control *controls, size_t count) {
    if (!controls) return;
    for (size_t i = 0; i < count; i++) { free((void *)controls[i].oid); free((void *)controls[i].value.data); }
    free(controls);
}
int adfl_controls_copy(const adfl_control *source, size_t count, adfl_control **out) {
    *out = NULL;
    if (!adfl_controls_valid(source, count)) return ADFL_INVALID;
    if (!count) return ADFL_OK;
    adfl_control *copy = calloc(count, sizeof(*copy));
    if (!copy) return ADFL_NO_MEMORY;
    for (size_t i = 0; i < count; i++) {
        copy[i] = source[i]; copy[i].oid = strdup(source[i].oid); copy[i].value.data = NULL;
        if (!copy[i].oid) goto failed;
        if (copy[i].value.length) {
            void *bytes = malloc(copy[i].value.length);
            if (!bytes) goto failed;
            memcpy(bytes, source[i].value.data, copy[i].value.length); copy[i].value.data = bytes;
        }
    }
    *out = copy; return ADFL_OK;
failed:
    adfl_controls_free(copy, count); return ADFL_NO_MEMORY;
}
void adfl_controls_release(LDAPControl **controls, size_t count) {
    if (!controls) return;
    for (size_t i = 0; i < count; i++) free(controls[i]);
    free(controls);
}
/* Descriptors borrow input bytes for the synchronous libldap send call. The
 * optional extra control is owned by the caller, not this allocation. Even an
 * empty request returns [NULL], avoiding OpenLDAP handle-default inheritance. */
int adfl_controls_build(const adfl_control *source, size_t count, LDAPControl *extra, LDAPControl ***out) {
    *out = NULL;
    if (!adfl_controls_valid(source, count)) return LDAP_PARAM_ERROR;
    LDAPControl **controls = calloc(count + 2, sizeof(*controls));
    if (!controls) return LDAP_NO_MEMORY;
    static char empty_value;
    for (size_t i = 0; i < count; i++) {
        controls[i] = calloc(1, sizeof(*controls[i]));
        if (!controls[i]) { adfl_controls_release(controls, count); return LDAP_NO_MEMORY; }
        controls[i]->ldctl_oid = (char *)source[i].oid;
        controls[i]->ldctl_iscritical = (char)source[i].critical;
        controls[i]->ldctl_value = (struct berval){source[i].value.length,
            source[i].has_value ? (source[i].value.length ? (char *)source[i].value.data : &empty_value) : NULL};
    }
    controls[count] = extra; *out = controls; return LDAP_SUCCESS;
}
