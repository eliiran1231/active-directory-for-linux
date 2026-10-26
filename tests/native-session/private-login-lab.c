/* Opt-in isolated-lab executable. NEVER part of offline tests.
 * Real credential acquisition and LDAP authentication occur ONLY when run.
 * Production source and capability gates remain unchanged. */
#define _POSIX_C_SOURCE 200809L
#include "adfl_native_internal.h"
#include <sasl/sasl.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

static int lab_probe(void *state, adfl_native_capabilities *caps) {
    int rc = adfl_system_ops.probe(state, caps);
    if (!rc) { caps->reviewed_build = 1; caps->authority_binding_enforced = 1; }
    return rc;
}
/* Diagnostic delegation only: callback, defaults, result and bind behavior
 * remain the production implementation. Never print tokens or raw diagnostics. */
static int lab_bind(void *state, LDAP *ld, LDAP_SASL_INTERACT_PROC *callback, void *defaults) {
    int rc = adfl_system_ops.bind(state, ld, callback, defaults);
    fprintf(stderr, "Native LDAP bind status=%d.\n", rc);
    return rc;
}
static int verify(adfl_bound_session *session, const char *expected, unsigned minimum) {
    sasl_ssf_t ssf = 0;
    if (ldap_get_option(session->ldap, LDAP_OPT_X_SASL_SSF, &ssf) != LDAP_OPT_SUCCESS || ssf < minimum) {
        fprintf(stderr, "Negotiated SASL SSF %u is below required %u.\n", (unsigned)ssf, minimum);
        return 1;
    }
    struct berval *identity = NULL;
    LDAPControl *empty[] = {NULL};
    int rc = ldap_whoami_s(session->ldap, &identity, empty, empty);
    int matches = rc == LDAP_SUCCESS && identity && identity->bv_val &&
        identity->bv_len == strlen(expected) && !memcmp(identity->bv_val, expected, identity->bv_len);
    if (!matches) fprintf(stderr, "WhoAmI did not exactly match expected lab authorization identity (LDAP status %d).\n", rc);
    if (identity) ber_bvfree(identity);
    if (matches) printf("Verified expected lab authorization identity; negotiated SASL SSF=%u.\n", (unsigned)ssf);
    return !matches;
}
/* Single-process isolated lab only. Restore the completed rename prefix even
 * when resolution/bind/identity verification fails. No credential bytes read. */
static int replacement(const adfl_native_ops *ops, const adfl_native_profile *profile,
    const adfl_credential_source *sources, adfl_bound_session *old_a,
    const char *expected_a, const char *expected_b) {
    const char *a=sources[0].absolute_path, *b=sources[1].absolute_path;
    const char *temporary="/run/adfl/swap.ccache";
    struct stat st;
    if (lstat(temporary,&st) == 0 || errno != ENOENT) {
        fputs("Cache swap refuses an existing or unverifiable temporary path.\n",stderr); return 1;
    }
    int stage=0, failed=1;
    adfl_authority *fresh=NULL; adfl_bound_session *bound=NULL;
    if (rename(a,temporary)) goto cleanup;
    stage=1;
    if (rename(b,a)) goto cleanup;
    stage=2;
    if (rename(temporary,b)) goto cleanup;
    stage=3;
    int rc=adfl_resolve_from_with(ops,NULL,profile,&sources[0],NULL,NULL,&fresh);
    if (rc) { fprintf(stderr,"Replacement source resolution failed (%d).\n",rc); goto cleanup; }
    rc=adfl_authority_bind(fresh,profile,NULL,NULL,&bound);
    if (rc) { fprintf(stderr,"Replacement source bind failed (%d).\n",rc); goto cleanup; }
    failed=verify(bound,expected_b,56);
    if (!failed) failed=verify(old_a,expected_a,56);
cleanup:
    adfl_session_close(&bound); adfl_authority_close(&fresh);
    /* Undo in reverse order. Stop on a restoration failure to avoid overwriting
     * the only surviving copy; report exact stage for isolated-lab recovery. */
    if (stage==3) { if (rename(b,temporary)) goto restore_failed; stage=2; }
    if (stage==2) { if (rename(a,b)) goto restore_failed; stage=1; }
    if (stage==1) { if (rename(temporary,a)) goto restore_failed; stage=0; }
    if (!failed) puts("Verified replacement routes fresh source A to identity B; established A remains A; cache paths restored.");
    return failed;
restore_failed:
    fprintf(stderr,"Cache restoration FAILED at swap stage %d (errno %d); isolated lab requires recovery.\n",stage,errno);
    return 1;
}
static int only_tgt(const char *path) {
    krb5_context context=NULL; krb5_ccache cache=NULL; krb5_cc_cursor cursor;
    int failed=1, started=0, count=0; char name[128];
    snprintf(name,sizeof(name),"FILE:%s",path);
    if (krb5_init_context(&context) || krb5_cc_resolve(context,name,&cache) ||
        krb5_cc_start_seq_get(context,cache,&cursor)) goto done;
    started=1;
    krb5_creds credentials;
    while (1) {
        memset(&credentials,0,sizeof(credentials));
        krb5_error_code rc=krb5_cc_next_cred(context,cache,&cursor,&credentials);
        if (rc==KRB5_CC_END) { failed=count!=1; break; }
        if (rc) break;
        if (krb5_is_config_principal(context,credentials.server)) {
            krb5_free_cred_contents(context,&credentials); continue;
        }
        int tgt=krb5_princ_size(context,credentials.server)==2 &&
            krb5_princ_component(context,credentials.server,0)->length==6 &&
            !memcmp(krb5_princ_component(context,credentials.server,0)->data,"krbtgt",6);
        krb5_free_cred_contents(context,&credentials);
        if (!tgt) break;
        count++;
    }
done:
    if (started) krb5_cc_end_seq_get(context,cache,&cursor);
    if (cache) krb5_cc_close(context,cache);
    if (context) krb5_free_context(context);
    if (failed) fputs("Lab requires fresh TGT-only caches before binding.\n",stderr);
    return failed;
}
int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "--isolated-lab") || !argv[2][0] || !argv[3][0] || !strcmp(argv[2], argv[3])) {
        fputs("Usage: private-login-lab --isolated-lab EXACT_WHOAMI_A EXACT_WHOAMI_B\n"
              "WARNING: performs real authentication against fixed 127.0.0.1:10389 using /run/adfl/client-{a,b}.ccache.\n"
              "Requires isolated ADFL.TEST configuration and ldap/127.0.0.1 service principal.\n", stderr);
        return 2;
    }
    adfl_native_ops ops = adfl_system_ops; ops.probe = lab_probe; ops.bind = lab_bind; /* gate override + diagnostic delegation */
    const adfl_credential_source sources[] = {
        {ADFL_SOURCE_FILE, "/run/adfl/client-a.ccache"},
        {ADFL_SOURCE_FILE, "/run/adfl/client-b.ccache"}
    };
    if (only_tgt(sources[0].absolute_path) || only_tgt(sources[1].absolute_path)) return 1;
    int failed = 0;
    for (unsigned sealing = 0; sealing < 2 && !failed; sealing++) {
        adfl_native_profile profile = {.host="127.0.0.1", .port=10389, .timeout_seconds=5, .signing=1, .sealing=sealing};
        adfl_authority *authorities[2] = {NULL, NULL};
        adfl_bound_session *sessions[4] = {NULL, NULL, NULL, NULL};
        for (int i=0; i<2 && !failed; i++) {
            int rc = adfl_resolve_from_with(&ops, NULL, &profile, &sources[i], NULL, NULL, &authorities[i]);
            if (rc) { fprintf(stderr,"Explicit lab source resolution failed (%d).\n",rc); failed=1; }
        }
        /* Two simultaneous sessions per authority; identities must not bleed. */
        for (int i=0; i<4 && !failed; i++) {
            int rc = adfl_authority_bind(authorities[i%2], &profile, NULL, NULL, &sessions[i]);
            if (rc) { fprintf(stderr,"Real lab bind failed (%d).\n",rc); failed=1; }
            else failed=verify(sessions[i], argv[2+i%2], sealing ? 56 : 1);
        }
        if (sealing && !failed)
            failed=replacement(&ops,&profile,sources,sessions[0],argv[2],argv[3]);
        /* Sessions retain the selected resource after the initial owners close. */
        for (int i=0; i<2; i++) adfl_authority_close(&authorities[i]);
        for (int i=0; i<4 && !failed; i++) failed=verify(sessions[i], argv[2+i%2], sealing ? 56 : 1);
        for (int i=0; i<4; i++) adfl_session_close(&sessions[i]);
    }
    if (!failed) puts("PASS: isolated real lab identities, paired session ownership, cache replacement, signing/sealing minimums. Production activation/reuse remains disabled.");
    return failed;
}
