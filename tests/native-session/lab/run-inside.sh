#!/bin/sh
# Only run in the disposable, network-none lab container; no host execution.
set -eu
umask 077
/probe
[ "$(id -u)" = 65534 ]
[ -d /run/adfl ]
export HOME=/run/adfl
export KRB5_CONFIG=/run/adfl/krb5.conf
export KRB5_KDC_PROFILE=/run/adfl/kdc.conf
export KRB5RCACHEDIR=/run/adfl
export KRB5_KTNAME=FILE:/run/adfl/ldap.keytab
export GSS_MECH_CONFIG=/run/adfl/empty-mechs
: > "$GSS_MECH_CONFIG"
mkdir /run/adfl/db /run/adfl/plugins
cat > "$KRB5_CONFIG" <<'CONFIG'
[libdefaults]
 default_realm = ADFL.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 dns_canonicalize_hostname = false
 rdns = false
 qualify_shortname = ""
 plugin_base_dir = /run/adfl/plugins
[realms]
 ADFL.TEST = {
  kdc = 127.0.0.1:10088
 }
[domain_realm]
 127.0.0.1 = ADFL.TEST
[plugins]
 ccselect = {
  enable_only = realm
 }
CONFIG
cat > "$KRB5_KDC_PROFILE" <<'CONFIG'
[kdcdefaults]
 kdc_listen = 127.0.0.1:10088
 kdc_tcp_listen = 127.0.0.1:10088
[realms]
 ADFL.TEST = {
  database_name = /run/adfl/principal
  key_stash_file = /run/adfl/stash
  acl_file = /run/adfl/kadm5.acl
  max_life = 1h
  max_renewable_life = 1h
 }
CONFIG
# All command output, including failure details, remains in ephemeral tmpfs.
# Only sanitized assertion messages are sent to the parent.
cleanup() {
 for pid in ${ldap_pid:-} ${kdc_pid:-}; do kill "$pid" 2>/dev/null || true; done
 wait 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
master=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
if ! /bin/kdb5_util create -s -P "$master" > /run/adfl/setup.log 2>&1; then
 echo 'FAIL: test realm creation'; exit 1
fi
unset master
for principal in client-a client-b ldap/127.0.0.1; do
 /bin/kadmin.local -q "addprinc -randkey $principal@ADFL.TEST" >> /run/adfl/setup.log 2>&1
 case "$principal" in ldap/*) file=ldap;; *) file=$principal;; esac
 /bin/kadmin.local -q "ktadd -k /run/adfl/$file.keytab $principal@ADFL.TEST" >> /run/adfl/setup.log 2>&1
done
/bin/krb5kdc -n > /run/adfl/kdc.log 2>&1 &
kdc_pid=$!
cat > /run/adfl/slapd.conf <<'CONFIG'
include /etc/core.schema
pidfile /run/adfl/slapd.pid
argsfile /run/adfl/slapd.args
sasl-host 127.0.0.1
sasl-realm ADFL.TEST
sasl-secprops minssf=1,maxssf=256,noanonymous,noplain
authz-regexp "^uid=(client-[ab]),cn=(adfl.test,cn=)?gssapi,cn=auth$" "uid=$1,dc=adfl,dc=test"
access to * by * read
database ldif
suffix "dc=adfl,dc=test"
directory /run/adfl/db
CONFIG
/bin/slapd -f /run/adfl/slapd.conf -h ldap://127.0.0.1:10389 -d 0 > /run/adfl/ldap.log 2>&1 &
ldap_pid=$!
# Bounded readiness retries do not replay library operations under test.
for client in client-a client-b; do
 ready=false
 for attempt in 1 2 3 4 5; do
  if /bin/kinit -c FILE:/run/adfl/$client.ccache -kt /run/adfl/$client.keytab "$client@ADFL.TEST" > /run/adfl/kinit.log 2>&1; then ready=true; break; fi
  sleep 1
 done
 if [ "$ready" != true ]; then echo 'FAIL: isolated test ticket acquisition'; exit 1; fi
done
sleep 1
if ! kill -0 "$ldap_pid" 2>/dev/null; then
 echo "FAIL: LDAP server exited before bind"; exit 1
fi
if ! /bin/real-bind --isolated-lab dn:uid=client-a,dc=adfl,dc=test dn:uid=client-b,dc=adfl,dc=test > /run/adfl/assertions.log 2>&1; then
 echo 'FAIL: isolated real-bind assertions'; cat /run/adfl/assertions.log; exit 1
fi
# Harness emits assertion summaries only, never native diagnostic or ticket data.
echo 'PASS: real private-stack binding identities and negotiated signing/sealing assertions'
