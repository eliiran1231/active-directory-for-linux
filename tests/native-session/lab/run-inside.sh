#!/bin/sh
# Only run in the disposable, network-none lab container; no host execution.
set -eu
umask 077
/probe
[ "$(id -u)" = 65534 ]
[ -d /run/adfl ]
if [ -f /lab/AdForLinux.NativeWorkerDemo.dll ]; then
 export DOTNET_EnableDiagnostics=0 DOTNET_GENERATE_ASPNET_CERTIFICATE=false DOTNET_CLI_TELEMETRY_OPTOUT=1
 if ! /dotnet/dotnet /lab/AdForLinux.NativeWorkerDemo.dll --real-lab-runtime-probe > /run/adfl/runtime.log 2>&1; then
  echo 'FAIL: managed runtime prerequisite before credential creation'; exit 1
 fi
fi
export HOME=/run/adfl
export KRB5_CONFIG=/run/adfl/krb5.conf
export KRB5_KDC_PROFILE=/run/adfl/kdc.conf
export KRB5RCACHEDIR=/run/adfl
export KRB5_KTNAME=FILE:/run/adfl/ldap.keytab
export GSS_MECH_CONFIG=/run/adfl/empty-mechs
: > "$GSS_MECH_CONFIG"
mkdir /run/adfl/db /run/adfl/plugins
cat /etc/lab-krb5.conf > "$KRB5_CONFIG"
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
include /etc/cosine.schema
pidfile /run/adfl/slapd.pid
argsfile /run/adfl/slapd.args
sasl-host 127.0.0.1
sasl-realm ADFL.TEST
sasl-secprops minssf=1,maxssf=256,noanonymous,noplain
authz-regexp "^uid=(client-[ab]),cn=(adfl.test,cn=)?gssapi,cn=auth$" "uid=$1,dc=adfl,dc=test"
access to dn.exact="cn=client-a,dc=adfl,dc=test" by dn.exact="uid=client-a,dc=adfl,dc=test" ssf=56 read by * none
access to dn.exact="cn=client-b,dc=adfl,dc=test" by dn.exact="uid=client-b,dc=adfl,dc=test" ssf=56 read by * none
access to * by * read
database mdb
maxsize 16777216
suffix "dc=adfl,dc=test"
directory /run/adfl/db
CONFIG
# Synthetic read-only ACL witnesses, confined to the disposable test database.
cat > /run/adfl/entries.ldif <<'ENTRY'
dn: dc=adfl,dc=test
objectClass: top
objectClass: domain
dc: adfl

ENTRY
for client in client-a client-b; do
 cat >> /run/adfl/entries.ldif <<ENTRY
dn: cn=$client,dc=adfl,dc=test
objectClass: top
objectClass: organizationalRole
cn: $client
description: $client

ENTRY
done
# MDB supplies the paged-results control exercised by the public cursor.
if ! /bin/slapd -Ta -f /run/adfl/slapd.conf -l /run/adfl/entries.ldif > /run/adfl/import.log 2>&1; then
 echo 'FAIL: synthetic directory fixture import'; exit 1
fi
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

if [ -f /lab/AdForLinux.NativeWorkerDemo.dll ]; then
 # Reset to fresh test TGTs before the supervised managed path.
 for client in client-a client-b; do
  /bin/kinit -c FILE:/run/adfl/$client.ccache -kt /run/adfl/$client.keytab "$client@ADFL.TEST" > /run/adfl/kinit.log 2>&1
 done
 export DOTNET_EnableDiagnostics=0 DOTNET_GENERATE_ASPNET_CERTIFICATE=false DOTNET_CLI_TELEMETRY_OPTOUT=1
 if /dotnet/dotnet /lab/AdForLinux.NativeWorkerDemo.dll --real-lab-parent > /run/adfl/managed-assertions.log 2>&1; then
  :
 else
  status=$?; echo "FAIL: supervised real-login assertions (numeric stage $status)"; exit 1
 fi
 echo 'PASS: supervised managed worker, paired real native sessions and shared request dispatch'
fi

if [ -f /bundle/production-v1/composition.json ]; then
 for client in client-a client-b; do
  /bin/kinit -c FILE:/run/adfl/$client.ccache -kt /run/adfl/$client.keytab "$client@ADFL.TEST" > /run/adfl/kinit.log 2>&1
 done
 if /dotnet/dotnet /lab/AdForLinux.NativeWorkerDemo.dll --real-public-lab > /run/adfl/public-assertions.log 2>&1; then
  echo 'PASS: public API uses admitted production source-only host; identity/SSF ACLs, paging and context operations verified'
 else
  status=$?; echo "FAIL: restricted public API assertions (numeric stage $status)"; cat /run/adfl/public-assertions.log; exit 1
 fi
fi
