#!/usr/bin/env bash
# Compile-only lab servers/tools. No install, credential creation or server startup.
# Inputs: pinned MIT, OpenLDAP, byacc archives; existing private bridge build; NEW output.
set -euo pipefail
mit_archive=$(realpath "${1:?MIT 1.21.3 original release archive}")
ldap_archive=$(realpath "${2:?OpenLDAP 2.6.10 GitHub tag archive}")
yacc_archive=$(realpath "${3:?byacc 2.0.20221106 original archive}")
private=$(realpath "${4:?Private LDAP/Cyrus/MIT build directory}")
out=$(realpath -m "${5:?New output directory}")
[[ "$out" != *[[:space:]]* && "$private" != *[[:space:]]* ]] || exit 2
python3 - "$mit_archive" "$ldap_archive" "$yacc_archive" "$out" <<'PY'
import hashlib, pathlib, sys, tarfile
out = pathlib.Path(sys.argv[4]); out.mkdir(parents=True, exist_ok=False)
inputs = [
 ('b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35', 'krb5-1.21.3'),
 ('1794dbb7225516ae5fb21f3f9a19c0181f0ce33e9d0218e0f623b0a386578181', 'openldap-OPENLDAP_REL_ENG_2_6_10'),
 # https://deb.debian.org/debian/pool/main/b/byacc/byacc_2.0.20221106.orig.tar.gz
 # Digest independently checked against byacc_2.0.20221106-1.dsc.
 ('a899be227bbcac9cf7700f7dbb5a8494688f1f9f0617b510762daeace47b9d12', 'byacc-20221106')]
for name, (digest, root) in zip(sys.argv[1:4], inputs):
    path = pathlib.Path(name)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError('Source archive hash mismatch: ' + name)
    with tarfile.open(path) as bundle:
        for member in bundle:
            parts = pathlib.Path(member.name).parts
            if not parts or parts[0] != root or '..' in parts or not (member.isdir() or member.isfile()):
                raise ValueError('Unexpected archive member: ' + member.name)
        bundle.extractall(out, filter='data')
PY
clean=(env -i PATH=/usr/bin:/bin LC_ALL=C CONFIG_SITE=/dev/null)
(
 cd "$out/byacc-20221106"
 "${clean[@]}" ./configure --prefix="$out/tools"
 "${clean[@]}" make -j4
)
mit="$out/krb5-1.21.3/src"
(
 cd "$mit"
 # Static dbutil/server library share tentative master_keyblock; preserve the
 # upstream common-symbol convention with GCC -fcommon, without source edits.
 "${clean[@]}" CFLAGS='-O2 -fPIC -fcommon' ./configure --enable-static --disable-shared \
  --disable-nls --with-crypto-impl=builtin --with-tls-impl=no --without-keyutils \
  --without-libedit --disable-pkinit --prefix="$out/runtime" \
  --libdir="$out/runtime/lib" --sysconfdir="$out/runtime/etc"
 "${clean[@]}" make all-prerecurse
 for directory in util include lib plugins/kdb/db2 kdc kadmin/cli kadmin/dbutil clients/kinit; do
  "${clean[@]}" make -C "$directory" -j4 YACC="$out/byacc-20221106/yacc"
 done
)
(
 cd "$out/openldap-OPENLDAP_REL_ENG_2_6_10"
 "${clean[@]}" CFLAGS='-O2 -fPIC' \
  CPPFLAGS="-I$private/include -I$private/mit/krb5-1.21.3/src/include" \
  LDFLAGS="-L$private/cyrus/cyrus-sasl-2.1.28/lib/.libs -L$private/mit/krb5-1.21.3/src/lib" \
  LIBS='-lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv -ldl -pthread' \
  ./configure --enable-static --disable-shared --enable-slapd --disable-balancer \
  --disable-dynamic --without-tls --without-systemd --without-fetch --with-cyrus-sasl \
  --with-threads=posix --enable-mdb=yes --disable-modules --prefix="$out/runtime"
 # Skip documentation targets requiring absent publishing tools.
 for directory in include libraries servers/slapd; do
  "${clean[@]}" make -C "$directory" -j4
 done
)
python3 - "$out" <<'PY'
import pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1]); mit = root/'krb5-1.21.3/src'
paths = [mit/'kdc/krb5kdc', mit/'kadmin/cli/kadmin.local', mit/'kadmin/dbutil/kdb5_util',
         mit/'clients/kinit/kinit', root/'openldap-OPENLDAP_REL_ENG_2_6_10/servers/slapd/slapd']
allowed = {'libc.so.6','libresolv.so.2','libm.so.6','libdl.so.2','libpthread.so.0'}
for path in paths:
    dynamic = subprocess.check_output(['readelf','-d',str(path)], text=True)
    needed = set(re.findall(r'Shared library: \[([^\]]+)\]', dynamic))
    if needed - allowed: raise ValueError('Unexpected runtime dependency: '+str((path,needed)))
    print(path, sorted(needed))
PY
