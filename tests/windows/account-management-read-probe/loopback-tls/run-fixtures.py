#!/usr/bin/env python3
"""Owned loopback TLS/LDAP fixtures, synthetic bind values, ephemeral test CA."""
import argparse
import contextlib
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def tlv(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else bytes([0x80 + (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag]) + encoded + value


def integer(value):
    encoded = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return tlv(2, encoded)


def fields(value):
    result = []
    while value:
        if len(value) < 2: raise ValueError()
        tag, length = value[:2]; offset = 2
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or len(value) < offset + count: raise ValueError()
            length = int.from_bytes(value[offset:offset + count], "big"); offset += count
        if length > 65536 or len(value) < offset + length: raise ValueError()
        result.append((tag, value[offset:offset + length])); value = value[offset + length:]
    return result


def receive(stream):
    def exact(size):
        result = b""
        while len(result) < size:
            chunk = stream.recv(size - len(result))
            if not chunk: raise EOFError()
            result += chunk
        return result
    header = exact(2)
    if header[0] != 0x30: raise ValueError()
    length = header[1]
    if length & 128:
        count = length & 127
        if not 1 <= count <= 4: raise ValueError()
        length = int.from_bytes(exact(count), "big")
    if length > 65536: raise ValueError()
    message = fields(exact(length))
    if len(message) != 2 or message[0][0] != 2: raise ValueError()
    identifier = int.from_bytes(message[0][1], "big", signed=True)
    if identifier <= 0: raise ValueError()
    return identifier, *message[1]


def reply(identifier, tag, body):
    return tlv(0x30, integer(identifier) + tlv(tag, body))


def result(code=0, referrals=()):
    value = tlv(0x0a, bytes([code])) + tlv(4, b"") + tlv(4, b"")
    return value + (tlv(0xa3, b"".join(tlv(4, url.encode("ascii")) for url in referrals)) if referrals else b"")


class Listener:
    def __init__(self, context=None, mode="trap", urls=()):
        self.context, self.mode, self.urls = context, mode, urls
        self.stop = threading.Event(); self.sockets = []; self.accept_threads = []; self.handlers = []; self.lock = threading.Lock()
        self.stats = dict(tcp=0, tls=0, binds=0, searches=0, unexpected=0, tls_errors=0, referrals_sent=0, references_sent=0)
        # Reserve BOTH localhost address families at the same port. Never let a
        # resolver-selected ::1 target belong to an unrelated local service.
        for _ in range(20):
            first = socket.socket(socket.AF_INET); first.bind(("127.0.0.1", 0)); port = first.getsockname()[1]
            try:
                second = socket.socket(socket.AF_INET6); second.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                second.bind(("::1", port))
            except OSError:
                first.close()
                with contextlib.suppress(UnboundLocalError): second.close()
                continue
            self.sockets = [first, second]; self.port = port; break
        if not self.sockets: raise RuntimeError("Cannot reserve both loopback families")
        for item in self.sockets:
            item.listen(8); item.settimeout(0.1)
            thread = threading.Thread(target=self.accept, args=(item,), daemon=True); self.accept_threads.append(thread); thread.start()

    def accept(self, listener):
        while not self.stop.is_set():
            try: client, address = listener.accept()
            except socket.timeout: continue
            except OSError: return
            self.bump("tcp")
            thread = threading.Thread(target=self.handle, args=(client,), daemon=True)
            with self.lock: self.handlers.append(thread); thread.start()

    def handle(self, client):
        with client:
            if self.mode == "trap": return
            if self.mode == "handshake-hang": self.stop.wait(8); return
            try:
                client.settimeout(2)
                with self.context.wrap_socket(client, server_side=True) as stream:
                    self.bump("tls")
                    identifier, tag, body = receive(stream)
                    if tag != 0x60 or fields(body) != [(2, b"\x03"), (4, b"cn=loopback-fixture"), (0x80, b"synthetic-only")]: raise ValueError()
                    self.bump("binds")
                    if self.mode == "bind-referral":
                        stream.sendall(reply(identifier, 0x61, result(10, self.urls))); self.bump("referrals_sent")
                        # Keep the connection alive until the SDK closes it, so
                        # a server EOF cannot stand in for response processing.
                        try:
                            _, end_tag, end_body = receive(stream)
                            if end_tag != 0x42 or end_body: raise ValueError()
                        except EOFError: pass
                        return
                    stream.sendall(reply(identifier, 0x61, result()))
                    identifier, tag, body = receive(stream)
                    values = fields(body)
                    expected = [(4, b"cn=fixture,dc=loopback"), (0x0a, b"\x00"), (0x0a, b"\x00"),
                                (2, b"\x02"), (2, b"\x01"), (1, b"\x00"), (0x87, b"objectClass"), (0x30, tlv(4, b"cn"))]
                    if tag != 0x63 or values != expected: raise ValueError()
                    self.bump("searches")
                    if self.mode == "search-hang": self.stop.wait(8); return
                    if self.mode == "partial-response": stream.sendall(b"\x30\x82"); self.stop.wait(8); return
                    if self.mode == "search-referral":
                        stream.sendall(reply(identifier, 0x65, result(10, self.urls))); self.bump("referrals_sent"); return
                    if self.mode == "reference":
                        stream.sendall(reply(identifier, 0x73, b"".join(tlv(4, url.encode("ascii")) for url in self.urls))); self.bump("references_sent")
                    else:
                        attributes = tlv(0x30, tlv(0x30, tlv(4, b"cn") + tlv(0x31, tlv(4, b"fixture"))))
                        stream.sendall(reply(identifier, 0x64, tlv(4, b"cn=fixture,dc=loopback") + attributes))
                    stream.sendall(reply(identifier, 0x65, result()))
                    try:
                        _, tag, body = receive(stream)
                        if tag != 0x42 or body: raise ValueError() # optional Unbind only
                    except EOFError: pass
            except ssl.SSLError: self.bump("tls_errors")
            except (EOFError, socket.timeout, ConnectionError): pass
            except Exception: self.bump("unexpected")

    def bump(self, name):
        with self.lock: self.stats[name] += 1

    def close(self):
        self.stop.set()
        for thread in self.accept_threads: thread.join(timeout=3)
        # The client has exited. Drain any completed connections from the listen
        # backlog before accepting zero-contact evidence for a referral trap.
        for item in self.sockets:
            item.settimeout(0.02)
            for _ in range(64):
                try:
                    client, _ = item.accept(); self.bump("tcp"); client.close()
                except socket.timeout: break
            else: self.bump("unexpected")
            item.close()
        with self.lock: handlers = list(self.handlers)
        for thread in handlers: thread.join(timeout=3)
        if any(thread.is_alive() for thread in self.accept_threads + handlers): raise RuntimeError("Loopback fixture thread did not stop")


def openssl(directory, *arguments):
    subprocess.run(["openssl", *map(str, arguments)], cwd=directory, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True, timeout=15,
                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "OPENSSL_CONF": str(directory / "openssl.cnf")})


def certificates(directory):
    (directory / "openssl.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n")
    for ca in ("ca", "other-ca"):
        openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=loopback-test-only",
                "-keyout", ca + ".key", "-out", ca + ".pem",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    # OpenLDAP 2.5/GnuTLS checks its local hostname for the literal
    # "localhost". Keep the socket target fixed and cover both local identities.
    local_name = socket.gethostname()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", local_name):
        raise RuntimeError("Unsupported local fixture hostname")
    matching_san = "DNS:localhost,DNS:" + local_name
    for name, san, ca, days in (("valid", matching_san, "ca", 1), ("wrong-san", "DNS:wrong.invalid", "ca", 1),
                               ("cn-only", None, "ca", 1), ("expired", matching_san, "ca", -1),
                               ("untrusted", matching_san, "other-ca", 1)):
        openssl(directory, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + local_name,
                "-keyout", name + ".key", "-out", name + ".csr")
        extension = directory / (name + ".ext")
        extension.write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n" +
                             ("subjectAltName=" + san + "\n" if san else ""))
        if days < 0:
            (directory / "index").write_text(""); (directory / "serial").write_text("1000\n")
            (directory / "minted").mkdir()
            (directory / "expired-ca.cnf").write_text("[ca]\ndefault_ca=fixture\n[fixture]\ndatabase=index\nserial=serial\nnew_certs_dir=minted\n"
                "default_md=sha256\npolicy=signing\ncertificate=ca.pem\nprivate_key=ca.key\n[signing]\ncommonName=supplied\n")
            openssl(directory, "ca", "-batch", "-config", "expired-ca.cnf", "-in", name + ".csr", "-out", name + ".pem",
                    "-startdate", "20200101000000Z", "-enddate", "20200102000000Z", "-extfile", extension.name)
        else:
            openssl(directory, "x509", "-req", "-in", name + ".csr", "-CA", ca + ".pem", "-CAkey", ca + ".key",
                    "-CAcreateserial", "-days", days, "-extfile", extension.name, "-out", name + ".pem")
        os.chmod(directory / (name + ".key"), 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--native-directory", type=Path)
    options = parser.parse_args()
    if os.environ.get("ADFL_OFFLINE_TESTS"): raise SystemExit("BLOCKED inherited offline guard; never remove it")
    root = Path(__file__).resolve().parent
    assemblies = [root / "bin" / "Release" / framework / "LoopbackTls.dll" for framework in ("net8.0", "net10.0")]
    if any(not value.is_file() for value in assemblies): raise SystemExit("BLOCKED build both loopback harness frameworks")
    report = dict(python_tls=ssl.OPENSSL_VERSION, scope="owned localhost/ephemeral ports only; explicit native TLS options, not production env configuration", cases=[])
    with tempfile.TemporaryDirectory(prefix="adfl-loopback-tls-") as temporary:
        directory = Path(temporary); certificates(directory)
        environment = {key: os.environ[key] for key in ("PATH", "DOTNET_ROOT", "DOTNET_CLI_HOME", "DOTNET_NOLOGO", "XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP") if key in os.environ}
        environment.update(ADFL_LOOPBACK_TLS_TESTS="1", LDAPNOINIT="1", DOTNET_EnableDiagnostics="0", COMPlus_EnableDiagnostics="0",
                           DOTNET_DbgEnableMiniDump="0", COMPlus_DbgEnableMiniDump="0")
        if options.native_directory:
            native = options.native_directory.resolve()
            if not all((native / name).is_file() for name in ("libldap-2.5.so.0", "liblber-2.5.so.0")):
                raise SystemExit("BLOCKED incomplete explicit native directory")
            environment["LD_LIBRARY_PATH"] = str(native)
            report["explicit_native_files_sha256"] = {name: hashlib.sha256((native / name).read_bytes()).hexdigest()
                for name in ("libldap-2.5.so.0", "liblber-2.5.so.0")}
        # No HOME replacement, credential copying, LDAP defaults or global trust changes.
        cases = [("valid-before", "valid", "normal", "strict"),
                 ("wrong-san", "wrong-san", "normal", "strict"), ("cn-only", "cn-only", "normal", "strict"),
                 ("expired", "expired", "normal", "strict"), ("untrusted", "untrusted", "normal", "strict"),
                 ("isolated-insecure-control", "wrong-san", "normal", "insecure-control"),
                 *((kind + "-" + scheme, "valid", mode, "strict") for kind, mode in
                    (("bind-referral", "bind-referral"), ("search-referral", "search-referral"), ("search-reference", "reference"))
                    for scheme in ("ldap", "ldaps")), ("handshake-hang", "valid", "handshake-hang", "strict"),
                 ("search-hang", "valid", "search-hang", "strict"), ("partial-response", "valid", "partial-response", "strict"),
                 ("valid-after", "valid", "normal", "strict")]
        for assembly in assemblies:
            for label, certificate, mode, requirement in cases:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(directory / (certificate + ".pem"), directory / (certificate + ".key"))
                cleanup = contextlib.ExitStack()
                try:
                    ldap_trap = Listener(); cleanup.callback(ldap_trap.close)
                    ldaps_trap = Listener(); cleanup.callback(ldaps_trap.close)
                    urls = (f"ldap://127.0.0.1:{ldap_trap.port}/cn=outside", f"ldaps://127.0.0.1:{ldaps_trap.port}/cn=outside")
                    selected_urls = (urls[0],) if label.endswith("-ldap") else (urls[1],) if label.endswith("-ldaps") else urls
                    server = Listener(context, mode, selected_urls); cleanup.callback(server.close)
                except BaseException:
                    cleanup.close()
                    raise
                started = time.monotonic(); parsed = None
                try:
                    def no_core():
                        import resource
                        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                    try:
                        child = subprocess.run([options.dotnet, str(assembly), str(server.port), requirement, str(directory / "ca.pem")],
                            cwd=directory, env=environment, input="", capture_output=True, text=True, timeout=6,
                            start_new_session=True, preexec_fn=no_core, check=False)
                        if child.stderr: raise AssertionError("Unexpected child diagnostics")
                        parsed = json.loads(child.stdout) if child.stdout else None
                        code = child.returncode
                    except subprocess.TimeoutExpired: code = "outer-timeout"
                    elapsed = time.monotonic() - started
                finally:
                    cleanup.close()
                row = dict(framework=assembly.parent.name, case=label, exit=code, elapsed_seconds=round(elapsed, 3),
                           server=server.stats, ldap_trap=ldap_trap.stats["tcp"], ldaps_trap=ldaps_trap.stats["tcp"], child=parsed)
                report["cases"].append(row)
                valid = server.stats["tcp"] > 0 and server.stats["unexpected"] == 0 and not (row["ldap_trap"] or row["ldaps_trap"]) and elapsed < 8
                if label in ("valid-before", "valid-after", "isolated-insecure-control"):
                    valid &= code == 0 and parsed is not None and parsed["outcome"] == "search-ok" and server.stats["binds"] == 1 and server.stats["searches"] == 1
                elif label in ("wrong-san", "cn-only", "expired", "untrusted"):
                    valid &= code == 1 and parsed is not None and parsed["stage"] == "bind" and server.stats["binds"] == 0 and server.stats["tls"] + server.stats["tls_errors"] > 0
                elif mode in ("bind-referral", "search-referral", "reference"):
                    valid &= parsed is not None and server.stats["binds"] == 1 and parsed["outcome"] in ("referral-observed", "reference-observed", "failure")
                    valid &= server.stats["searches"] == (0 if mode == "bind-referral" else 1)
                    if mode == "reference": valid &= code == 0 and parsed["stage"] == "search" and parsed["outcome"] == "reference-observed" and server.stats["references_sent"] == 1
                    if mode == "search-referral": valid &= code == 0 and parsed["stage"] == "search" and parsed["outcome"] == "referral-observed" and server.stats["referrals_sent"] == 1
                    if mode == "bind-referral":
                        row["evidence_limit"] = "server emitted referral; SDK bind failed; zero trap contacts; Bind exception has no response code"
                        valid &= parsed["stage"] == "bind" and server.stats["referrals_sent"] == 1 and (
                            parsed["outcome"] == "referral-observed" or parsed.get("ldap_error") == 10 or
                            code == 1 and parsed.get("error") == "DirectoryOperationException/DirectoryOperationException")
                else:
                    row["timeout_source"] = "outer-process" if code == "outer-timeout" else "native-sdk"
                    valid &= (code == "outer-timeout" and parsed is None) or (
                        code == 1 and parsed is not None and parsed["stage"] == ("bind" if mode == "handshake-hang" else "search"))
                    valid &= server.stats["binds"] == (0 if mode == "handshake-hang" else 1)
                    valid &= server.stats["searches"] == (0 if mode == "handshake-hang" else 1)
                row["passed"] = bool(valid)
                Path(options.report).write_text(json.dumps(report, indent=2) + "\n")
                if not valid:
                    Path(options.report).write_text(json.dumps(report, indent=2) + "\n")
                    raise SystemExit("FAIL loopback case " + assembly.parent.name + "/" + label)
    report["temporary_test_keys_removed"] = not directory.exists()
    report["real_ad_or_real_credentials"] = False
    Path(options.report).write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS {len(report['cases'])} isolated loopback native SDK cases; temporary keys removed")


if __name__ == "__main__": main()
