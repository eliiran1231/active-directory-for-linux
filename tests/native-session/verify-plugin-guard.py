#!/usr/bin/env python3
"""Hash-check/patch upstream source; execute its extracted guard with recording stubs.

No Cyrus plugin is built/loaded and no credential, GSS, SASL or network API runs.
The input source is supplied explicitly; this verifier never downloads software.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE_SHA256 = "732d311438c588ece922b866aa74d5833734cddedc5a8a1954ef737fa0e6cac0"
PATCH = ROOT / "src/AdForLinux.DirectoryServices.Native/patches/cyrus-sasl-2.1.28-explicit-credential.patch"
TEMPLATE = Path(__file__).with_name("plugin-guard-harness.c.in")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Unmodified official Cyrus SASL 2.1.28 plugins/gssapi.c")
    parser.add_argument("--sanitize", action="store_true", help="Enable address/undefined-behavior sanitizers")
    args = parser.parse_args()
    original = args.source.read_bytes()
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        parser.error("Source hash mismatch: only the exact reviewed upstream source is admitted.")
    with tempfile.TemporaryDirectory(prefix="adfl-plugin-guard-") as directory:
        work = Path(directory)
        (work / "plugins").mkdir()
        source = work / "plugins/gssapi.c"
        source.write_bytes(original)
        subprocess.run(["patch", "--batch", "--forward", "-p1", "-i", str(PATCH)],
                       cwd=work, check=True, capture_output=True, text=True)
        patched = source.read_text()
        function = patched[patched.index("static int gssapi_client_mech_step("):]
        begin = function.index("/* ADFL_EXPLICIT_CREDENTIAL_GUARD_BEGIN")
        end = function.index("/* ADFL_EXPLICIT_CREDENTIAL_GUARD_END */")
        end += len("/* ADFL_EXPLICIT_CREDENTIAL_GUARD_END */")
        prefix = function[:begin]
        assert "return SASL_INTERACT;" in prefix
        assert "gss_cred_id_t client_creds = (gss_cred_id_t)params->gss_creds;" in prefix
        assert not re.search(r"\bgss_[A-Za-z0-9_]+\s*\(", prefix), "GSS call before guard"
        assert begin < function.index("if (text->server_name == GSS_C_NO_NAME)")
        for call in re.finditer(r"\bgss_(?:acquire_cred\w*|init_sec_context)\s*\(", function):
            assert call.start() > end, "Credential acquisition/init precedes guard"
        guard = function[begin:end]
        assert "if (client_creds == GSS_C_NO_CREDENTIAL)" in guard
        assert "params->gss_creds" not in guard
        # Compile the actual upstream initial interaction block plus applied guard.
        fragment = function[function.index("/* try to get the userid */"):end]
        template = TEMPLATE.read_text()
        assert template.count("/* ADFL_EXTRACTED_FRAGMENT */") == 1
        harness = work / "guard.c"
        harness.write_text(template.replace("/* ADFL_EXTRACTED_FRAGMENT */", fragment))
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
        if args.sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        executable = work / "guard"
        subprocess.run([os.environ.get("CC", "cc"), *flags, str(harness), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
    print("PASS: pinned source hash, patch application, source ordering and extracted guard.")
    print("Compile-only guard harness; no full plugin build/load or authentication proof.")
    print("Controlled composition remains unavailable; this test cannot enable a backend.")


if __name__ == "__main__":
    main()
