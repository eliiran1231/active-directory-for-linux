"""Validate versioned detached recording lines without treating clone values as oracle."""
import json
import re

PREFIX = "ADFL_DIFFERENTIAL_OBSERVATION_V1: "


def read(stdout, case_id, framework, source_commit):
    # The retained TRX may represent line boundaries as literal \r\n text.
    # Consume each JSON object before looking for the next boundary: blindly
    # replacing escapes would also corrupt newlines inside observation strings.
    boundary = re.compile(r"\r\n|\r|\n|\\r\\n")
    decoder = json.JSONDecoder()
    rows = []
    position = 0
    while position < len(stdout):
        if stdout.startswith("ADFL_DIFFERENTIAL_OBSERVATION_", position):
            if not stdout.startswith(PREFIX, position):
                raise ValueError("Unsupported structured observation version")
            row, position = decoder.raw_decode(stdout, position + len(PREFIX))
            rows.append(row)
            if position < len(stdout) and not boundary.match(stdout, position):
                if stdout[position:].strip():
                    raise ValueError("Trailing content after structured observation")
                break
        next_boundary = boundary.search(stdout, position)
        if next_boundary is None:
            break
        position = next_boundary.end()
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("Duplicate structured observations")
    row = rows[0]
    if not isinstance(row, dict) or type(row.get("schemaVersion")) is not int or row.get("schemaVersion") != 1 or row.get("caseId") != case_id:
        raise ValueError("Structured schema or case identity mismatch")
    if row.get("source") != "microsoft-windows-differential":
        raise ValueError("Wrong structured observation source")
    provenance = row.get("provenance", {})
    if not isinstance(provenance, dict):
        raise ValueError("Invalid structured provenance")
    if provenance.get("commit") != source_commit or not isinstance(provenance.get("os"), str) or not provenance["os"].startswith("Microsoft Windows "):
        raise ValueError("Structured commit or platform mismatch")
    target = {"net8.0": ".NETCoreApp,Version=v8.0", "net10.0": ".NETCoreApp,Version=v10.0"}[framework]
    if provenance.get("target") != target:
        raise ValueError("Structured target mismatch")
    for field in ("microsoftDirectoryServices", "microsoftAccountManagement"):
        if not isinstance(provenance.get(field), str) or not provenance[field].startswith("9.0.0+"):
            raise ValueError("Structured Microsoft package mismatch")
    if any(not isinstance(provenance.get(field), str) or not provenance[field] for field in ("runtime", "sdk", "architecture")):
        raise ValueError("Incomplete structured provenance")
    if not isinstance(row.get("microsoft"), (str, dict)):
        raise ValueError("Missing or invalid structured Microsoft observation")
    # Deliberately exclude adForLinux from the result. It is diagnostics only.
    return {"microsoft": row["microsoft"], "provenance": provenance}
