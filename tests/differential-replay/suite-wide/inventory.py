#!/usr/bin/env python3
"""Inventory source declarations and lexical capture gaps; never execute a test."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
SUITE = Path("tests/AdForLinux.DifferentialTests")
TEST_ATTRIBUTES = {"Fact", "Theory", "OfflineFact", "OfflineTheory"}
DATA_ATTRIBUTES = {"InlineData", "MemberData", "ClassData"}
COUNT_KEYS = ("comparison_constructions", "check_calls", "check_set_calls",
              "comparison_assert_calls", "direct_assert_calls", "structured_recording_calls",
              "suite_operand_wrapper_calls", "suite_comparison_recording_calls")
LIVE_IDENTIFIERS = {"TestDataFixture", "DifferentialSettings", "CompatibilityOwnedDirectoryObjects"}


@dataclass(frozen=True)
class Token:
    value: str
    offset: int
    line: int


def _quoted_end(source: str, start: int) -> int:
    """Consume C# character/regular/verbatim/interpolated/raw literals as opaque data."""
    pos = start
    while pos < len(source) and source[pos] in "@$":
        pos += 1
    quote = source[pos]
    prefix = source[start:pos]
    if quote == '"':
        run = len(source[pos:]) - len(source[pos:].lstrip('"'))
        if run >= 3:
            end = source.find('"' * run, pos + run)
            if end < 0:
                raise ValueError("Unterminated raw string")
            return end + run
    verbatim = "@" in prefix
    interpolated = "$" in prefix
    pos += 1
    while pos < len(source):
        char = source[pos]
        if char == quote:
            if verbatim and pos + 1 < len(source) and source[pos + 1] == quote:
                pos += 2
                continue
            return pos + 1
        if char == "\\" and not verbatim:
            pos += 2
            continue
        if interpolated and char == "{":
            if source.startswith("{{", pos):
                pos += 2
                continue
            # Ignore interpolation expressions as part of the literal, but allow
            # their nested strings/braces so their quotes cannot corrupt scopes.
            depth = 1
            pos += 1
            while pos < len(source) and depth:
                if source.startswith("//", pos):
                    end = source.find("\n", pos)
                    pos = len(source) if end < 0 else end
                elif source.startswith("/*", pos):
                    end = source.find("*/", pos + 2)
                    if end < 0:
                        raise ValueError("Unterminated interpolation comment")
                    pos = end + 2
                elif _starts_literal(source, pos):
                    pos = _quoted_end(source, pos)
                else:
                    depth += (source[pos] == "{") - (source[pos] == "}")
                    pos += 1
            continue
        pos += 1
    raise ValueError("Unterminated string/character literal")


def _starts_literal(source: str, pos: int) -> bool:
    return source[pos] in "\"'" or bool(re.match(r'(?:\$+@?|@\$?)"', source[pos:]))


def tokenize(source: str) -> list[Token]:
    """Keep locations, mask comments/literals, and retain both #if branches."""
    tokens = []
    pos, line = 0, 1
    while pos < len(source):
        start, first_line = pos, line
        if source[pos].isspace():
            pos += 1
        elif source.startswith("//", pos) or source[pos] == "#":
            end = source.find("\n", pos)
            pos = len(source) if end < 0 else end
        elif source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            if end < 0:
                raise ValueError("Unterminated block comment")
            pos = end + 2
        elif _starts_literal(source, pos):
            pos = _quoted_end(source, pos)
            tokens.append(Token("<literal>", start, line))
        else:
            match = re.match(r"@?[A-Za-z_]\w*|\d+(?:\.\d+)?|=>|::|\?\.", source[pos:])
            value = match.group() if match else source[pos]
            tokens.append(Token(value, pos, line))
            pos += len(value)
        line += source[start:pos].count("\n")
        assert line >= first_line
    return tokens


def pairs(tokens: list[Token]) -> tuple[dict[int, int], dict[int, int]]:
    result, depths, stack = {}, {}, []
    opens = {"(": ")", "[": "]", "{": "}"}
    for index, token in enumerate(tokens):
        depths[index] = sum(tokens[item].value == "{" for item in stack)
        if token.value in opens:
            stack.append(index)
        elif token.value in opens.values():
            if not stack or opens[tokens[stack[-1]].value] != token.value:
                raise ValueError(f"Unbalanced delimiter on line {token.line}")
            opening = stack.pop()
            result[opening] = index
    if stack:
        raise ValueError(f"Unclosed delimiter on line {tokens[stack[-1]].line}")
    return result, depths


def _attributes(tokens, begin, end, paired):
    """Attribute short names; skip their argument lists, including nested arrays."""
    names, skip = [], False
    pos = begin + 1
    while pos < end:
        if tokens[pos].value in ("(", "[", "{"):
            # Skip= is metadata only; no claim the case will actually be skipped.
            skip |= any(tokens[index].value == "Skip" and tokens[index + 1].value == "="
                        for index in range(pos, paired[pos] - 1))
            pos = paired[pos] + 1
            continue
        if tokens[pos].value == ",":
            pos += 1
            continue
        if re.fullmatch(r"@?[A-Za-z_]\w*", tokens[pos].value):
            name = tokens[pos].value
            pos += 1
            while pos + 1 < end and tokens[pos].value in (".", "::"):
                name = tokens[pos + 1].value
                pos += 2
            names.append(name.removesuffix("Attribute"))
        else:
            pos += 1
    return names, skip


def parse_source(source: str, path: str) -> dict:
    tokens = tokenize(source)
    paired, depths = pairs(tokens)
    namespace = ""
    for index, token in enumerate(tokens):
        if token.value == "namespace":
            end = index + 1
            while end < len(tokens) and tokens[end].value not in (";", "{"):
                end += 1
            namespace = "".join(t.value for t in tokens[index + 1:end])
            break
    classes = []
    for index, token in enumerate(tokens):
        if token.value != "class" or index and tokens[index - 1].value == ":":
            continue
        if index + 1 >= len(tokens) or not re.fullmatch(r"@?[A-Za-z_]\w*", tokens[index + 1].value):
            continue
        pos = index + 2
        while pos < len(tokens) and tokens[pos].value not in ("{", ";"):
            if tokens[pos].value in ("(", "["):
                pos = paired[pos] + 1
            else:
                pos += 1
        if pos >= len(tokens) or tokens[pos].value != "{":
            continue
        parent = next((c for c in reversed(classes) if c["start"] < index < c["end"]), None)
        name = tokens[index + 1].value.lstrip("@")
        fullname = f'{parent["full_name"]}+{name}' if parent else f"{namespace}.{name}".lstrip(".")
        classes.append({"name": name, "full_name": fullname, "start": pos,
                        "end": paired[pos], "line": token.line})
    declarations, recognized = [], set()
    for cls in classes:
        pos = cls["start"] + 1
        while pos < cls["end"]:
            if tokens[pos].value != "[" or depths[pos] != depths[cls["start"]] + 1:
                pos += 1
                continue
            start, attrs, skip = pos, [], False
            while pos < cls["end"] and tokens[pos].value == "[":
                names, has_skip = _attributes(tokens, pos, paired[pos], paired)
                attrs.extend(names)
                skip |= has_skip
                pos = paired[pos] + 1
            kind = [a for a in attrs if a in TEST_ATTRIBUTES]
            if not kind:
                continue
            recognized.add(start)
            # Method names and parameter lists may span any number of lines.
            parameter_start = pos
            while parameter_start < cls["end"] and tokens[parameter_start].value not in ("(", "{", ";", "=>"):
                parameter_start += 1
            if parameter_start >= cls["end"] or tokens[parameter_start].value != "(":
                raise ValueError(f"Unrecognized test declaration at {path}:{tokens[start].line}")
            name_index = parameter_start - 1
            if tokens[name_index].value == ">":
                level = 1
                name_index -= 1
                while name_index >= pos and level:
                    level += (tokens[name_index].value == ">") - (tokens[name_index].value == "<")
                    name_index -= 1
            name = tokens[name_index].value.lstrip("@")
            if not re.fullmatch(r"[A-Za-z_]\w*", name):
                raise ValueError(f"Unsupported test method signature at {path}:{tokens[start].line}")
            body = paired[parameter_start] + 1
            while body < cls["end"] and tokens[body].value not in ("{", "=>", ";"):
                body += 1
            if body >= cls["end"] or tokens[body].value == ";":
                raise ValueError(f"Missing test body at {path}:{tokens[start].line}")
            if tokens[body].value == "{":
                end = paired[body]
            else:
                end = body + 1
                while end < cls["end"] and tokens[end].value != ";":
                    end = paired[end] + 1 if tokens[end].value in ("(", "[", "{") else end + 1
                if end >= cls["end"]:
                    raise ValueError(f"Unclosed test expression at {path}:{tokens[start].line}")
            declarations.append({"id": f'{cls["full_name"]}.{name}', "class": cls["name"],
                                 "class_full_name": cls["full_name"], "method": name,
                                 "path": path, "line": tokens[name_index].line,
                                 "attribute_line": tokens[start].line, "end_line": tokens[end].line,
                                 "kind": kind[0], "attributes": attrs,
                                 "inline_data_declarations": attrs.count("InlineData"),
                                 "dynamic_data_attributes": [a for a in attrs if a in ("MemberData", "ClassData")],
                                 "has_skip_metadata": skip,
                                 "runtime_case_count": None,
                                 "_body": body, "_end": end})
            pos = end + 1
    # Fail closed if a recognizable test attribute was not bound to a declaration.
    # Attribute groups can also contain InlineData or qualified Xunit attributes.
    for index, token in enumerate(tokens):
        if token.value != "[":
            continue
        names, _ = _attributes(tokens, index, paired[index], paired)
        if set(names) & TEST_ATTRIBUTES and index not in recognized:
            if not any(d["attribute_line"] <= token.line <= d["line"] for d in declarations):
                raise ValueError(f"Unclaimed test attribute at {path}:{token.line}")
    calls = []
    for index, token in enumerate(tokens):
        category, metadata = None, {}
        if token.value == "Comparison" and index + 1 < len(tokens) and tokens[index + 1].value == "(":
            before = index - 1
            while before >= 1 and tokens[before].value in (".", "::"):
                before -= 2
            if before >= 0 and tokens[before].value == "new":
                category = "comparison_constructions"
        if index >= 1 and tokens[index - 1].value in (".", "?.") and index + 1 < len(tokens) and tokens[index + 1].value == "(":
            category = {"Check": "check_calls", "CheckSet": "check_set_calls",
                        "Assert": "comparison_assert_calls"}.get(token.value, category)
        if token.value == "Assert" and index + 3 < len(tokens) and tokens[index + 1].value == ".":
            following = index + 3
            if tokens[following].value == "<":
                level = 1
                following += 1
                while following < len(tokens) and level:
                    level += (tokens[following].value == "<") - (tokens[following].value == ">")
                    following += 1
            if following < len(tokens) and tokens[following].value == "(":
                category = "direct_assert_calls"
                operands = argument_ranges(tokens, following, paired)
                wrapped = [position for position, (begin, end) in enumerate(operands)
                           if [t.value for t in tokens[begin:begin + 4]] == ["SuiteCapture", ".", "Expected", "("]
                           and paired[begin + 3] == end - 1]
                metadata = {"assertion": tokens[index + 2].value,
                            "argument_count": len(operands), "wrapped_operand_positions": wrapped,
                            "operand_origin": "unverified_not_necessarily_microsoft",
                            "capture_admission": "wrapped_operand_sites" if wrapped else "no_top_level_operand_wrapper"}
        if token.value == "DifferentialRecording" and [t.value for t in tokens[index + 1:index + 4]] == [".", "Write", "("]:
            category = "structured_recording_calls"
        if token.value == "SuiteCapture" and index + 3 < len(tokens) and tokens[index + 1].value == "." and tokens[index + 3].value == "(":
            category = {"Expected": "suite_operand_wrapper_calls",
                        "Comparison": "suite_comparison_recording_calls"}.get(tokens[index + 2].value, category)
        if category:
            owner = next((d["id"] for d in declarations if d["_body"] < index < d["_end"]), None)
            cls = next((c["full_name"] for c in reversed(classes) if c["start"] < index < c["end"]), None)
            calls.append({"category": category, "line": token.line, "class_full_name": cls,
                          "test_id": owner, "scope": "test_body" if owner else "helper_or_support", **metadata})
    for declaration in declarations:
        del declaration["_body"], declaration["_end"]
        declaration["lexical_counts"] = counts(c for c in calls if c["test_id"] == declaration["id"])
    class_signals = {}
    for cls in classes:
        class_signals[cls["full_name"]] = sorted({t.value for t in tokens[cls["start"]:cls["end"]] if t.value in LIVE_IDENTIFIERS})
        # Primary constructor/base-list fixture references precede the body.
        header = [t for t in tokens if cls["line"] <= t.line <= tokens[cls["start"]].line]
        class_signals[cls["full_name"]] = sorted(set(class_signals[cls["full_name"]]) | {t.value for t in header if t.value in LIVE_IDENTIFIERS})
    return {"path": path, "sha256": hashlib.sha256(source.encode()).hexdigest(),
            "test_declarations": declarations, "lexical_counts": counts(calls), "call_sites": calls,
            "class_live_identifier_signals": class_signals,
            "contains_conditional_compilation": bool(re.search(r"^\s*#(?:if|elif)\b", source, re.M))}


def argument_ranges(tokens, opening, paired):
    """Split ordinary invocation arguments, skipping nested delimiters/generics."""
    end = paired[opening]
    if opening + 1 == end:
        return []
    start, pos, result = opening + 1, opening + 1, []
    while pos < end:
        value = tokens[pos].value
        if value in ("(", "[", "{"):
            pos = paired[pos] + 1
            continue
        if value == "<":
            # Only a plausible generic type argument list, not x < y, may hide commas.
            close, level = pos + 1, 1
            while close < end and level:
                candidate = tokens[close].value
                if candidate not in ("<", ">", ".", "::", ",", "?", "[", "]") and not re.fullmatch(r"@?[A-Za-z_]\w*", candidate):
                    break
                level += (candidate == "<") - (candidate == ">")
                close += 1
            if level == 0 and close < end and tokens[close].value in ("(", ".", "::", "[", ",", ")"):
                pos = close
                continue
        if value == ",":
            result.append((start, pos))
            start = pos + 1
        pos += 1
    result.append((start, end))
    return result


def source_paths(root: Path) -> list[Path]:
    """Current SDK default compile items plus explicit linked C# files."""
    project = root / SUITE / "AdForLinux.DifferentialTests.csproj"
    document = ET.parse(project)
    if document.findtext(".//EnableDefaultCompileItems") == "false":
        raise ValueError("Differential project disabled default compile sources; scope needs review")
    for group in document.iter():
        if group.get("Condition") and group.findall(".//Compile"):
            raise ValueError("Conditional differential Compile group requires scope review")
    paths = {path.resolve() for path in (root / SUITE).rglob("*.cs")
             if not {"bin", "obj"}.intersection(path.relative_to(root / SUITE).parts)}
    if any(not path.is_relative_to(root) for path in paths):
        raise ValueError("Differential default source escapes the repository")
    for element in document.findall(".//Compile"):
        if element.get("Remove") or element.get("Exclude") or element.get("Condition"):
            raise ValueError("Conditional/removed differential Compile sources require scope review")
        include = element.get("Include")
        if not include:
            continue
        if any(char in include for char in "*?$"):
            raise ValueError("Differential Compile include is not explicit")
        path = (project.parent / include.replace("\\", "/")).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Differential Compile source escapes the repository")
        paths.add(path)
    return sorted(paths)


def counts(calls) -> dict:
    tally = Counter(c["category"] for c in calls)
    return {key: tally[key] for key in COUNT_KEYS}


def read_offline_allowlist(path: Path) -> tuple[set[str], set[str]]:
    # Parse literals, do not import/execute the test runner or resolve settings.
    assignments = {}
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ("GROUPS", "EXTRA"):
                    assignments[target.id] = ast.literal_eval(node.value)
    project, defaults = assignments["GROUPS"]["surface"]
    if project != "AdForLinux.DifferentialTests":
        raise ValueError("Offline surface group points to an unexpected project")
    return set(defaults), set(assignments["EXTRA"].get("surface", []))


def portable_sources(root: Path) -> set[Path]:
    project = root / "tests/differential-replay/AdForLinux.DifferentialTests.csproj"
    document = ET.parse(project)
    defaults = document.findtext(".//EnableDefaultCompileItems")
    if defaults != "false":
        raise ValueError("Portable replay project no longer has an explicit source allowlist")
    result = set()
    for group in document.iter():
        if group.get("Condition") and group.findall(".//Compile"):
            raise ValueError("Conditional portable Compile group requires scope review")
    for element in document.findall(".//Compile"):
        if element.get("Condition") or element.get("Remove") or element.get("Exclude"):
            raise ValueError("Conditional/removed portable Compile sources require scope review")
        include = element.get("Include", "")
        if any(char in include for char in "*?$"):
            raise ValueError("Portable replay Compile list is not explicit")
        result.add((project.parent / include.replace("\\", "/")).resolve())
    return result


def inventory(root: Path = ROOT) -> dict:
    root = root.resolve()
    defaults, optional = read_offline_allowlist(root / "tests/run-offline-tests.py")
    linked = portable_sources(root)
    files = []
    for path in source_paths(root):
        content = path.read_bytes()
        file = parse_source(content.decode("utf-8-sig"), path.relative_to(root).as_posix())
        file["sha256"] = hashlib.sha256(content).hexdigest()
        files.append(file)
    tests = [test for file in files for test in file["test_declarations"]]
    identities = [test["id"] for test in tests]
    if len(identities) != len(set(identities)):
        raise ValueError("Duplicate source test identities (overloads/conditional declarations need review)")
    classes = []
    qualified_defaults = {f"AdForLinux.DifferentialTests.{name}" for name in defaults}
    qualified_optional = {f"AdForLinux.DifferentialTests.{name}" for name in optional}
    for fullname in sorted({test["class_full_name"] for test in tests}):
        members = [test for test in tests if test["class_full_name"] == fullname]
        name = members[0]["class"]
        paths = sorted({test["path"] for test in members})
        signals = sorted({signal for file in files for signal in file["class_live_identifier_signals"].get(fullname, [])})
        admission = ("default" if fullname in qualified_defaults else
                     "optional" if fullname in qualified_optional else "not_allowlisted")
        is_pilot = all((root / path).resolve() in linked for path in paths)
        if is_pilot:
            replay = "existing_linked_portable_pilot"
        elif admission != "not_allowlisted":
            replay = "detached_oracle_adapter_review_needed"
        elif signals:
            replay = "controlled_transport_or_live_scenario_review_needed"
        else:
            replay = "unreviewed_windows_or_live_dependencies"
        classes.append({"name": name, "full_name": fullname, "paths": paths,
                        "source_test_declarations": len(members), "offline_allowlist": admission,
                        "live_identifier_signals": signals, "portable_replay_classification": replay})
        for member in members:
            member["offline_allowlist"] = admission
            member["portable_replay_classification"] = replay
    missing = (qualified_defaults | qualified_optional) - {cls["full_name"] for cls in classes}
    if missing:
        raise ValueError(f"Offline allowlisted classes missing source tests: {sorted(missing)}")
    calls = [call for file in files for call in file["call_sites"]]
    summary = {
        "source_files": len(files), "source_test_classes": len(classes), "source_test_declarations": len(tests),
        "fact_declarations": sum(test["kind"] in ("Fact", "OfflineFact") for test in tests),
        "theory_declarations": sum(test["kind"] in ("Theory", "OfflineTheory") for test in tests),
        "inline_data_declarations": sum(test["inline_data_declarations"] for test in tests),
        "tests_with_dynamic_data": sum(bool(test["dynamic_data_attributes"]) for test in tests),
        "tests_with_skip_metadata": sum(test["has_skip_metadata"] for test in tests),
        "class_offline_admission_counts": dict(sorted(Counter(cls["offline_allowlist"] for cls in classes).items())),
        "class_replay_counts": dict(sorted(Counter(cls["portable_replay_classification"] for cls in classes).items())),
        "lexical_counts_all_source": counts(calls),
        "lexical_counts_test_bodies": counts(c for c in calls if c["scope"] == "test_body"),
        "lexical_counts_helpers_and_support": counts(c for c in calls if c["scope"] == "helper_or_support"),
        "direct_assert_calls_with_wrapped_operands": sum(c["category"] == "direct_assert_calls" and bool(c["wrapped_operand_positions"]) for c in calls),
        "direct_assert_calls_without_wrapped_operands": sum(c["category"] == "direct_assert_calls" and not c["wrapped_operand_positions"] for c in calls),
        "direct_assert_calls_first_two_operands_wrapped": sum(c["category"] == "direct_assert_calls" and {0, 1}.issubset(c["wrapped_operand_positions"]) for c in calls),
        "runtime_discovered_cases": None, "executed_cases": None, "captured_observations": None,
    }
    return {"schema_version": 1, "measurement": "static_source_inventory_not_runtime_coverage",
            "scope": "Differential project default and explicit linked C# sources", "summary": summary, "classes": classes, "files": files,
            "limitations": [
                "Counts are lexical source sites, not executed assertions, behavior coverage, or capture completeness.",
                "Both conditional compilation branches are included; no MSBuild or C# semantic analysis is performed.",
                "Comments and literal contents, including interpolation expressions, are excluded from call-site counts.",
                "MemberData/ClassData are not evaluated. InlineData declarations are not discovered runtime cases.",
                "Helper/support sites are counted separately and not attributed transitively to tests.",
                "Check/CheckSet/Assert receivers are matched lexically, not type-resolved; aliases/static imports may be missed.",
                "Offline admission uses exact runner classes; names, source signals and replay membership grant no live or offline execution permission.",
                "Non-allowlisted classes can be detached, Windows-native or live. Dependency signals require manual scenario review.",
                "The existing portable pilot remains a bounded source-linked project; capture infrastructure does not make other tests replayable.",
                "SDK default .cs sources excluding bin/obj plus explicit Compile includes are inventoried. Generated sources and MSBuild imports require scope review.",
                "SuiteCapture.Expected wrappers preserve assertion operands but do not establish Microsoft origin, runtime reachability, or replay completeness.",
            ]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root; never executes code from it")
    parser.add_argument("--output", type=Path, help="Write deterministic JSON; otherwise stdout")
    parser.add_argument("--summary", action="store_true", help="Print summary only")
    args = parser.parse_args(argv)
    try:
        report = inventory(args.root)
        if args.summary:
            report = {"measurement": report["measurement"], "summary": report["summary"]}
        serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(serialized, encoding="utf-8")
        else:
            sys.stdout.write(serialized)
        return 0
    except (ValueError, OSError, KeyError, SyntaxError, ET.ParseError) as error:
        parser.exit(2, f"Inventory refused: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
