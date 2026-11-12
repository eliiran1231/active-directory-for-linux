#!/usr/bin/env python3
"""Offline parser/inventory tests. No dotnet, network, directory, or test execution."""
import json
from pathlib import Path
import tempfile
import unittest

import inventory


class SourceParserTests(unittest.TestCase):
    def parse(self, body):
        return inventory.parse_source(body, "Example.cs")

    def test_multiline_declarations_attributes_and_data(self):
        result = self.parse('''namespace Sample;
public partial class Examples(object data)
{
    [Xunit.TheoryAttribute]
    [InlineData(
       1,
       new[] { "a", "b" })]
    [InlineData(2, null), Trait("Category", "Detached")]
    public async System.Threading.Tasks.Task
        Multiline_test(
            int value,
            string[]? values)
    {
        Assert.Equal(value, values.Length);
    }
    [Fact(Skip = "Deliberate")]
    public void Expression_body() => Assert.True(true);
    [Theory, MemberData(nameof(Rows))]
    public void Dynamic(int value) { Assert.NotNull(value); }
}''')
        tests = result["test_declarations"]
        self.assertEqual(["Multiline_test", "Expression_body", "Dynamic"], [t["method"] for t in tests])
        self.assertEqual("Sample.Examples.Multiline_test", tests[0]["id"])
        self.assertEqual(2, tests[0]["inline_data_declarations"])
        self.assertTrue(tests[1]["has_skip_metadata"])
        self.assertEqual(["MemberData"], tests[2]["dynamic_data_attributes"])
        self.assertTrue(all(t["runtime_case_count"] is None for t in tests))
        self.assertEqual(3, result["lexical_counts"]["direct_assert_calls"])

    def test_comments_and_literal_contents_are_not_code(self):
        result = self.parse('''
namespace Sample;
// [Fact] public void Fake() { Assert.False(true); }
/* class Imaginary { [Theory] public void Fake() {} } */
class Real {
 [Fact] public void Actual() {
    var one = "Assert.Equal(1, 2); } [Fact]";
    var two = @"class Other { "" }";
    var three = $"{string.Join(", ", new[] { "}" })} Assert.True(false)";
    var four = """ [Fact] class Fake { Assert.Equal(1, 2); } """;
    var five = '\\'';
    Assert.True(true);
 }
}''')
        self.assertEqual(1, len(result["test_declarations"]))
        self.assertEqual(1, result["lexical_counts"]["direct_assert_calls"])

    def test_nested_classes_and_helpers_are_separate(self):
        result = self.parse('''namespace N;
class Outer {
 [Fact] public void Test() { Helper(); Assert.True(true); }
 private static void Helper() { Assert.Equal(1, 2); }
 class Inner {
  [Fact] public void Test() { Assert.IsType<int>(1); }
 }
}''')
        self.assertEqual(["N.Outer.Test", "N.Outer+Inner.Test"], [t["id"] for t in result["test_declarations"]])
        calls = result["call_sites"]
        self.assertEqual(1, sum(c["scope"] == "helper_or_support" for c in calls))
        self.assertEqual(1, result["test_declarations"][0]["lexical_counts"]["direct_assert_calls"])
        self.assertEqual("IsType", calls[-1]["assertion"])

    def test_comparison_and_recording_sites(self):
        result = self.parse('''namespace N; class C {
 [Fact] public void Test() {
  new Comparison("test").Check("x", 1, 2).CheckSet("s", a, b).Assert();
  new N.Comparison("test").Assert();
  DifferentialRecording.Write(output, "case", a, b);
  SuiteCapture.Comparison("value", a, b, file, member, line);
 }
}''')
        self.assertEqual({"comparison_constructions": 2, "check_calls": 1,
                          "check_set_calls": 1, "comparison_assert_calls": 2,
                          "direct_assert_calls": 0, "structured_recording_calls": 1,
                          "suite_operand_wrapper_calls": 0, "suite_comparison_recording_calls": 1},
                         result["lexical_counts"])

    def test_wrapper_admission_never_claims_microsoft_origin(self):
        result = self.parse('''class C {
 [Fact] public void Test() {
  Assert.Equal(SuiteCapture.Expected(expected, "expected", 1),
               SuiteCapture.Expected(actual, "actual", 1));
  Xunit.Assert.Equal<string>("constant", actual);
  Assert.True(Check(SuiteCapture.Expected(value, "nested", 1)));
  Assert.Equal(Foo<int, string>(), Bar<int, string>());
 }
}''')
        assertions = [c for c in result["call_sites"] if c["category"] == "direct_assert_calls"]
        self.assertEqual([0, 1], assertions[0]["wrapped_operand_positions"])
        self.assertEqual([], assertions[1]["wrapped_operand_positions"])
        self.assertEqual([], assertions[2]["wrapped_operand_positions"])
        self.assertEqual(2, assertions[3]["argument_count"])
        self.assertTrue(all(c["operand_origin"] == "unverified_not_necessarily_microsoft" for c in assertions))
        self.assertEqual(3, result["lexical_counts"]["suite_operand_wrapper_calls"])

    def test_conditional_branches_are_lexical_not_executed(self):
        result = self.parse('''class C {
 [Fact] public void Test() {
#if RECORDED_MICROSOFT_ORACLE
  Assert.True(true);
#else
  Assert.False(false);
#endif
 }
}''')
        self.assertTrue(result["contains_conditional_compilation"])
        self.assertEqual(2, result["lexical_counts"]["direct_assert_calls"])

    def test_malformed_source_fails_closed(self):
        for source in ('class C { [Fact] public void Missing() ; }',
                       '[Fact] public void OutsideClass() {}',
                       'class C { [Fact] public void Broken() {',
                       'class C { string s = "unfinished; }'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.parse(source)

    def test_generic_multiline_test_method(self):
        result = self.parse('''namespace N; class C {
 [Theory]
 public void Generic<T,
  U>(T left, U right) where T : class {
  Assert.Equal<T>(left, left);
 }
}''')
        self.assertEqual("N.C.Generic", result["test_declarations"][0]["id"])


class RepositoryInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = inventory.inventory()

    def test_current_suite_is_enumerated_and_not_reported_as_runtime_coverage(self):
        summary = self.report["summary"]
        self.assertGreaterEqual(summary["source_test_declarations"], 359)
        self.assertGreaterEqual(summary["source_test_classes"], 155)
        self.assertEqual(summary["source_test_declarations"], summary["fact_declarations"] + summary["theory_declarations"])
        self.assertEqual("static_source_inventory_not_runtime_coverage", self.report["measurement"])
        for field in ("runtime_discovered_cases", "executed_cases", "captured_observations"):
            self.assertIsNone(summary[field])
        for key in inventory.COUNT_KEYS:
            self.assertEqual(summary["lexical_counts_all_source"][key],
                             summary["lexical_counts_test_bodies"][key] + summary["lexical_counts_helpers_and_support"][key])
        self.assertEqual(summary["lexical_counts_all_source"]["direct_assert_calls"],
                         summary["direct_assert_calls_with_wrapped_operands"] + summary["direct_assert_calls_without_wrapped_operands"])

    def test_multiline_partial_and_dynamic_current_tests_are_present(self):
        tests = [test for file in self.report["files"] for test in file["test_declarations"]]
        multiline = next(t for t in tests if t["method"] == "Empty_collection_CopyTo_at_array_boundary_matches_microsoft")
        self.assertEqual(6, multiline["inline_data_declarations"])
        fixture = next(t for t in tests if t["method"] == "Test_data_consumers_register_their_class_fixture")
        self.assertEqual(["MemberData"], fixture["dynamic_data_attributes"])
        partial = next(c for c in self.report["classes"] if c["name"] == "SearcherValidationContractComparisonTests")
        self.assertEqual(2, len(partial["paths"]))

    def test_allowlist_exact_classes_and_pilot_are_independent(self):
        defaults, optional = inventory.read_offline_allowlist(inventory.ROOT / "tests/windows/run-offline-tests.py")
        classes = self.report["classes"]
        self.assertEqual(defaults, {c["name"] for c in classes if c["offline_allowlist"] == "default"})
        self.assertEqual(optional, {c["name"] for c in classes if c["offline_allowlist"] == "optional"})
        misleading = next(c for c in classes if c["name"] == "ConnectionStateOfflineComparisonTests")
        self.assertEqual("not_allowlisted", misleading["offline_allowlist"])
        pilot = [c for c in classes if c["portable_replay_classification"] == "existing_linked_portable_pilot"]
        self.assertEqual(4, len(pilot))
        self.assertTrue(all(c["offline_allowlist"] == "not_allowlisted" for c in pilot))

    def test_support_sources_and_fingerprints_are_included(self):
        files = {file["path"]: file for file in self.report["files"]}
        self.assertIn("tests/windows/Shared/OfflineFactAttribute.cs", files)
        self.assertEqual([], files["tests/windows/AdForLinux.DifferentialTests/Comparison.cs"]["test_declarations"])
        self.assertTrue(all(len(file["sha256"]) == 64 for file in files.values()))

    def test_allowlist_read_does_not_execute_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner.py"
            path.write_text('GROUPS = {"surface": ("AdForLinux.DifferentialTests", ["Safe"])}\n'
                            'EXTRA = {"surface": ["Optional"]}\nraise RuntimeError("MUST NOT EXECUTE")\n')
            self.assertEqual(({"Safe"}, {"Optional"}), inventory.read_offline_allowlist(path))

    def test_cli_serializes_deterministic_json(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "inventory.json"
            self.assertEqual(0, inventory.main(["--summary", "--output", str(output)]))
            parsed = json.loads(output.read_text())
            self.assertEqual(self.report["summary"]["source_test_declarations"], parsed["summary"]["source_test_declarations"])
            self.assertNotIn("files", parsed)

    def test_project_wildcard_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / inventory.SUITE
            project.mkdir(parents=True)
            (project / "AdForLinux.DifferentialTests.csproj").write_text('<Project><ItemGroup><Compile Include="../*.cs" /></ItemGroup></Project>')
            with self.assertRaises(ValueError):
                inventory.source_paths(root)


if __name__ == "__main__":
    unittest.main()
