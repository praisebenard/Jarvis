import ast
import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path


class PHPFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        tree = ast.parse(source_path.read_text())
        functions = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name in {"analyze_php_flow", "_trace_php_flow"}
        ]
        namespace = {
            "Path": Path,
            "re": re,
            "REPORTS_DIR": self.root / "reports",
        }
        exec(
            compile(
                ast.fix_missing_locations(
                    ast.Module(body=functions, type_ignores=[])
                ),
                str(source_path),
                "exec",
            ),
            namespace,
        )
        self.analyze = namespace["analyze_php_flow"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def analyze_fixture(self, filename, php_source):
        fixture = self.root / filename
        fixture.write_text(php_source)
        with contextlib.redirect_stdout(io.StringIO()):
            self.analyze(fixture)
        report = self.root / "reports" / f"{fixture.stem}_php_flow.txt"
        return report.read_text()

    def test_unrelated_input_and_sql_are_not_linked(self):
        report = self.analyze_fixture(
            "unrelated.php",
            """<?php
$id = $_GET['id'];
echo $id;
$query = "SELECT * FROM users";
mysqli_query($db, $query);
""",
        )

        self.assertIn("Sink text (output)", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("Explicit textual relationship: [GET] id", report)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Sink text (output)", source_flow)
        self.assertNotIn("Sink text (SQL/query)", source_flow)
        self.assertIn("no vulnerability is confirmed", report)

    def test_direct_request_reference_in_query_is_reported(self):
        report = self.analyze_fixture(
            "direct_query.php",
            """<?php
mysqli_query($db, $_GET['id']);
""",
        )

        self.assertIn("Explicit textual relationship: [GET] id", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertNotIn("Tracked-variable association:", report)

    def test_source_flow_relationships_identify_each_sink_location(self):
        report = self.analyze_fixture(
            "two_sinks.php",
            """<?php
$output_value = $_GET['id'];
echo $output_value;
$query_value = $_POST['name'];
mysqli_query($db, $query_value);
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        output_sink = source_flow.split("Sink text (output)", 1)[1].split(
            "Sink text (SQL/query)", 1
        )[0]
        sql_sink = source_flow.split("Sink text (SQL/query)", 1)[1]
        self.assertIn("[GET] id at two_sinks.php:2", output_sink)
        self.assertIn("sink at two_sinks.php:3", output_sink)
        self.assertIn("Tracked-variable association: $output_value", output_sink)
        self.assertNotIn("$query_value", output_sink)
        self.assertIn("[POST] name at two_sinks.php:4", sql_sink)
        self.assertIn("sink at two_sinks.php:5", sql_sink)
        self.assertIn("Tracked-variable association: $query_value", sql_sink)
        self.assertNotIn("$output_value", sql_sink)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_transformation_call_is_observed_without_claiming_effectiveness(self):
        report = self.analyze_fixture(
            "transform.php",
            """<?php
$id = $_GET['id'];
$safe = mysqli_real_escape_string($db, $id);
$sql = "SELECT * FROM users WHERE id = '$safe'";
mysqli_query($db, $sql);
""",
        )

        self.assertNotIn("Explicit textual relationship: [GET] id", report)
        self.assertIn("Unresolved assignment", report)
        self.assertIn("sanitization effectiveness are not inferred", report)

    def test_unrelated_stored_output_does_not_create_dataflow_chain(self):
        report = self.analyze_fixture(
            "disconnected_output.php",
            """<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users";
mysqli_query($db, $sql);
echo xss_check_1($row->entry);
""",
        )

        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Stored XSS review:", report)

    def test_misleading_variable_names_do_not_create_source_evidence(self):
        report = self.analyze_fixture(
            "misleading_names.php",
            """<?php
$user_input = 'local constant';
$sql = "SELECT * FROM users WHERE id=" . $user_input;
mysqli_query($db, $sql);
""",
        )
        self.assertIn("NO INPUT DETECTED", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_echoed_sql_like_string_is_not_classified_as_sql_sink(self):
        report = self.analyze_fixture(
            "harmless_string.php",
            """<?php
$value = $_GET['message'];
echo "SELECT is just text: " . $value;
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertNotIn("Sink text (SQL/query)", report)
        self.assertIn("no vulnerability is confirmed", report)

    def test_overwritten_input_is_not_reported_as_reaching_sink(self):
        report = self.analyze_fixture(
            "overwritten.php",
            """<?php
$value = $_GET['id'];
$value = 'constant';
echo $value;
""",
        )
        self.assertIn("[GET] id", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_input_without_relevant_sink_is_not_reported_as_flow(self):
        report = self.analyze_fixture(
            "unused_input.php",
            """<?php
$value = $_POST['note'];
$message = 'saved';
""",
        )
        self.assertIn("[POST] note", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertIn("INPUT DETECTED", report)

    def test_conditional_request_assignments_are_unresolved_input_evidence(self):
        for method in ("GET", "POST", "REQUEST"):
            with self.subTest(method=method):
                report = self.analyze_fixture(
                    f"conditional_{method.lower()}_input.php",
                    f"""<?php
if ($enabled) {{
    $value = $_{method}['item'];
}}
echo $value;
""",
                )
                self.assertIn(f"[{method}] item", report)
                self.assertIn("UNRESOLVED INPUT EVIDENCE", report)
                self.assertIn("Unresolved conditional assignment", report)
                self.assertNotIn("Explicit textual relationship", report)
                self.assertNotIn("NO INPUT DETECTED", report)

    def test_genuinely_input_free_file_reports_no_input_detected(self):
        report = self.analyze_fixture(
            "constant_only.php",
            """<?php
$message = 'Welcome';
echo $message;
""",
        )
        self.assertIn("No direct GET/POST/REQUEST inputs detected.", report)
        self.assertIn("NO INPUT DETECTED", report)
        self.assertNotIn("UNRESOLVED INPUT EVIDENCE", report)

    def test_database_sink_is_reported_without_request_input(self):
        report = self.analyze_fixture(
            "database_sink_only.php",
            """<?php
$query = 'SELECT 1';
mysqli_query($db, $query);
""",
        )
        self.assertIn("Sink observations:", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("database_sink_only.php:3", report)
        self.assertIn("mysqli_query($db, $query)", report)
        self.assertIn("NO INPUT DETECTED", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertIn("no vulnerability is confirmed", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Observed sink patterns", report)
        self.assertIn("Supported source-to-sink evidence", report)
        self.assertIn("Evidence and confidence limitations:", report)

    def test_conditional_database_sink_is_observed_without_flow_claim(self):
        report = self.analyze_fixture(
            "conditional_database_sink.php",
            """<?php
if ($enabled) {
    mysqli_query($db, $query);
}
""",
        )
        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("conditional_database_sink.php:3", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertIn("NO INPUT DETECTED", report)

    def test_output_sink_is_reported_without_request_input(self):
        report = self.analyze_fixture(
            "output_sink_only.php",
            """<?php
print $message;
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertIn("output_sink_only.php:2", report)
        self.assertIn("NO INPUT DETECTED", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_call_like_text_in_comments_and_strings_is_not_a_sink(self):
        report = self.analyze_fixture(
            "sink_text_only.php",
            """<?php
// mysqli_query($db, $query); echo $value;
$example = 'mysql_query($query); echo $value;';
""",
        )
        self.assertIn("NO INPUT DETECTED", report)
        self.assertIn("No sink observations detected.", report)
        self.assertNotIn("Sink text (SQL/query)", report)
        self.assertNotIn("Sink text (output)", report)

    def test_direct_and_multi_step_assignment_are_traced(self):
        report = self.analyze_fixture(
            "assignments.php",
            """<?php
$first = $_POST['name'];
$second = $first;
$query = "SELECT * FROM users WHERE name='" . $second;
mysqli_query($db, $query);
""",
        )
        self.assertIn("[POST] name", report)
        self.assertIn("Assignment evidence", report)
        self.assertIn("Sink text (SQL/query)", report)

    def test_direct_request_value_is_reported_and_reaches_output(self):
        report = self.analyze_fixture(
            "direct_request_value.php",
            """<?php
$value = $_POST['entry'];
echo $value;
""",
        )
        self.assertIn("Input evidence:\n  [POST] entry", report)
        self.assertIn("Explicit textual relationship: [POST] entry", report)
        self.assertIn("Request presence evidence:\n  None detected.", report)
        self.assertIn("direct_request_value.php:2", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Supported source-to-sink evidence", report)

    def test_unresolved_function_call_is_a_candidate_not_a_flow_claim(self):
        report = self.analyze_fixture(
            "unresolved_report_candidate.php",
            """<?php
$input = $_GET['value'];
echo unknown_transform($input);
""",
        )
        self.assertIn("Unresolved analysis candidates:", report)
        self.assertIn("Unresolved function call unknown_transform", report)
        self.assertIn("Sink text (output)", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_supported_static_flow_remains_unconfirmed_vulnerability_candidate(self):
        report = self.analyze_fixture(
            "supported_flow_unconfirmed.php",
            """<?php
$input = $_GET['value'];
echo $input;
""",
        )
        self.assertIn("Explicit textual relationship: [GET] value", report)
        self.assertIn("Supported source-to-sink evidence", report)
        self.assertIn("Review status:\n  SOURCE PATTERNS DETECTED", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("runtime behavior was not validated", report)
        self.assertIn("no vulnerability is confirmed", report)

    def test_isset_ternary_is_presence_evidence_not_value_provenance(self):
        report = self.analyze_fixture(
            "presence_flag.php",
            """<?php
$entry_all = isset($_POST['entry_all']) ? 1 : 0;
echo $entry_all;
""",
        )
        self.assertIn("Request presence evidence:", report)
        self.assertIn("[POST] entry_all", report)
        self.assertIn("presence", report.lower())
        self.assertNotIn("Input evidence:\n  [POST] entry_all", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertIn("Unresolved request-reference evidence:\n  None detected.", report)

    def test_alias_of_presence_flag_does_not_gain_request_value_provenance(self):
        report = self.analyze_fixture(
            "presence_flag_alias.php",
            """<?php
$entry_all = isset($_POST['entry_all']) ? 1 : 0;
$copy = $entry_all;
echo $copy;
""",
        )
        self.assertIn("Request presence evidence:", report)
        self.assertIn("[POST] entry_all", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_alias_of_direct_request_value_preserves_provenance(self):
        report = self.analyze_fixture(
            "direct_request_alias.php",
            """<?php
$value = $_POST['entry'];
$copy = $value;
echo $copy;
""",
        )
        self.assertIn(
            "Explicit textual relationship: [POST] entry at direct_request_alias.php:2 "
            "reaches a referenced variable or appears directly in the sink "
            "at direct_request_alias.php:4.",
            report,
        )
        self.assertIn("Tracked-variable association: $copy", report)
        self.assertIn("Assignment evidence: direct_request_alias.php:3", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_direct_value_concatenation_with_question_mark_string_is_traced(self):
        report = self.analyze_fixture(
            "request_concat_question_mark.php",
            """<?php
$value = '/search?q=' . $_GET['query'];
echo $value;
""",
        )
        self.assertIn("Explicit textual relationship: [GET] query", report)

    def test_unsupported_request_expression_is_unresolved_not_presence(self):
        report = self.analyze_fixture(
            "unsupported_request_expression.php",
            """<?php
$value = custom_transform($_GET['value']);
echo $value;
""",
        )
        self.assertIn("Unresolved request-reference evidence:", report)
        self.assertIn("[GET] value", report)
        self.assertIn("unsupported_request_expression.php:2", report)
        self.assertIn("Request presence evidence:\n  None detected.", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_presence_flag_does_not_link_to_unrelated_sink(self):
        report = self.analyze_fixture(
            "presence_unrelated_sink.php",
            """<?php
$entry_all = isset($_POST['entry_all']) ? 1 : 0;
$message = 'constant';
echo $message;
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertIn("Request presence evidence:", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_dot_assignment_preserves_explicit_source_chain(self):
        report = self.analyze_fixture(
            "dot_assignment.php",
            """<?php
$value = $_GET['name'];
$query = "SELECT name FROM users WHERE name='";
$query .= $value;
mysqli_query($db, $query);
""",
        )
        self.assertIn("Explicit textual relationship: [GET] name", report)
        self.assertIn("dot_assignment.php:4", report)

    def test_conditional_reassignment_is_reported_as_unresolved(self):
        report = self.analyze_fixture(
            "conditional_assignment.php",
            """<?php
$value = $_GET['id'];
if ($replace) {
    $value = 'constant';
}
echo $value;
""",
        )
        self.assertNotIn("Explicit textual relationship", report)
        self.assertIn("Unresolved conditional assignment", report)

    def test_simple_if_assignment_alias_and_concatenation_trace_conditionally(self):
        report = self.analyze_fixture(
            "simple_conditional_flow.php",
            """<?php
if ($enabled) {
    $value = $_GET['id'];
    $alias = $value;
    $query = "SELECT " . $alias;
    mysqli_query($db, $query);
}
""",
        )
        self.assertIn("simple_conditional_flow.php:3", report)
        self.assertIn("simple_conditional_flow.php:6", report)
        self.assertIn("Conditional textual relationship: [GET] id", report)
        self.assertIn("Tracked-variable association: $query", report)
        self.assertIn("Assignment evidence", report)
        self.assertIn("[conditional context; flow not established]", report)
        self.assertIn(
            "Review status:\n  CONDITIONAL SOURCE PATTERNS; FLOW NOT ESTABLISHED",
            report,
        )
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Unresolved conditional input evidence:\n  None detected.", report)
        self.assertIn("no vulnerability is confirmed", report)

    def test_next_line_if_brace_traces_assignment_and_alias_with_exact_lines(self):
        report = self.analyze_fixture(
            "next_line_brace_flow.php",
            """<?php
if ($enabled)
{
    $value = $_GET['id'];
    $alias = $value;
    echo $alias;
}
""",
        )
        self.assertIn("Conditional textual relationship: [GET] id at next_line_brace_flow.php:4", report)
        self.assertIn("Assignment evidence: next_line_brace_flow.php:5", report)
        self.assertIn("Sink text (output) at next_line_brace_flow.php:6", report)
        self.assertNotIn("Unresolved conditional input evidence:\n  [GET] id", report)

    def test_next_line_if_brace_does_not_link_unrelated_input_and_sink(self):
        report = self.analyze_fixture(
            "next_line_unrelated.php",
            """<?php
if ($enabled)
{
    $value = $_GET['id'];
    echo 'constant';
}
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertIn("[GET] id", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_next_line_if_nested_block_remains_unresolved(self):
        report = self.analyze_fixture(
            "next_line_nested.php",
            """<?php
if ($enabled)
{
    if ($other) {
        $value = $_GET['id'];
        echo $value;
    }
}
""",
        )
        self.assertIn("Unresolved unsupported conditional structure", report)
        self.assertIn("[GET] id", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_ambiguous_next_line_brace_association_remains_unresolved(self):
        report = self.analyze_fixture(
            "ambiguous_next_line_brace.php",
            """<?php
if ($enabled)

{
    $value = $_GET['id'];
    echo $value;
}
""",
        )
        self.assertIn("Unresolved conditional assignment", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_unrelated_conditional_input_and_sink_remain_unlinked(self):
        report = self.analyze_fixture(
            "unrelated_conditional_flow.php",
            """<?php
if ($enabled) {
    $value = $_GET['id'];
    $query = "SELECT 1";
    mysqli_query($db, $query);
}
""",
        )
        self.assertIn("[GET] id", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_ambiguous_if_else_join_is_unresolved_without_stale_flow(self):
        report = self.analyze_fixture(
            "ambiguous_conditional_join.php",
            """<?php
$value = $_GET['id'];
if ($replace) {
    $value = 'constant';
} else {
    $value = $other;
}
echo $value;
""",
        )
        self.assertIn("Unresolved conditional", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_if_else_join_preserves_same_provenance_from_both_paths(self):
        report = self.analyze_fixture(
            "matching_conditional_join.php",
            """<?php
if ($first) {
    $value = $_GET['id'];
} else {
    $value = $_GET['id'];
}
echo $value;
""",
        )
        self.assertIn("Explicit textual relationship: [GET] id", report)
        self.assertIn("matching_conditional_join.php:3", report)
        self.assertIn("matching_conditional_join.php:5", report)
        self.assertNotIn("Unresolved conditional join", report)

    def test_unmatched_conditional_block_is_unresolved_and_not_traced(self):
        report = self.analyze_fixture(
            "unmatched_conditional.php",
            """<?php
if ($enabled) {
    $value = $_GET['id'];
    echo $value;
""",
        )
        self.assertIn("Unresolved unmatched conditional block", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_elseif_branch_is_unresolved(self):
        report = self.analyze_fixture(
            "elseif_conditional.php",
            """<?php
if ($first) {
    $value = $_GET['id'];
} elseif ($second) {
    $value = $_POST['id'];
    echo $value;
}
""",
        )
        self.assertIn("Unresolved unsupported conditional structure", report)
        self.assertIn("[GET] id", report)
        self.assertIn("[POST] id", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_unsupported_conditional_structure_stays_unresolved(self):
        report = self.analyze_fixture(
            "unsupported_conditional.php",
            """<?php
if ($first) {
    if ($second) {
        $value = $_GET['id'];
    }
} elseif ($third) {
    $value = $_POST['id'];
}
echo $value;
""",
        )
        self.assertIn("Unresolved conditional", report)
        self.assertIn("[GET] id", report)
        self.assertIn("[POST] id", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_static_include_propagates_assignment_and_reports_edge(self):
        child = self.root / "inputs.php"
        child.write_text("<?php\n// fixture\n$value = $_GET['id'];\n")
        report = self.analyze_fixture(
            "entry.php",
            """<?php
require_once 'inputs.php';
$query = "SELECT * FROM t WHERE id=" . $value;
mysqli_query($db, $query);
""",
        )
        self.assertIn("entry.php:2 -> inputs.php:3", report)
        self.assertIn("inputs.php:3", report)
        self.assertIn("Explicit textual relationship: [GET] id", report)

    def test_unrelated_included_inputs_are_separate_from_entry_file_inputs(self):
        child = self.root / "shared_inputs.php"
        child.write_text(
            """<?php
$noise = $_GET['noise'];
$present = isset($_POST['present']) ? 1 : 0;
$unknown = transform($_REQUEST['unknown']);
"""
        )
        report = self.analyze_fixture(
            "entry_with_shared_inputs.php",
            """<?php
require_once 'shared_inputs.php';
$query = "SELECT 1";
mysqli_query($db, $query);
""",
        )
        entry_inputs = report.split("Unresolved conditional input evidence:", 1)[0]
        self.assertIn("No direct GET/POST/REQUEST inputs detected.", entry_inputs)
        self.assertIn("Request presence evidence:\n  None detected.", report)
        self.assertIn("Unresolved request-reference evidence:\n  None detected.", report)
        included = report.split("Included-file input observations:", 1)[1].split(
            "Sink observations:", 1
        )[0]
        self.assertIn("Direct request-value observation: [GET] noise", included)
        self.assertIn("Presence-check observation: [POST] present", included)
        self.assertIn("Unresolved request-reference observation: [REQUEST] unknown", included)
        self.assertIn("shared_inputs.php:2", included)
        self.assertIn("shared_inputs.php:3", included)
        self.assertIn("shared_inputs.php:4", included)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertIn("INCLUDED-FILE INPUT EVIDENCE", report)

    def test_relevant_included_input_still_reaches_entry_file_sink(self):
        child = self.root / "shared_source.php"
        child.write_text("<?php\n$value = $_POST['entry'];\n")
        report = self.analyze_fixture(
            "entry_with_shared_source.php",
            """<?php
require_once 'shared_source.php';
echo $value;
""",
        )
        self.assertIn("No direct GET/POST/REQUEST inputs detected.", report)
        included = report.split("Included-file input observations:", 1)[1].split(
            "Sink observations:", 1
        )[0]
        observations = report.split("Sink observations:", 1)[1].split(
            "Source-flow evidence:", 1
        )[0]
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn(
            "Direct request-value observation: [POST] entry at shared_source.php:2",
            included,
        )
        self.assertIn(
            "Sink text (output) at entry_with_shared_source.php:3", observations
        )
        self.assertIn(
            "Sink text (output) at entry_with_shared_source.php:3", source_flow
        )
        self.assertIn(
            "Explicit textual relationship: [POST] entry at shared_source.php:2 "
            "reaches a referenced variable or appears directly in the sink "
            "at entry_with_shared_source.php:3.",
            source_flow,
        )
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_same_file_input_sections_remain_entry_scoped(self):
        report = self.analyze_fixture(
            "same_file_input.php",
            """<?php
$value = $_GET['local'];
echo $value;
""",
        )
        entry_inputs = report.split("Unresolved conditional input evidence:", 1)[0]
        self.assertIn("Input evidence:\n  [GET] local", entry_inputs)
        included = report.split("Included-file input observations:", 1)[1].split(
            "Sink observations:", 1
        )[0]
        self.assertIn("None detected.", included)

    def test_simple_function_parameter_return_reaches_output(self):
        report = self.analyze_fixture(
            "function_return.php",
            """<?php
function carry_value($argument) {
    return $argument;
}
$input = $_GET['title'];
echo carry_value($input);
""",
        )
        self.assertIn("Explicit textual relationship: [GET] title", report)
        self.assertIn("function_return.php:5", report)
        self.assertIn("Function definition: function_return.php:2", report)
        self.assertIn("Function return: function_return.php:3", report)
        self.assertIn("Function call: function_return.php:6", report)
        self.assertIn("Sink text (output) at function_return.php:6", report)

    def test_function_local_alias_and_concatenated_call_preserve_evidence(self):
        report = self.analyze_fixture(
            "function_alias.php",
            """<?php
function carry_value($argument) {
    $local = $argument;
    return $local;
}
$input = $_GET['name'];
$message = "Hello " . carry_value($input);
echo $message;
""",
        )
        self.assertIn("Explicit textual relationship: [GET] name", report)
        self.assertIn("Function definition: function_alias.php:2", report)
        self.assertIn("Function alias: function_alias.php:3", report)
        self.assertIn("Function return: function_alias.php:4", report)
        self.assertIn("Function call: function_alias.php:7", report)
        self.assertIn("Assignment evidence: function_alias.php:7", report)
        self.assertIn("Sink text (output) at function_alias.php:8", report)

    def test_function_return_inside_sql_concatenation_reaches_database_sink(self):
        report = self.analyze_fixture(
            "function_sql.php",
            """<?php
function carry_value($argument) {
    return $argument;
}
$title = $_GET['title'];
$sql = "SELECT * FROM movies WHERE title='" . carry_value($title) . "'";
mysqli_query($db, $sql);
""",
        )
        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("Explicit textual relationship: [GET] title", report)
        self.assertIn("Function call: function_sql.php:6", report)
        self.assertIn("Function return: function_sql.php:3", report)
        self.assertIn("Sink text (SQL/query) at function_sql.php:7", report)

    def test_function_defined_in_supported_include_can_be_traced(self):
        (self.root / "function_helpers.php").write_text(
            """<?php
function carry_value($argument) {
    return $argument;
}
"""
        )
        report = self.analyze_fixture(
            "included_function.php",
            """<?php
$input = $_POST['entry'];
require_once 'function_helpers.php';
echo carry_value($input);
""",
        )
        self.assertIn("Explicit textual relationship: [POST] entry", report)
        self.assertIn("Function definition: function_helpers.php:2", report)
        self.assertIn("Function return: function_helpers.php:3", report)
        self.assertIn("Function call: included_function.php:4", report)

    def test_included_function_is_not_available_before_its_include(self):
        (self.root / "later_function.php").write_text(
            """<?php
function carry_value($argument) {
    return $argument;
}
"""
        )
        report = self.analyze_fixture(
            "function_before_include.php",
            """<?php
$input = $_GET['value'];
$output = carry_value($input);
require_once 'later_function.php';
echo $output;
""",
        )
        self.assertIn("no statically available definition", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_unknown_function_call_does_not_propagate_argument_provenance(self):
        report = self.analyze_fixture(
            "unknown_function.php",
            """<?php
$input = $_GET['value'];
$output = unknown_transform($input);
echo $output;
""",
        )
        self.assertIn("Unresolved function call", report)
        self.assertIn("unknown_function.php:3", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_unknown_function_with_direct_request_remains_unresolved(self):
        report = self.analyze_fixture(
            "unknown_direct_request_call.php",
            """<?php
$output = unknown_transform($_POST['value']);
echo $output;
""",
        )
        self.assertIn("Unresolved function call", report)
        self.assertIn("Unresolved request-reference evidence:", report)
        self.assertIn("[POST] value", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_unknown_function_inside_database_sink_does_not_link_argument(self):
        report = self.analyze_fixture(
            "unknown_function_sink.php",
            """<?php
$input = $_GET['value'];
mysqli_query($db, unknown_transform($input));
""",
        )
        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("Unresolved function call", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_sink_inside_unsupported_function_is_observed_without_flow(self):
        report = self.analyze_fixture(
            "function_sink.php",
            """<?php
function render_value($value) {
    echo $value;
    if ($value) {
        return $value;
    }
    return '';
}
$input = $_GET['value'];
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertIn("function_sink.php:3", report)
        self.assertIn("function body; execution not established", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_multiple_function_return_paths_remain_unresolved(self):
        report = self.analyze_fixture(
            "multiple_returns.php",
            """<?php
function choose_value($argument) {
    if ($condition) {
        return $argument;
    }
    return $argument;
}
$input = $_GET['value'];
echo choose_value($input);
""",
        )
        self.assertIn("Unresolved function definition", report)
        self.assertIn("Unresolved function call", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_duplicate_function_definitions_remain_ambiguous(self):
        report = self.analyze_fixture(
            "duplicate_functions.php",
            """<?php
function identity($value) {
    return $value;
}
function identity($value) {
    return $value;
}
$input = $_GET['value'];
echo identity($input);
""",
        )
        self.assertIn("duplicate function definitions", report)
        self.assertIn("Unresolved function call", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_recursive_function_remains_unresolved(self):
        report = self.analyze_fixture(
            "recursive_function.php",
            """<?php
function recurse_value($value) {
    return recurse_value($value);
}
$input = $_GET['value'];
echo recurse_value($input);
""",
        )
        self.assertIn("Unresolved function definition", report)
        self.assertIn("Unresolved function call", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_wrong_function_argument_count_remains_unresolved(self):
        report = self.analyze_fixture(
            "wrong_function_arguments.php",
            """<?php
function identity($value) {
    return $value;
}
$input = $_GET['value'];
echo identity($input, 'extra');
""",
        )
        self.assertIn("argument count does not match", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_function_return_does_not_link_unrelated_input_and_sink(self):
        report = self.analyze_fixture(
            "unrelated_function_sink.php",
            """<?php
function identity($argument) {
    return $argument;
}
$input = $_GET['input'];
$constant = 'fixed';
$output = identity($constant);
echo $unrelated;
""",
        )
        self.assertIn("[GET] input", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_trailing_literal_optional_parameter_can_be_omitted(self):
        report = self.analyze_fixture(
            "optional_parameter.php",
            """<?php
function carry_value($value, $mode = "plain") {
    return $value;
}
$input = $_GET['value'];
echo carry_value($input);
""",
        )
        self.assertIn("Explicit textual relationship: [GET] value", report)
        self.assertIn("Function definition: optional_parameter.php:2", report)
        self.assertIn("Function parameter: $value receives $input", report)
        self.assertIn("Function return: optional_parameter.php:3", report)
        self.assertIn("Function call: optional_parameter.php:6", report)

    def test_trailing_literal_optional_parameter_can_be_supplied(self):
        report = self.analyze_fixture(
            "optional_parameter_supplied.php",
            """<?php
function carry_value($value, $label = "plain, value", $count = 2, $mode = 1.5, $enabled = false) {
    $alias = $value;
    return $alias;
}
$input = $_POST['value'];
echo carry_value($input, "label, with comma", 3, 2.5, true);
""",
        )
        self.assertIn("Explicit textual relationship: [POST] value", report)
        self.assertIn("Function alias: optional_parameter_supplied.php:3", report)
        self.assertIn("Function return: optional_parameter_supplied.php:4", report)

    def test_complex_default_optional_parameter_remains_unresolved(self):
        report = self.analyze_fixture(
            "complex_optional_default.php",
            """<?php
function carry_value($value, $mode = make_default()) {
    return $value;
}
$input = $_GET['value'];
echo carry_value($input);
""",
        )
        self.assertIn("Unresolved function definition carry_value", report)
        self.assertIn("complex_optional_default.php:2", report)
        self.assertIn("Unresolved function call carry_value at complex_optional_default.php:6", report)
        self.assertIn("optional parameter default", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_nontrailing_optional_parameter_remains_unresolved(self):
        report = self.analyze_fixture(
            "nontrailing_optional.php",
            """<?php
function carry_value($mode = "plain", $value) {
    return $value;
}
$input = $_GET['value'];
echo carry_value($input);
""",
        )
        self.assertIn("nontrailing optional parameter", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_return_of_omitted_optional_parameter_remains_unresolved(self):
        report = self.analyze_fixture(
            "optional_return.php",
            """<?php
function carry_value($value, $fallback = "fixed") {
    return $fallback;
}
$input = $_GET['value'];
echo carry_value($input);
""",
        )
        self.assertIn("return value depends on an optional parameter", report)
        self.assertIn("Unresolved function call carry_value", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_transformed_function_return_remains_unresolved(self):
        report = self.analyze_fixture(
            "transformed_function_return.php",
            """<?php
function transform_value($value) {
    return encode_value($value);
}
$input = $_GET['value'];
echo transform_value($input);
""",
        )
        self.assertIn("First unsupported statement at transformed_function_return.php:3", report)
        self.assertIn("Unresolved function call transform_value at transformed_function_return.php:6", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_switch_function_summary_reports_blocking_statement_and_call_site(self):
        report = self.analyze_fixture(
            "switch_function.php",
            """<?php
function choose_value($value) {
    switch ($mode) {
        case 1: $value = helper($value); break;
    }
    return $value;
}
$input = $_GET['value'];
echo choose_value($input);
""",
        )
        self.assertIn("Unresolved function definition choose_value at switch_function.php:2", report)
        self.assertIn("First unsupported statement at switch_function.php:3", report)
        self.assertIn("switch ($mode)", report)
        self.assertIn("Unresolved function call choose_value at switch_function.php:9", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_unknown_call_inside_output_is_unresolved_and_not_a_flow(self):
        report = self.analyze_fixture(
            "unknown_output_call.php",
            """<?php
$input = $_GET['value'];
echo unknown_transform($input);
echo $unrelated;
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertIn("Unresolved function call unknown_transform at unknown_output_call.php:3", report)
        self.assertIn("Unresolved function-call expression at unknown_output_call.php:3", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_unsupported_defined_call_inside_unsupported_branch_is_diagnosed(self):
        report = self.analyze_fixture(
            "unsupported_output_branch.php",
            """<?php
function choose_value($value) {
    switch ($mode) {
        case 1: $value = helper($value); break;
    }
    return $value;
}
$input = $_GET['value'];
if ($outer) {
    if ($inner) {
        echo choose_value($input);
    }
}
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertIn("Unresolved function definition choose_value at unsupported_output_branch.php:2", report)
        self.assertIn("First unsupported statement at unsupported_output_branch.php:3", report)
        self.assertIn("Unresolved function call choose_value at unsupported_output_branch.php:11", report)
        self.assertIn("function body contains unsupported control flow or syntax", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_multiple_unsupported_calls_in_one_output_are_diagnosed_once_each(self):
        report = self.analyze_fixture(
            "multiple_unsupported_output_calls.php",
            """<?php
function first_value($value) {
    switch ($mode) {
        case 1: $value = helper($value); break;
    }
    return $value;
}
function second_value($value) {
    if ($mode) {
        return $value;
    }
    return $value;
}
$input = $_GET['value'];
if ($outer) {
    if ($inner) {
        print first_value($input) . second_value($input) . first_value($input);
    }
}
""",
        )
        self.assertIn("Unresolved function call first_value at multiple_unsupported_output_calls.php:17", report)
        self.assertIn("Unresolved function call second_value at multiple_unsupported_output_calls.php:17", report)
        self.assertEqual(report.count("Unresolved function call first_value at multiple_unsupported_output_calls.php:17"), 2)
        self.assertEqual(report.count("Unresolved function call second_value at multiple_unsupported_output_calls.php:17"), 1)
        self.assertEqual(report.count("Unresolved function definition first_value at multiple_unsupported_output_calls.php:2"), 1)
        self.assertEqual(report.count("Unresolved function-call expression at multiple_unsupported_output_calls.php:17"), 1)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_repeated_same_function_calls_on_one_line_have_distinct_stable_diagnostics(self):
        report = self.analyze_fixture(
            "repeated_unsupported_calls.php",
            """<?php
function transform($value) {
    switch ($mode) {
        case 1: return $value;
    }
    return $value;
}
echo transform('one') . transform('two');
""",
        )
        diagnostics = [
            line for line in report.splitlines()
            if "Unresolved function call transform at repeated_unsupported_calls.php:8" in line
        ]
        self.assertEqual(len(diagnostics), 2)
        self.assertNotEqual(diagnostics[0], diagnostics[1])
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_multiline_output_calls_have_actual_call_locations(self):
        report = self.analyze_fixture(
            "multiline_output_calls.php",
            """<?php
function transform($value) {
    switch ($mode) {
        case 1: return $value;
    }
    return $value;
}
echo 'prefix' .
    transform(
        'value'
    );
""",
        )
        self.assertIn("multiline_output_calls.php:8: echo 'prefix' .", report)
        self.assertRegex(
            report,
            r"Unresolved function call transform at multiline_output_calls\.php:9 \(column \d+\)",
        )
        self.assertIn("First unsupported statement at multiline_output_calls.php:3", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_multiline_print_and_printf_calls_are_diagnosed_by_actual_line(self):
        report = self.analyze_fixture(
            "multiline_print_printf.php",
            """<?php
print
    unknown_print('value');
printf(
    '%s',
    unknown_printf('value')
);
""",
        )
        self.assertIn("Unresolved function call unknown_print at multiline_print_printf.php:3 (column", report)
        self.assertIn("Unresolved function call unknown_printf at multiline_print_printf.php:6 (column", report)
        self.assertEqual(report.count("Unresolved function call unknown_print at multiline_print_printf.php:3"), 1)
        self.assertEqual(report.count("Unresolved function call unknown_printf at multiline_print_printf.php:6"), 1)
        self.assertNotIn("Explicit textual relationship", report)

    def test_output_diagnostics_ignore_call_like_comments_and_quoted_text(self):
        report = self.analyze_fixture(
            "output_comment_string_calls.php",
            """<?php
function transform($value) {
    switch ($mode) {
        case 1: return $value;
    }
    return $value;
}
echo "transform('quoted')" /* transform($comment) */ . transform('actual');
""",
        )
        self.assertEqual(report.count("Unresolved function call transform at output_comment_string_calls.php:8"), 1)
        self.assertNotIn("quoted') (column", report)
        self.assertNotIn("comment) (column", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_method_call_has_one_method_diagnostic_and_keeps_sql_sink(self):
        report = self.analyze_fixture(
            "method_query_diagnostic.php",
            """<?php
$sql = "SELECT * FROM items";
$recordset = $link->query($sql);
$static_result = Registry::lookup($sql);
echo $unrelated;
""",
        )
        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("Unresolved method call query at method_query_diagnostic.php:3 (column 21)", report)
        self.assertEqual(report.count("Unresolved method call query at method_query_diagnostic.php:3"), 1)
        self.assertNotIn("Unresolved function call query at method_query_diagnostic.php:3", report)
        self.assertIn("Unresolved static method call lookup at method_query_diagnostic.php:4 (column 28)", report)
        self.assertNotIn("Unresolved function call lookup at method_query_diagnostic.php:4", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_nested_function_calls_have_one_diagnostic_at_each_call_site(self):
        report = self.analyze_fixture(
            "nested_call_diagnostics.php",
            """<?php
$result = explode(",", trim($_GET['value']));
mysqli_query($db, "SELECT * FROM items");
""",
        )
        self.assertIn("Unresolved function call explode at nested_call_diagnostics.php:2 (column 11)", report)
        self.assertIn("Unresolved function call trim at nested_call_diagnostics.php:2 (column 24)", report)
        self.assertEqual(report.count("Unresolved function call explode at nested_call_diagnostics.php:2"), 1)
        self.assertEqual(report.count("Unresolved function call trim at nested_call_diagnostics.php:2"), 1)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_array_language_construct_is_not_reported_as_user_function(self):
        report = self.analyze_fixture(
            "array_language_construct.php",
            """<?php
$input = $_GET['value'];
$values = array($input);
echo $unrelated;
""",
        )
        self.assertNotIn("Unresolved function call array", report)
        self.assertIn("Unresolved assignment at array_language_construct.php:3", report)
        self.assertIn("Sink text (output)", report)
        self.assertNotIn("Explicit textual relationship", report)

    def test_mysqli_constructor_is_distinct_deduplicated_and_not_a_flow(self):
        report = self.analyze_fixture(
            "mysqli_constructor_diagnostic.php",
            """<?php
$request_value = $_GET['value'];
$link = new mysqli($request_value);
echo new mysqli($request_value);
mysqli_query($db, $sql);
""",
        )
        expected = "Unresolved constructor call mysqli at mysqli_constructor_diagnostic.php:3 (column 13)"
        self.assertEqual(report.count(expected), 1)
        self.assertIn(
            "Unresolved constructor call mysqli at mysqli_constructor_diagnostic.php:4 (column 10)",
            report,
        )
        self.assertNotIn("Unresolved function call mysqli", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_qualified_and_fully_qualified_constructors_are_classified(self):
        report = self.analyze_fixture(
            "namespaced_constructor_diagnostic.php",
            r"""<?php
$first = new Vendor\Package\Widget();
$second = new \Vendor\Package\Widget();
""",
        )
        self.assertIn(
            "Unresolved constructor call Vendor\\Package\\Widget at namespaced_constructor_diagnostic.php:2 (column 14)",
            report,
        )
        self.assertIn(
            "Unresolved constructor call \\Vendor\\Package\\Widget at namespaced_constructor_diagnostic.php:3 (column 15)",
            report,
        )
        self.assertNotIn("Unresolved function call Widget", report)

    def test_ordinary_function_call_remains_classified_as_function(self):
        report = self.analyze_fixture(
            "ordinary_function_call_diagnostic.php",
            """<?php
$result = unknown_transform($value);
""",
        )
        self.assertIn(
            "Unresolved function call unknown_transform at ordinary_function_call_diagnostic.php:2 (column 11)",
            report,
        )
        self.assertNotIn("Unresolved constructor call unknown_transform", report)

    def test_constructor_like_comments_and_strings_are_ignored(self):
        report = self.analyze_fixture(
            "constructor_like_text.php",
            '''<?php
// new mysqli($request);
$text = "new Vendor\\\\Package\\\\Widget($value)";
echo $text;
''',
        )
        self.assertNotIn("Unresolved constructor call", report)
        self.assertNotIn("Unresolved function call mysqli", report)
        self.assertNotIn("Unresolved function call Widget", report)
        self.assertIn("Sink text (output)", report)

    def test_two_same_line_xss_calls_keep_distinct_deduplicated_locations(self):
        report = self.analyze_fixture(
            "repeated_xss_diagnostics.php",
            """<?php
function xss($value) {
    switch ($mode) {
        case 1: return $value;
    }
    return $value;
}
$first = $_GET['first'];
$last = $_GET['last'];
echo xss($first) . xss($last);
""",
        )
        first = "Unresolved function call xss at repeated_xss_diagnostics.php:10 (column 6)"
        second = "Unresolved function call xss at repeated_xss_diagnostics.php:10 (column 20)"
        self.assertEqual(report.count(first), 1)
        self.assertEqual(report.count(second), 1)
        self.assertIn("Sink text (output)", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_incomplete_multiline_output_does_not_consume_following_statement(self):
        report = self.analyze_fixture(
            "incomplete_multiline_output.php",
            """<?php
$input = $_GET['value'];
echo unknown_transform(
$separate = unrelated_transform($input);
mysqli_query($db, $sql);
""",
        )
        self.assertIn("Unresolved function call unknown_transform at incomplete_multiline_output.php:3", report)
        self.assertEqual(
            report.count("Unresolved function call unknown_transform at incomplete_multiline_output.php:3"),
            1,
        )
        self.assertIn("Unresolved function call unrelated_transform at incomplete_multiline_output.php:4", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_unknown_call_inside_unsupported_output_branch_is_diagnosed(self):
        report = self.analyze_fixture(
            "unknown_output_branch.php",
            """<?php
$input = $_POST['value'];
if ($outer) {
    if ($inner) {
        printf("%s", unknown_transform($input));
    }
}
""",
        )
        self.assertIn("Sink text (output)", report)
        self.assertIn("Unresolved function call unknown_transform at unknown_output_branch.php:5", report)
        self.assertIn("no statically available definition", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_output_call_diagnostics_do_not_link_unrelated_input_or_sql_sink(self):
        report = self.analyze_fixture(
            "output_call_unrelated_sinks.php",
            """<?php
$input = $_GET['id'];
$sql = "SELECT * FROM items";
if ($outer) {
    if ($inner) {
        echo unknown_transform($input);
    }
}
mysqli_query($db, $sql);
echo $unrelated;
""",
        )
        self.assertIn("Unresolved function call unknown_transform at output_call_unrelated_sinks.php:6", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("Sink text (output)", report)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertNotIn("Explicit textual relationship", source_flow)
        self.assertNotIn("Conditional textual relationship", source_flow)

    def test_unsupported_function_call_does_not_link_unrelated_sink(self):
        report = self.analyze_fixture(
            "unsupported_call_unrelated_sink.php",
            """<?php
function transform($value) {
    $value = unknown_transform($value);
    return $value;
}
$input = $_GET['input'];
echo transform($input);
mysqli_query($db, "SELECT * FROM items");
""",
        )
        self.assertIn("First unsupported statement at unsupported_call_unrelated_sink.php:3", report)
        self.assertIn("Unresolved function call transform at unsupported_call_unrelated_sink.php:7", report)
        self.assertIn("Sink text (SQL/query)", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)

    def test_dir_relative_include_traces_source_to_sink(self):
        (self.root / "source.php").write_text("<?php\n$value = $_POST['entry'];\n")
        report = self.analyze_fixture(
            "dir_include.php",
            """<?php
require_once __DIR__ . '/source.php';
echo $value;
""",
        )
        self.assertIn("dir_include.php:2 -> source.php", report)
        self.assertIn("Explicit textual relationship: [POST] entry", report)

    def test_include_evidence_distinguishes_same_basename_in_different_directories(self):
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        (first_dir / "shared.php").write_text("<?php\n$first = $_GET['first'];\n")
        (second_dir / "shared.php").write_text("<?php\n$second = $_POST['second'];\n")
        report = self.analyze_fixture(
            "duplicate_include_names.php",
            """<?php
require_once __DIR__ . '/first/shared.php';
require_once __DIR__ . '/second/shared.php';
""",
        )

        self.assertIn(
            "Include evidence: duplicate_include_names.php:2 -> first/shared.php:2",
            report,
        )
        self.assertIn(
            "Include evidence: duplicate_include_names.php:3 -> second/shared.php:2",
            report,
        )
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_dynamic_and_missing_includes_are_unresolved(self):
        report = self.analyze_fixture(
            "includes.php",
            """<?php
include $requested_path;
require 'missing.php';
""",
        )
        self.assertIn("Unresolved dynamic include", report)
        self.assertIn("Unresolved missing include", report)
        self.assertIn(
            "Review status:\n  ANALYSIS INCOMPLETE — NO INPUT DETECTED", report
        )
        self.assertNotIn("Review status:\n  NO INPUT DETECTED", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_out_of_root_include_does_not_contribute_php_flow_evidence(self):
        entry_dir = self.root / "app"
        entry_dir.mkdir()
        (self.root / "outside.php").write_text(
            "<?php\n$value = $_GET['outside'];\n"
            "mysqli_query($db, $value);\necho $value;\n"
        )
        report = self.analyze_fixture(
            "app/entry.php",
            """<?php
require_once '../outside.php';
""",
        )
        included = report.split("Included-file input observations:", 1)[1].split(
            "Sink observations:", 1
        )[0]
        sink_observations = report.split("Sink observations:", 1)[1].split(
            "Source-flow evidence:", 1
        )[0]
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn(
            "Unresolved out-of-root include at entry.php:2: ../outside.php", report
        )
        self.assertNotIn("[GET] outside", included)
        self.assertNotIn("outside.php", included)
        self.assertNotIn("Sink text (SQL/query)", sink_observations)
        self.assertNotIn("Sink text (output)", sink_observations)
        self.assertNotIn("outside.php", sink_observations)
        self.assertNotIn("Explicit textual relationship", source_flow)
        self.assertNotIn("Conditional textual relationship", source_flow)
        self.assertNotIn("outside.php", source_flow)
        self.assertIn(
            "Review status:\n  ANALYSIS INCOMPLETE — NO INPUT DETECTED", report
        )
        self.assertNotIn("Review status:\n  NO INPUT DETECTED", report)
        self.assertIn("no vulnerability is confirmed", report.lower())
        self.assertNotIn("Vulnerability status: VERIFIED", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_include_cycle_is_reported_and_stops(self):
        (self.root / "other.php").write_text("<?php\ninclude 'cycle.php';\n")
        report = self.analyze_fixture("cycle.php", "<?php\ninclude 'other.php';\n")
        self.assertIn("Unresolved include cycle", report)

    def test_conditional_include_and_unrelated_variable_are_not_linked(self):
        (self.root / "conditional.php").write_text("<?php\n$value = $_GET['id'];\n")
        report = self.analyze_fixture(
            "conditional_entry.php",
            """<?php
if ($enabled) {
    include 'conditional.php';
}
$query = "SELECT * FROM t";
mysqli_query($db, $query);
echo $unrelated;
""",
        )
        self.assertIn("Unresolved conditional/nested include", report)
        self.assertNotIn("Explicit textual relationship", report)


if __name__ == "__main__":
    unittest.main()
