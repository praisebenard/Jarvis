import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PHPFlowCLITests(unittest.TestCase):
    def test_php_flow_cases_through_interactive_cli(self):
        project_root = Path(__file__).resolve().parents[1]
        cases = {
            "cli_safe_constant_case.php": """<?php
echo 'Welcome';
""",
            "cli_explicit_db_flow_case.php": """<?php
$value = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $value;
mysqli_query($db, $query);
""",
            "cli_overwritten_input_case.php": """<?php
$value = $_GET['id'];
$value = 'constant';
echo $value;
""",
            "cli_conditional_assignment_case.php": """<?php
$value = $_GET['id'];
if ($replace) {
    $value = 'constant';
}
echo $value;
""",
            "cli_conditional_post_input_case.php": """<?php
if ($enabled) {
    $value = $_POST['comment'];
}
echo $value;
""",
            "cli_dynamic_missing_include_case.php": """<?php
include $requested_path;
require 'cli_absent_local_fixture.php';
""",
            "cli_printed_sql_text_case.php": """<?php
$message = $_GET['message'];
echo "SELECT is display text: " . $message;
""",
            "cli_unknown_transform_case.php": """<?php
$input = $_POST['entry'];
$changed = custom_clean($input);
echo $changed;
""",
            "cli_conditional_sink_only_case.php": """<?php
if ($enabled) {
    $result = $db->query($query);
    echo $message;
}
""",
            "cli_sink_text_only_case.php": """<?php
// mysqli_query($db, $query); echo $message;
$example = 'mysql_query($query); echo $message;';
""",
            "cli_simple_conditional_flow_case.php": """<?php
if ($enabled) {
    $value = $_GET['id'];
    $alias = $value;
    echo "Value: " . $alias;
}
""",
            "cli_unrelated_conditional_flow_case.php": """<?php
if ($enabled) {
    $value = $_GET['id'];
    echo 'constant';
}
""",
            "cli_ambiguous_conditional_join_case.php": """<?php
$value = $_GET['id'];
if ($replace) {
    $value = 'constant';
} else {
    $value = $other;
}
echo $value;
""",
            "cli_unsupported_conditional_case.php": """<?php
if ($first) {
    if ($second) {
        $value = $_GET['id'];
    }
} elseif ($third) {
    $value = $_POST['id'];
}
echo $value;
""",
            "cli_elseif_conditional_case.php": """<?php
if ($first) {
    $value = $_GET['id'];
} elseif ($second) {
    $value = $_POST['id'];
    echo $value;
}
""",
            "cli_next_line_brace_flow_case.php": """<?php
if ($enabled)
{
    $value = $_GET['id'];
    $alias = $value;
    echo $alias;
}
""",
            "cli_next_line_brace_unrelated_case.php": """<?php
if ($enabled)
{
    $value = $_GET['id'];
    echo 'constant';
}
""",
            "cli_next_line_brace_nested_case.php": """<?php
if ($enabled)
{
    if ($other) {
        $value = $_GET['id'];
        echo $value;
    }
}
""",
        }

        with tempfile.TemporaryDirectory(prefix="jarvis-php-flow-cli-") as temp:
            workdir = Path(temp)
            fixture_dir = workdir / "fixtures"
            fixture_dir.mkdir()
            fixture_paths = {}
            for filename, source in cases.items():
                fixture_path = fixture_dir / filename
                fixture_path.write_text(source)
                fixture_paths[filename] = fixture_path

            commands = "".join(
                f"php-flow {fixture_paths[filename]}\n" for filename in cases
            ) + "exit\n"
            result = subprocess.run(
                [sys.executable, str(project_root / "jarvis.py")],
                input=commands,
                text=True,
                capture_output=True,
                cwd=workdir,
                timeout=20,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("JARVIS is online.", result.stdout)
            self.assertIn("JARVIS: Goodbye.", result.stdout)
            reports_dir = workdir / "reports"

            safe = (reports_dir / "cli_safe_constant_case_php_flow.txt").read_text()
            self.assertIn("NO INPUT DETECTED", safe)
            self.assertNotIn("Explicit textual relationship", safe)
            self.assertIn("no vulnerability is confirmed", safe)

            explicit = (reports_dir / "cli_explicit_db_flow_case_php_flow.txt").read_text()
            self.assertIn("[GET] id", explicit)
            self.assertIn("Sink text (SQL/query)", explicit)
            self.assertIn("Explicit textual relationship: [GET] id", explicit)
            self.assertIn("Assignment evidence", explicit)
            self.assertIn("no vulnerability is confirmed", explicit)

            overwritten = (reports_dir / "cli_overwritten_input_case_php_flow.txt").read_text()
            self.assertIn("[GET] id", overwritten)
            self.assertIn("Sink text (output)", overwritten)
            self.assertNotIn("Explicit textual relationship", overwritten)
            self.assertIn("INPUT DETECTED", overwritten)

            conditional = (reports_dir / "cli_conditional_assignment_case_php_flow.txt").read_text()
            self.assertIn("Unresolved conditional assignment", conditional)
            self.assertNotIn("Explicit textual relationship", conditional)
            self.assertIn("INPUT DETECTED", conditional)

            conditional_input = (reports_dir / "cli_conditional_post_input_case_php_flow.txt").read_text()
            self.assertIn("[POST] comment", conditional_input)
            self.assertIn("UNRESOLVED INPUT EVIDENCE", conditional_input)
            self.assertNotIn("Explicit textual relationship", conditional_input)
            self.assertNotIn("NO INPUT DETECTED", conditional_input)

            includes = (reports_dir / "cli_dynamic_missing_include_case_php_flow.txt").read_text()
            self.assertIn("Unresolved dynamic include", includes)
            self.assertIn("Unresolved missing include", includes)
            self.assertNotIn("Explicit textual relationship", includes)
            self.assertIn("NO INPUT DETECTED", includes)

            printed = (reports_dir / "cli_printed_sql_text_case_php_flow.txt").read_text()
            self.assertIn("Sink text (output)", printed)
            self.assertNotIn("Sink text (SQL/query)", printed)
            self.assertIn("Explicit textual relationship: [GET] message", printed)
            self.assertIn("no vulnerability is confirmed", printed)

            transformed = (reports_dir / "cli_unknown_transform_case_php_flow.txt").read_text()
            self.assertIn("Unresolved assignment", transformed)
            self.assertIn("sanitization effectiveness are not inferred", transformed)
            self.assertNotIn("Explicit textual relationship: [POST] entry", transformed)
            self.assertIn("INPUT DETECTED", transformed)

            conditional_sinks = (reports_dir / "cli_conditional_sink_only_case_php_flow.txt").read_text()
            self.assertIn("Sink text (SQL/query)", conditional_sinks)
            self.assertIn("Sink text (output)", conditional_sinks)
            self.assertIn("cli_conditional_sink_only_case.php:3", conditional_sinks)
            self.assertIn("cli_conditional_sink_only_case.php:4", conditional_sinks)
            self.assertNotIn("Explicit textual relationship", conditional_sinks)
            self.assertIn("NO INPUT DETECTED", conditional_sinks)

            sink_text_only = (reports_dir / "cli_sink_text_only_case_php_flow.txt").read_text()
            self.assertIn("No sink observations detected.", sink_text_only)
            self.assertNotIn("Sink text (SQL/query)", sink_text_only)
            self.assertNotIn("Sink text (output)", sink_text_only)

            simple_conditional = (reports_dir / "cli_simple_conditional_flow_case_php_flow.txt").read_text()
            self.assertIn("Conditional textual relationship: [GET] id", simple_conditional)
            self.assertIn("cli_simple_conditional_flow_case.php:3", simple_conditional)
            self.assertIn("cli_simple_conditional_flow_case.php:5", simple_conditional)
            self.assertIn("Sink observations:", simple_conditional)
            self.assertIn("no vulnerability is confirmed", simple_conditional)

            unrelated_conditional = (reports_dir / "cli_unrelated_conditional_flow_case_php_flow.txt").read_text()
            self.assertIn("Sink text (output)", unrelated_conditional)
            self.assertNotIn("Conditional textual relationship", unrelated_conditional)
            self.assertNotIn("Explicit textual relationship", unrelated_conditional)

            ambiguous_join = (reports_dir / "cli_ambiguous_conditional_join_case_php_flow.txt").read_text()
            self.assertIn("Unresolved conditional", ambiguous_join)
            self.assertNotIn("Explicit textual relationship", ambiguous_join)
            self.assertNotIn("Conditional textual relationship", ambiguous_join)

            unsupported_conditional = (reports_dir / "cli_unsupported_conditional_case_php_flow.txt").read_text()
            self.assertIn("Unresolved conditional", unsupported_conditional)
            self.assertIn("[GET] id", unsupported_conditional)
            self.assertIn("[POST] id", unsupported_conditional)
            self.assertNotIn("Explicit textual relationship", unsupported_conditional)
            self.assertNotIn("Conditional textual relationship", unsupported_conditional)

            elseif_conditional = (reports_dir / "cli_elseif_conditional_case_php_flow.txt").read_text()
            self.assertIn("Unresolved unsupported conditional structure", elseif_conditional)
            self.assertIn("[GET] id", elseif_conditional)
            self.assertIn("[POST] id", elseif_conditional)
            self.assertNotIn("Conditional textual relationship", elseif_conditional)
            self.assertNotIn("Explicit textual relationship", elseif_conditional)

            split_brace = (reports_dir / "cli_next_line_brace_flow_case_php_flow.txt").read_text()
            self.assertIn("Conditional textual relationship: [GET] id at cli_next_line_brace_flow_case.php:4", split_brace)
            self.assertIn("Assignment evidence: cli_next_line_brace_flow_case.php:5", split_brace)
            self.assertIn("Sink text (output) at cli_next_line_brace_flow_case.php:6", split_brace)

            split_unrelated = (reports_dir / "cli_next_line_brace_unrelated_case_php_flow.txt").read_text()
            self.assertIn("Sink text (output)", split_unrelated)
            self.assertIn("[GET] id", split_unrelated)
            self.assertNotIn("Conditional textual relationship", split_unrelated)
            self.assertNotIn("Explicit textual relationship", split_unrelated)

            split_nested = (reports_dir / "cli_next_line_brace_nested_case_php_flow.txt").read_text()
            self.assertIn("Unresolved unsupported conditional structure", split_nested)
            self.assertNotIn("Conditional textual relationship", split_nested)
            self.assertNotIn("Explicit textual relationship", split_nested)

            self.assertEqual(len(list(reports_dir.glob("*_php_flow.txt"))), len(cases))


if __name__ == "__main__":
    unittest.main()
