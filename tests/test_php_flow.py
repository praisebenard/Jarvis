import ast
import contextlib
import hashlib
import io
import re
import tempfile
import unittest
from datetime import datetime, timezone
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
            and node.name in {
                "analyze_php_flow",
                "_trace_php_flow",
                "_redact_potential_secrets",
                "_triage_static_severity",
                "_source_flow_severity_lines",
                "_begin_source_analysis_provenance",
                "_format_source_analysis_provenance",
                "_write_php_flow_report",
            }
        ]
        namespace = {
            "Path": Path,
            "re": re,
            "hashlib": hashlib,
            "datetime": datetime,
            "timezone": timezone,
            "REPORTS_DIR": self.root / "reports",
            "__file__": str(source_path),
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

    def analyze_local_source(self, source_path):
        source = Path(source_path)
        self.assertTrue(source.is_file(), f"local source fixture is unavailable: {source}")
        source.read_text(errors="ignore")  # Confirm readable source before analysis.
        with contextlib.redirect_stdout(io.StringIO()):
            self.analyze(source)
        report = self.root / "reports" / f"{source.stem}_php_flow.txt"
        return report.read_text()

    def test_offline_upload_review_synthetic_fixtures(self):
        fixtures = Path(__file__).parent / "fixtures" / "php_upload"

        direct = self.analyze_fixture("upload_direct.php", (fixtures / "direct_move.php").read_text())
        self.assertIn("Upload source: $_FILES['avatar']['tmp_name']", direct)
        self.assertIn("move_uploaded_file()", direct)
        self.assertIn("Vulnerability status: UNCONFIRMED.", direct)
        self.assertIn("Severity: NEEDS_REVIEW", direct)

        checked = self.analyze_fixture("upload_checks.php", (fixtures / "extension_mime.php").read_text())
        self.assertIn("Observed filename/extension check", checked)
        self.assertIn("Observed MIME-type check", checked)
        self.assertIn("none is treated as sufficient validation", checked)

        limits = self.analyze_fixture("upload_limits.php", (fixtures / "error_size.php").read_text())
        self.assertIn("Observed upload error check", limits)
        self.assertIn("Observed upload size check", limits)

        dynamic = self.analyze_fixture("upload_destination.php", (fixtures / "user_destination.php").read_text())
        self.assertIn("user-controlled expression observed", dynamic)
        self.assertIn("$_POST['name']", dynamic)

        helper = self.analyze_fixture("upload_helper.php", (fixtures / "helper_fixed_destination.php").read_text())
        self.assertIn("fixed or otherwise unclassified expression", helper)
        self.assertIn("Observed filename/extension check", helper)
        self.assertIn("Validation-like helper call validateUpload(...) at", helper)
        self.assertIn("effectiveness and enforcement on this path are unresolved", helper)

        unresolved = self.analyze_fixture("upload_unresolved.php", (fixtures / "unresolved.php").read_text())
        self.assertIn("Unresolved upload handling: $_FILES['archive']", unresolved)
        self.assertIn("Vulnerability status: UNCONFIRMED.", unresolved)

        unrelated = self.analyze_fixture("upload_unrelated.php", (fixtures / "unrelated_request.php").read_text())
        upload_section = unrelated.split("File-upload review observations", 1)[1].split("Source-flow evidence:", 1)[0]
        self.assertIn("No $_FILES upload handling detected.", upload_section)
        self.assertNotIn("$_POST['id']", upload_section)

    def test_php_flow_report_records_source_and_analyzer_provenance(self):
        source_text = "<?php\n$value = $_GET['value'];\necho $value;\n"
        fixture = self.root / "provenance.php"
        fixture.write_text(source_text)
        analyzer_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        analyzer_hash = hashlib.sha256(analyzer_path.read_bytes()).hexdigest()

        report = self.analyze_fixture("provenance.php", source_text)

        self.assertIn("Report provenance:", report)
        self.assertIn("Analysis started (UTC):", report)
        self.assertIn("Report prepared (UTC):", report)
        self.assertIn(f"Analyzer source: {analyzer_path}", report)
        self.assertIn(f"Analyzer source SHA-256: {analyzer_hash}", report)
        self.assertIn(f"Source file: {fixture}", report)
        self.assertIn(
            f"Source SHA-256: {hashlib.sha256(source_text.encode()).hexdigest()}",
            report,
        )
        self.assertIn("Matches current file when report was prepared: YES", report)
        self.assertIn("Source matched analyzed snapshot when report was prepared: YES", report)

    def test_php_flow_report_preserves_existing_report_and_uses_unique_name(self):
        fixture = self.root / "preserved.php"
        fixture.write_text("<?php\necho 'local';\n")
        reports_dir = self.root / "reports"
        reports_dir.mkdir()
        existing = reports_dir / "preserved_php_flow.txt"
        existing.write_text("older report stays unchanged\n")

        with contextlib.redirect_stdout(io.StringIO()):
            self.analyze(fixture)

        self.assertEqual(existing.read_text(), "older report stays unchanged\n")
        self.assertTrue((reports_dir / "preserved_php_flow_1.txt").is_file())

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
        self.assertIn("Severity: NEEDS_REVIEW", report)
        self.assertIn("Vulnerability status remains UNCONFIRMED", report)
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

    def test_request_identifier_to_database_sink_is_reviewed_without_claiming_missing_auth(self):
        report = self.analyze_fixture(
            "object_id_without_visible_guard.php",
            """<?php
$document_id = $_GET['document_id'];
$query = "SELECT * FROM documents WHERE id=" . $document_id;
mysqli_query($db, $query);
""",
        )

        self.assertIn("Object-level access-control review observations", report)
        self.assertIn("[GET] document_id at object_id_without_visible_guard.php:2", report)
        self.assertIn("SQL/query at object_id_without_visible_guard.php:4", report)
        self.assertIn("No supported authorization-like condition was recognized", report)
        self.assertIn("This does not prove that authorization is missing", report)
        self.assertIn("Severity: NEEDS_REVIEW", report)
        self.assertIn("Finding confidence: Low", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_nearby_owner_or_session_guard_is_reported_without_proving_effectiveness(self):
        report = self.analyze_fixture(
            "object_id_with_guard.php",
            """<?php
$document_id = $_GET['document_id'];
if ($document_id === $_SESSION['user_id']) {
    $query = "SELECT * FROM documents WHERE id=" . $document_id;
    mysqli_query($db, $query);
}
""",
        )

        self.assertIn("Authorization-like condition observed", report)
        self.assertIn("if ($document_id === $_SESSION['user_id'])", report)
        self.assertIn("does not establish that it checks the requested object's owner", report)
        self.assertIn("Severity: NEEDS_REVIEW", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_prepared_object_lookup_is_reviewed_without_calling_it_sql_injection(self):
        report = self.analyze_fixture(
            "prepared_object_access.php",
            """<?php
$document_id = $_GET['document_id'];
$sql = "SELECT * FROM documents WHERE id = ?";
$stmt = $db->prepare($sql);
$stmt->bind_param("i", $document_id);
$stmt->execute();
""",
        )

        self.assertIn("Object-level access-control review observations", report)
        self.assertIn("[GET] document_id at prepared_object_access.php:2", report)
        self.assertIn("SQL/prepared statement parameter at prepared_object_access.php:6", report)
        self.assertNotIn("SQL injection candidate", report)
        self.assertIn("No supported authorization-like condition was recognized", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_unrelated_guard_and_non_identifier_input_are_not_authorization_evidence(self):
        report = self.analyze_fixture(
            "non_authorization_review.php",
            """<?php
$search = $_GET['search'];
if ($feature_enabled) {
    $query = "SELECT * FROM documents WHERE name='" . $search . "'";
    mysqli_query($db, $query);
}
""",
        )

        self.assertNotIn("Object-level access-control review observations", report)
        self.assertNotIn("Authorization-like condition observed", report)

    def test_session_login_check_is_not_mistaken_for_object_authorization(self):
        report = self.analyze_fixture(
            "login_not_ownership.php",
            """<?php
$document_id = $_GET['document_id'];
if ($_SESSION['user_id'] > 0) {
    $query = "SELECT * FROM documents WHERE id=" . $document_id;
    mysqli_query($db, $query);
}
""",
        )

        self.assertIn("Object-level access-control review observations", report)
        self.assertNotIn("Authorization-like condition observed", report)
        self.assertIn("No supported authorization-like condition was recognized", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_local_helper_parameter_comparison_is_reported_as_limited_evidence(self):
        report = self.analyze_fixture(
            "helper_object_authorization.php",
            """<?php
function owns_document($requested_id) {
    return $requested_id === $_SESSION['document_id'];
}
$document_id = $_GET['document_id'];
if (owns_document($document_id)) {
    $query = "SELECT * FROM documents WHERE id=" . $document_id;
    mysqli_query($db, $query);
}
""",
        )

        self.assertIn("Authorization-like condition observed", report)
        self.assertIn("Local helper evidence: owns_document", report)
        self.assertIn("helper_object_authorization.php:2", report)
        self.assertIn("does not prove the helper is complete or effective", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_unrelated_role_helper_does_not_count_as_object_authorization(self):
        report = self.analyze_fixture(
            "unrelated_role_helper.php",
            """<?php
function is_admin() {
    return $_SESSION['role'] === 'admin';
}
$document_id = $_GET['document_id'];
if (is_admin()) {
    $query = "SELECT * FROM documents WHERE id=" . $document_id;
    mysqli_query($db, $query);
}
""",
        )

        self.assertIn("Object-level access-control review observations", report)
        self.assertNotIn("Authorization-like condition observed", report)
        self.assertIn("No supported authorization-like condition was recognized", report)

    def test_direct_request_flow_to_command_operation_is_reported_conservatively(self):
        report = self.analyze_fixture(
            "command_operation.php",
            """<?php
$command = $_GET['command'];
$result = shell_exec($command);
""",
        )

        self.assertIn("Sink text (Dangerous server-side operation: shell_exec)", report)
        self.assertIn("Explicit textual relationship: [GET] command", report)
        self.assertIn("shell_exec($command)", report)
        self.assertIn("Command-execution / command-injection review observations", report)
        self.assertIn("[GET] command at command_operation.php:2", report)
        self.assertIn("shell_exec() at command_operation.php:3", report)
        self.assertIn("Static flow does not establish shell interpretation", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Severity: NEEDS_REVIEW", report)

    def test_command_operation_observation_does_not_link_unrelated_input_or_literal(self):
        report = self.analyze_fixture(
            "unrelated_command_operation.php",
            """<?php
$request_value = $_GET['command'];
$result = shell_exec('fixed local command');
""",
        )

        self.assertIn("Sink text (Dangerous server-side operation: shell_exec)", report)
        self.assertNotIn("Explicit textual relationship: [GET] command", report)
        self.assertNotIn("Conditional textual relationship: [GET] command", report)
        self.assertIn("No supported request-controlled flow to an OS command-execution function", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_request_argument_passed_through_escapeshellarg_is_recorded_not_assumed_safe(self):
        report = self.analyze_fixture(
            "command_argument_escaping.php",
            """<?php
$argument = $_GET['argument'];
$escaped = escapeshellarg($argument);
$command = 'tool ' . $escaped;
$result = shell_exec($command);
""",
        )

        self.assertIn("[GET] argument at command_argument_escaping.php:2", report)
        self.assertIn("shell_exec() at command_argument_escaping.php:5", report)
        self.assertIn("Recognized command argument transformation: escapeshellarg($argument)", report)
        self.assertIn("Transformation evidence: escapeshellarg($argument)", report)
        self.assertIn("safe argument boundaries, option handling, command composition", report)
        self.assertIn("Severity: NEEDS_REVIEW", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_command_built_through_unsupported_helper_is_left_unresolved(self):
        report = self.analyze_fixture(
            "dynamic_command_helper.php",
            """<?php
function build_command($value) {
    return assemble_command($value);
}
$input = $_GET['command'];
$result = shell_exec(build_command($input));
""",
        )

        self.assertIn("Sink text (Dangerous server-side operation: shell_exec)", report)
        self.assertIn("Unresolved", report)
        self.assertIn("No supported request-controlled flow to an OS command-execution function was established", report)
        self.assertNotIn("Request input [GET] command", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_request_controlled_file_network_operation_is_reported_as_candidate(self):
        report = self.analyze_fixture(
            "file_access_operation.php",
            """<?php
$url = $_GET['url'];
$body = file_get_contents($url);
""",
        )

        self.assertIn("Sink text (Dangerous server-side operation: file_get_contents)", report)
        self.assertIn("Explicit textual relationship: [GET] url", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_request_url_fetch_flow_has_locations_and_unresolved_ssrf_assumptions(self):
        report = self.analyze_fixture(
            "request_url_fetch.php",
            """<?php
$url = $_GET['url'];
$body = file_get_contents($url);
""",
        )

        self.assertIn("URL-fetch / SSRF review observations", report)
        self.assertIn("[GET] url at request_url_fetch.php:2", report)
        self.assertIn("file_get_contents() at request_url_fetch.php:3", report)
        self.assertIn("destination control, URL parsing, redirects", report)
        self.assertIn("Severity: NEEDS_REVIEW", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_fixed_url_fetch_does_not_create_request_controlled_ssrf_flow(self):
        report = self.analyze_fixture(
            "fixed_url_fetch.php",
            """<?php
$body = file_get_contents('https://static.example.invalid/data');
""",
        )

        self.assertIn("Sink text (Dangerous server-side operation: file_get_contents)", report)
        self.assertIn("No supported request-controlled flow to file_get_contents() was established", report)
        self.assertNotIn("Request input [GET]", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_url_format_validation_is_recorded_without_claiming_safe_destination(self):
        report = self.analyze_fixture(
            "url_format_check.php",
            """<?php
$url = $_GET['url'];
if (filter_var($url, FILTER_VALIDATE_URL)) {
    $body = file_get_contents($url);
}
""",
        )

        self.assertIn("Recognized URL-format validation evidence", report)
        self.assertIn("if (filter_var($url, FILTER_VALIDATE_URL))", report)
        self.assertIn("does not establish an allowed host, scheme", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_exact_url_allowlist_condition_is_observed_with_unknown_contents(self):
        report = self.analyze_fixture(
            "url_allowlist_check.php",
            """<?php
$url = $_GET['url'];
if (in_array($url, $allowed_urls, true)) {
    $body = file_get_contents($url);
}
""",
        )

        self.assertIn("Recognized exact-URL allowlist-like membership evidence", report)
        self.assertIn("if (in_array($url, $allowed_urls, true))", report)
        self.assertIn("Allowlist contents, URL-to-entry equivalence", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_unsupported_network_method_and_unrelated_request_value_stay_unresolved(self):
        unsupported = self.analyze_fixture(
            "unsupported_url_client.php",
            """<?php
$url = $_GET['url'];
$response = $client->get($url);
""",
        )
        self.assertIn("No supported request-controlled flow to file_get_contents() was established", unsupported)
        self.assertIn("Unresolved", unsupported)
        self.assertNotIn("Request input [GET] url", unsupported)

        unrelated = self.analyze_fixture(
            "request_not_used_for_network.php",
            """<?php
$url = $_GET['url'];
$message = 'local text';
echo $message;
$body = file_get_contents('https://static.example.invalid/data');
""",
        )
        self.assertIn("No supported request-controlled flow to file_get_contents() was established", unrelated)
        self.assertNotIn("Request input [GET] url", unrelated)

    def test_database_object_exec_is_not_misclassified_as_shell_execution(self):
        report = self.analyze_fixture(
            "database_exec_method.php",
            """<?php
$query = "DELETE FROM items";
$database->exec($query);
""",
        )

        self.assertIn("Sink text (SQL/query)", report)
        self.assertIn("No supported request-controlled flow to an OS command-execution function", report)
        self.assertNotIn(
            "Dangerous server-side operation: exec",
            report,
        )

    def test_request_controlled_path_reaching_supported_read_operations_is_observed(self):
        report = self.analyze_fixture(
            "request_file_read.php",
            """<?php
$path = $_GET['path'];
$contents = file_get_contents($path);
readfile($path);
""",
        )

        self.assertIn("File-access / path-traversal review observations", report)
        self.assertIn("[GET] path at request_file_read.php:2", report)
        self.assertIn("file_get_contents() at request_file_read.php:3", report)
        self.assertIn("readfile() at request_file_read.php:4", report)
        self.assertIn("does not prove traversal", report)
        self.assertIn("Severity: NEEDS_REVIEW", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_fixed_hard_coded_file_path_has_no_request_controlled_observation(self):
        report = self.analyze_fixture(
            "fixed_file_read.php",
            """<?php
$contents = file_get_contents('/srv/app/data/public.txt');
""",
        )

        self.assertIn("Sink text (Dangerous server-side operation: file_get_contents)", report)
        self.assertIn("No supported request-controlled flow to file_get_contents() or readfile()", report)
        self.assertNotIn("Request input [GET]", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_basename_path_transformation_is_recorded_without_claiming_containment(self):
        report = self.analyze_fixture(
            "basename_file_read.php",
            """<?php
$requested = $_GET['file'];
$safe_name = basename($requested);
$contents = file_get_contents($safe_name);
""",
        )

        self.assertIn("[GET] file at basename_file_read.php:2", report)
        self.assertIn("Path transformation evidence: basename($requested)", report)
        self.assertIn("does not establish base-directory containment", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_realpath_canonicalization_is_recorded_without_claiming_root_enforcement(self):
        report = self.analyze_fixture(
            "realpath_file_read.php",
            """<?php
$requested = $_GET['file'];
$resolved = realpath($requested);
$contents = file_get_contents($resolved);
""",
        )

        self.assertIn("Path transformation evidence: realpath($requested)", report)
        self.assertIn("containment against an intended base", report)
        self.assertIn("failure handling", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_base_directory_prefix_guard_is_recorded_with_containment_limits(self):
        report = self.analyze_fixture(
            "base_directory_guard.php",
            """<?php
$path = $_GET['path'];
if (strpos($path, $base_dir) === 0) {
    $contents = file_get_contents($path);
}
""",
        )

        self.assertIn("Recognized base-directory prefix check-like condition", report)
        self.assertIn("strpos($path, $base_dir)", report)
        self.assertIn("separator boundaries, symlink behavior", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_dynamic_path_helper_and_disconnected_input_are_not_linked_to_file_read(self):
        unresolved = self.analyze_fixture(
            "unresolved_file_path.php",
            """<?php
$requested = $_GET['file'];
$path = build_path($requested);
$contents = file_get_contents($path);
""",
        )
        self.assertIn("Sink text (Dangerous server-side operation: file_get_contents)", unresolved)
        self.assertIn("Unresolved", unresolved)
        self.assertIn("No supported request-controlled flow to file_get_contents() or readfile()", unresolved)
        self.assertNotIn("Request input [GET] file", unresolved)
        self.assertIn("Vulnerability status: UNCONFIRMED", unresolved)

        unrelated = self.analyze_fixture(
            "unused_path_input.php",
            """<?php
$requested = $_GET['file'];
$contents = file_get_contents('/srv/app/data/public.txt');
echo 'done';
""",
        )
        self.assertIn("No supported request-controlled flow to file_get_contents() or readfile()", unrelated)
        self.assertNotIn("Request input [GET] file", unrelated)

    def test_php_source_report_redacts_secret_values_in_file_and_console(self):
        secret = "php_synthetic_secret_value_93"
        fixture = self.root / "secret_in_query.php"
        fixture.write_text(
            "<?php\n"
            f'$db->query("SELECT * FROM users WHERE api_token=\'{secret}\'");\n'
        )
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.analyze(fixture)
        report = (self.root / "reports" / "secret_in_query_php_flow.txt").read_text()
        self.assertIn("[REDACTED]", report)
        self.assertNotIn(secret, report)
        self.assertNotIn(secret, output.getvalue())

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

    def test_request_data_concatenated_into_sql_is_evidence_not_confirmation(self):
        report = self.analyze_fixture(
            "sql_request_concatenation.php",
            """<?php
$record_id = $_GET['record_id'];
$query = "SELECT * FROM records WHERE id=" . $record_id;
mysqli_query($db, $query);
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("[GET] record_id at sql_request_concatenation.php:2", source_flow)
        self.assertIn("$query references $record_id", source_flow)
        self.assertIn("Sink text (SQL/query) at sql_request_concatenation.php:4", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report)

    def test_sql_escape_helper_is_evidence_not_a_context_safety_guarantee(self):
        report = self.analyze_fixture(
            "sql_escape_then_concatenate.php",
            """<?php
function escape_sql_value($value) {
    return mysqli_real_escape_string($db, $value);
}
$name = $_GET['name'];
$escaped_name = escape_sql_value($name);
$query = "SELECT * FROM records WHERE name='" . $escaped_name . "'";
mysqli_query($db, $query);
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("[GET] name", source_flow)
        self.assertIn("Function transformed return expression: mysqli_real_escape_string", source_flow)
        self.assertIn("SQL escaping, not HTML output encoding", source_flow)
        self.assertIn("SQL-context effectiveness is not inferred", source_flow)
        self.assertIn("Sink text (SQL/query)", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_request_data_bound_to_prepared_statement_is_not_query_concatenation(self):
        report = self.analyze_fixture(
            "prepared_parameter_flow.php",
            """<?php
$record_id = $_GET['record_id'];
$query = "SELECT * FROM records WHERE id = ?";
$statement = $db->prepare($query);
$statement->bind_param("i", $record_id);
$statement->execute();
""",
        )

        self.assertIn("[GET] record_id", report)
        self.assertIn("Query text at prepared_parameter_flow.php:3", report)
        self.assertIn("Binding evidence: parameter #1 uses $record_id", report)
        self.assertIn("not concatenated into the SQL text", report)
        self.assertIn("reaches bound parameter #1 ($record_id)", report)
        self.assertNotIn("SQL injection candidate", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_dynamic_sql_expression_is_left_unresolved(self):
        report = self.analyze_fixture(
            "dynamic_sql_unresolved.php",
            """<?php
$filter = $_GET['filter'];
$query = build_query($filter);
mysqli_query($db, $query);
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("Sink text (SQL/query) at dynamic_sql_unresolved.php:4", report)
        self.assertIn("Unresolved assignment at dynamic_sql_unresolved.php:3", report)
        self.assertNotIn("Explicit textual relationship: [GET] filter", source_flow)
        self.assertNotIn("Conditional textual relationship: [GET] filter", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_input_used_only_as_bound_value_is_separate_from_query_text(self):
        report = self.analyze_fixture(
            "bound_value_not_sql_text.php",
            """<?php
$search_term = $_POST['search_term'];
$query = "SELECT * FROM records WHERE title = ?";
$statement = $db->prepare($query);
$statement->bind_param("s", $search_term);
$statement->execute();
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("[POST] search_term", source_flow)
        self.assertIn("reaches bound parameter #1 ($search_term)", source_flow)
        self.assertNotIn("Sink text (SQL/query) at bound_value_not_sql_text.php", source_flow)
        self.assertIn("not concatenated into the SQL text", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_untrusted_input_in_static_html_text_context_is_not_xss_confirmation(self):
        report = self.analyze_fixture(
            "output_html_text_context.php",
            """<?php
$message = $_GET['message'];
echo '<p>' . $message . '</p>';
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("[GET] message", source_flow)
        self.assertIn("Sink text (output) at output_html_text_context.php:3", source_flow)
        self.assertIn("Output context evidence: HTML text", source_flow)
        self.assertIn("Context is inferred from static source fragments only", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Severity: NEEDS_REVIEW", report)

    def test_untrusted_input_in_quoted_html_attribute_is_classified(self):
        report = self.analyze_fixture(
            "output_html_attribute_context.php",
            """<?php
$label = $_GET['label'];
echo '<div title="' . $label . '">item</div>';
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("Output context evidence: HTML attribute", source_flow)
        self.assertIn("bounded by a quoted static attribute value", source_flow)
        self.assertIn("does not prove browser interpretation", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_untrusted_input_in_javascript_string_context_is_classified(self):
        report = self.analyze_fixture(
            "output_javascript_string_context.php",
            """<?php
$label = $_GET['label'];
echo '<script>const label = "' . $label . '";</script>';
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("Output context evidence: JavaScript string", source_flow)
        self.assertIn("bounded by static script markup and quote delimiters", source_flow)
        self.assertIn("exploitability", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_html_encoder_is_observed_in_html_text_context_without_proof_of_effectiveness(self):
        report = self.analyze_fixture(
            "html_encoded_output_context.php",
            """<?php
function encode_html($value) {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
$message = $_GET['message'];
echo '<p>' . encode_html($message) . '</p>';
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("Output context evidence: HTML text", source_flow)
        self.assertIn("HTML output encoding, not SQL escaping", source_flow)
        self.assertIn("context effectiveness is not inferred", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_addslashes_in_html_text_is_not_context_appropriate_html_encoding(self):
        report = self.analyze_fixture(
            "addslashes_html_text_context.php",
            """<?php
function quote_value($value) {
    return addslashes($value);
}
$message = $_GET['message'];
echo '<p>' . quote_value($message) . '</p>';
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("Output context evidence: HTML text", source_flow)
        self.assertIn("addslashes quote escaping observed", source_flow)
        self.assertIn("not HTML output encoding", source_flow)
        self.assertIn("HTML-context protection is not inferred", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_output_context_without_static_markup_remains_unresolved(self):
        report = self.analyze_fixture(
            "output_context_unknown.php",
            """<?php
$message = $_GET['message'];
echo $message;
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]

        self.assertIn("Output context evidence: unresolved", source_flow)
        self.assertIn("surrounding static markup does not establish a supported output context", source_flow)
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

    def test_html_form_control_name_alone_is_not_a_request_source(self):
        report = self.analyze_fixture(
            "form_control_only.php",
            """<!doctype html>
<form method="POST">
<textarea name="entry"></textarea>
<input name="entry_all">
<input data-name="not_a_control_name">
</form>
<?php
$message = "static content";
echo $message;
""",
        )

        controls = report.split("Form control observations:", 1)[1].split(
            "Input evidence:", 1
        )[0]
        self.assertIn("[textarea] name=entry at form_control_only.php:3", controls)
        self.assertIn("[input] name=entry_all at form_control_only.php:4", controls)
        self.assertIn("[input] name=(unnamed) at form_control_only.php:5", controls)
        self.assertIn("No direct GET/POST/REQUEST inputs detected.", report)
        self.assertIn("NO INPUT DETECTED", report)
        self.assertNotIn("[POST] entry", report)

    def test_stored_value_provenance_and_database_output_observations_are_separated(self):
        report = self.analyze_fixture(
            "stored_blog.php",
            """<form method="POST"><textarea name="entry"></textarea></form>
<?php
function xss($data) {
    if ($level == "2") { return sqli_check_3($db, $data); }
    return sqli_check_3($db, $data);
}
if (isset($_POST['entry_add'])) {
    $entry = xss($_POST['entry']);
    $sql = "INSERT INTO blog (entry) VALUES ('" . $entry . "')";
    $db->query($sql);
}
$sql = "SELECT entry FROM blog";
$rows = $db->query($sql);
while ($row = $rows->fetch_object()) {
    echo xss_check_3($row->entry);
}
""",
        )

        self.assertIn("Form control observations:", report)
        self.assertIn("[textarea] name=entry at stored_blog.php:1", report)
        self.assertIn("Unresolved request-reference evidence:", report)
        self.assertIn("[POST] entry (expression value unresolved)", report)
        self.assertIn("stored_blog.php:8: xss($_POST['entry'])", report)
        self.assertIn("Database write statement construction (INSERT)", report)
        self.assertIn("stored_blog.php:9", report)
        self.assertIn("Database write execution (INSERT)", report)
        self.assertIn("Database retrieval statement construction (SELECT)", report)
        self.assertIn("stored_blog.php:12", report)
        self.assertIn("Database retrieval execution (SELECT)", report)
        self.assertIn("Output branch observation at stored_blog.php:15", report)
        self.assertIn("echo xss_check_3($row->entry)", report)
        self.assertIn("does not establish a joined stored-data flow", report.lower())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Supported source-to-sink relationship", report)

    def test_supported_stored_data_path_links_request_write_read_and_output(self):
        report = self.analyze_fixture(
            "stored_complete.php",
            """<?php
$entry = $_POST['entry'];
$stored = $entry;
$sql = "INSERT INTO notes (id, entry) VALUES (7, '" . $stored . "')";
$write = $db->query($sql);
$read_sql = "SELECT entry FROM notes WHERE id = 7";
$rows = $db->query($read_sql);
$row = $rows->fetch_object();
echo $row->entry;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("Supported stored-data path: [POST] entry", stored)
        for evidence in (
            "stored_complete.php:2", "stored_complete.php:3",
            "stored_complete.php:4", "stored_complete.php:5",
            "stored_complete.php:6", "stored_complete.php:7",
            "stored_complete.php:8", "stored_complete.php:9", "notes.entry",
        ):
            self.assertIn(evidence, stored)
        self.assertIn("query success", stored.lower())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_stored_write_without_proven_later_read_stays_separate(self):
        report = self.analyze_fixture(
            "stored_write_only.php",
            """<?php
$entry = $_POST['entry'];
$sql = "INSERT INTO notes (id, entry) VALUES (7, '" . $entry . "')";
$db->query($sql);
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("Request [POST] entry", stored)
        self.assertIn("INSERT column entry", stored)
        self.assertNotIn("Supported stored-data path", stored)
        self.assertIn("no supported request-to-write-to-read-to-output", stored.lower())

    def test_unrelated_database_read_does_not_join_to_stored_write(self):
        report = self.analyze_fixture(
            "stored_unrelated_read.php",
            """<?php
$entry = $_POST['entry'];
$sql = "INSERT INTO notes (id, entry) VALUES (7, '" . $entry . "')";
$db->query($sql);
$read_sql = "SELECT entry FROM archive WHERE id = 7";
$rows = $db->query($read_sql);
$row = $rows->fetch_object();
echo $row->entry;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertNotIn("Supported stored-data path", stored)
        self.assertIn("not INSERT table notes", stored)

    def test_unrelated_output_variable_is_not_linked_to_stored_value(self):
        report = self.analyze_fixture(
            "stored_unrelated_output.php",
            """<?php
$entry = $_POST['entry'];
$sql = "INSERT INTO notes (id, entry) VALUES (7, '" . $entry . "')";
$db->query($sql);
$read_sql = "SELECT entry FROM notes WHERE id = 7";
$rows = $db->query($read_sql);
$row = $rows->fetch_object();
$unrelated = 'fixed';
echo $unrelated;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertNotIn("Supported stored-data path", stored)
        self.assertNotIn("retrieved $entry is observed in output", stored)

    def test_unsupported_helper_and_ambiguous_sql_remain_unresolved(self):
        report = self.analyze_fixture(
            "stored_ambiguous.php",
            """<?php
$entry = unknown_transform($_POST['entry']);
$sql = "INSERT INTO notes (entry) VALUES ('" . $entry . "')";
$db->query($sql);
$read_sql = "SELECT entry FROM notes";
$read_sql = "SELECT body FROM notes";
$rows = $db->query($read_sql);
$row = $rows->fetch_object();
echo $row->entry;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertNotIn("Supported stored-data path", stored)
        self.assertIn("unresolved expression unknown_transform()", stored)
        self.assertIn("multiple or missing query assignments", stored)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_guarded_stored_assignment_retains_guard_without_validation_claim(self):
        report = self.analyze_fixture(
            "stored_guarded.php",
            """<?php
if (isset($_POST['submit'])) {
    $entry = $_POST['entry'];
}
$sql = "INSERT INTO notes (id, entry) VALUES (7, '" . $entry . "')";
$db->query($sql);
$read_sql = "SELECT entry FROM notes WHERE id = 7";
$rows = $db->query($read_sql);
$row = $rows->fetch_object();
echo $row->entry;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("Conditional stored-data path", stored)
        self.assertIn("isset($_POST['submit'])", stored)
        self.assertIn("not validation or sanitization", stored)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_real_bwapp_stored_source_traces_helper_but_keeps_record_path_unresolved(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/xss_stored_1.php")

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("Request [POST] entry", stored)
        self.assertIn('Helper call xss at xss_stored_1.php:68 resolves branch "0"', stored)
        self.assertIn('switch ($_COOKIE["security_level"])', stored)
        for branch_line in (39, 44, 50, 56):
            self.assertIn(f"sqli_check_3($link, $data) at xss_stored_1.php:{branch_line}", stored)
        self.assertIn("Shared helper return at xss_stored_1.php:61 returns $data", stored)
        self.assertIn("Helper context include at xss_stored_1.php:32", stored)
        self.assertIn("Nested helper sqli_check_3 definition at functions_external.php:218", stored)
        self.assertIn("mysqli_real_escape_string($link, $data)", stored)
        self.assertIn("SQL escaping, not HTML output encoding", stored)
        self.assertIn("INSERT column entry", stored)
        self.assertIn("xss_stored_1.php:81", stored)
        self.assertIn("xss_stored_1.php:83", stored)
        self.assertIn("ambiguous", stored.lower())
        self.assertIn("literal key", stored.lower())
        self.assertNotIn("Supported stored-data path", stored)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_real_bwapp_stored_xss_source_is_reported_conservatively(self):
        # The analyzer reads PHP source and follows static includes only. Its
        # generated report is written under this test's temporary directory.
        report = self.analyze_local_source("/var/www/html/bWAPP/xss_stored_1.php")

        inputs = report.split("Input evidence:", 1)[1].split(
            "Request presence evidence:", 1
        )[0]
        self.assertIn("[POST] entry", inputs)
        self.assertIn("xss_stored_1.php:68", inputs)
        self.assertNotIn("[POST] entry_all", inputs)

        presence = report.split("Request presence evidence:", 1)[1].split(
            "Unresolved request-reference evidence:", 1
        )[0]
        self.assertIn("[POST] entry_all", presence)
        self.assertIn("selection/control presence only", presence)

        unresolved = report.split("Unresolved request-reference evidence:", 1)[1].split(
            "Included-file input observations:", 1
        )[0]
        self.assertNotIn("[POST] entry (expression value unresolved)", unresolved)

        database = report.split("Database operation observations:", 1)[1].split(
            "Output branch observations:", 1
        )[0]
        self.assertIn("Database write statement construction (INSERT)", database)
        self.assertIn("xss_stored_1.php:81", database)
        self.assertIn("Database write execution (INSERT)", database)
        self.assertIn("xss_stored_1.php:83", database)
        self.assertIn("Database retrieval statement construction (SELECT)", database)
        self.assertIn("xss_stored_1.php:253", database)
        self.assertIn("xss_stored_1.php:260", database)
        self.assertIn("Database retrieval execution (SELECT)", database)
        self.assertIn("xss_stored_1.php:264", database)

        output = report.split("Output branch observations:", 1)[1].split(
            "Included-file analysis:", 1
        )[0]
        for line_number in (301, 320, 338):
            self.assertIn(f"xss_stored_1.php:{line_number}", output)
        self.assertIn("do not establish encoder behavior or exploitability", output)
        self.assertIn("does not establish a joined stored-data flow", database.lower())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report)
        self.assertNotIn("Supported source-to-sink relationship", report)

    def test_select_fetch_and_matching_row_column_reach_output(self):
        report = self.analyze_fixture(
            "select_output.php",
            """<?php
if ($show_rows) {
    $sql = "SELECT entry FROM blog WHERE id = 7";
    $rows = $db->query($sql);
    $row = $rows->fetch_object();
    echo $row->entry;
}
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("Supported SELECT-to-output path", stored)
        self.assertIn("SELECT entry FROM blog", stored)
        self.assertIn("WHERE id = 7", stored)
        for line_number in (3, 4, 5, 6):
            self.assertIn(f"select_output.php:{line_number}", stored)
        self.assertIn("fetch_object assigns result to $row", stored)
        self.assertIn("$row column entry", stored)
        self.assertIn("Guard condition: $show_rows", stored)
        self.assertIn("does not identify a particular earlier INSERT", stored)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_select_result_fetched_but_never_output_has_no_output_flow(self):
        report = self.analyze_fixture(
            "select_not_output.php",
            """<?php
$sql = "SELECT entry FROM blog WHERE id = 7";
$rows = $db->query($sql);
$row = $rows->fetch_assoc();
$count = count($row);
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("SELECT construction at select_not_output.php:2", stored)
        self.assertIn("fetch_assoc", stored)
        self.assertIn("No supported SELECT-to-output path established", stored)

    def test_unrelated_output_row_variable_is_not_linked_to_select_result(self):
        report = self.analyze_fixture(
            "select_unrelated_output.php",
            """<?php
$sql = "SELECT entry FROM blog WHERE id = 7";
$rows = $db->query($sql);
$row = $rows->fetch_object();
echo $other->entry;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertNotIn("Supported SELECT-to-output path", stored)
        self.assertIn("no supported fetch-to-SELECT relationship", stored)

    def test_same_table_read_does_not_link_to_write_without_matching_record_predicate(self):
        report = self.analyze_fixture(
            "select_same_table_unmatched_record.php",
            """<?php
$entry = $_POST['entry'];
$insert_sql = "INSERT INTO notes (id, entry) VALUES (7, '" . $entry . "')";
$db->query($insert_sql);
$read_sql = "SELECT entry FROM notes";
$rows = $db->query($read_sql);
$row = $rows->fetch_object();
echo $row->entry;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("Supported SELECT-to-output path", stored)
        self.assertIn("no WHERE predicate", stored)
        self.assertNotIn("Supported stored-data path", stored)
        self.assertIn("does not prove a row match", stored)
        self.assertIn("matching table or column alone is insufficient", stored)

    def test_conflicting_select_assignments_do_not_create_result_to_output_path(self):
        report = self.analyze_fixture(
            "select_conflicting_assignments.php",
            """<?php
if ($first) {
    $sql = "SELECT entry FROM blog WHERE id = 7";
} else {
    $sql = "SELECT body FROM blog WHERE id = 7";
}
$rows = $db->query($sql);
$row = $rows->fetch_object();
echo $row->entry;
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertNotIn("Supported SELECT-to-output path", stored)
        self.assertIn("multiple or missing query assignments make the statement ambiguous", stored)
        self.assertIn("conflicting SELECT assignments", stored)

    def test_dynamic_select_and_unsupported_fetch_stay_unresolved(self):
        dynamic_report = self.analyze_fixture(
            "dynamic_select.php",
            """<?php
$table = $_GET['table'];
$sql = "SELECT entry FROM " . $table;
$rows = $db->query($sql);
$row = $rows->fetch_object();
echo $row->entry;
""",
        )
        dynamic_stored = dynamic_report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertNotIn("Supported SELECT-to-output path", dynamic_stored)
        self.assertIn("dynamic or unsupported query expression", dynamic_stored)

        fetch_report = self.analyze_fixture(
            "unsupported_fetch.php",
            """<?php
$sql = "SELECT entry FROM blog WHERE id = 7";
$rows = $db->query($sql);
$row = $rows->fetch_array();
echo $row['entry'];
""",
        )
        fetch_stored = fetch_report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertNotIn("Supported SELECT-to-output path", fetch_stored)
        self.assertIn("unsupported fetch method fetch_array", fetch_stored)
        self.assertIn("Unresolved SELECT-to-output relationship", fetch_stored)

    def test_select_output_helper_return_keeps_html_and_sql_contexts_distinct(self):
        report = self.analyze_fixture(
            "select_output_helper.php",
            """<?php
function output_value($value) {
    return htmlspecialchars($value, ENT_QUOTES);
}
$sql = "SELECT entry FROM blog WHERE id = 7";
$rows = $db->query($sql);
$row = $rows->fetch_object();
echo output_value($row->entry);
""",
        )

        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]
        self.assertIn("Supported SELECT-to-output path", stored)
        self.assertIn("output_value definition", stored)
        self.assertIn("HTML output encoding, not SQL escaping", stored)
        self.assertIn("effectiveness for the specific output context is not inferred", stored)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_real_bwapp_stored_select_to_output_remains_unresolved(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/xss_stored_1.php")
        stored = report.split("Stored-data provenance observations:", 1)[1].split(
            "Prepared-statement observations:", 1
        )[0]

        self.assertIn("SELECT", stored)
        self.assertIn("xss_stored_1.php:253", stored)
        self.assertIn("xss_stored_1.php:260", stored)
        self.assertIn("xss_stored_1.php:264", stored)
        self.assertIn("xss_stored_1.php:287", stored)
        self.assertIn("xss_stored_1.php:301", stored)
        self.assertIn("multiple or missing query assignments", stored)
        self.assertIn("wildcard projection", stored)
        self.assertNotIn("Supported SELECT-to-output path", stored)
        self.assertNotIn("Supported stored-data path", stored)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_real_bwapp_sqli_get_source_summarizes_helper_but_keeps_query_flow_unresolved(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/sqli_1.php")

        inputs = report.split("Input evidence:", 1)[1].split(
            "Request presence evidence:", 1
        )[0]
        self.assertIn("[GET] title", inputs)
        self.assertIn("sqli_1.php:141", inputs)
        self.assertNotIn("[GET] action", inputs)

        unresolved = report.split("Unresolved analysis candidates:", 1)[1].split(
            "Evidence and confidence limitations:", 1
        )[0]
        self.assertNotIn("Unresolved function definition sqli at sqli_1.php:25", unresolved)
        self.assertNotIn("Unresolved function call sqli at sqli_1.php:143", unresolved)
        self.assertIn("Unresolved conditional assignment at sqli_1.php:143", unresolved)
        self.assertIn("switch($_COOKIE[\"security_level\"])", unresolved)
        self.assertIn("function behavior and sanitization effectiveness are not inferred", report.lower())

        database = report.split("Database operation observations:", 1)[1].split(
            "Output branch observations:", 1
        )[0]
        self.assertIn("Database retrieval statement construction (SELECT)", database)
        self.assertIn("sqli_1.php:143", database)
        sql_sinks = report.split("Sink observations:", 1)[1].split(
            "Source-flow evidence:", 1
        )[0]
        self.assertIn("Sink text (SQL/query) at sqli_1.php:145", sql_sinks)

        output = report.split("Output branch observations:", 1)[1].split(
            "Included-file analysis:", 1
        )[0]
        self.assertIn("Output branch observation at sqli_1.php:181", output)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertNotIn("Explicit textual relationship: [GET] title", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report)

    def test_real_bwapp_sqli_selector_tracks_guarded_helper_path_to_query(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/sqli_2.php")

        inputs = report.split("Input evidence:", 1)[1].split(
            "Unresolved conditional input evidence:", 1
        )[0]
        self.assertIn("[GET] movie", inputs)
        self.assertIn("sqli_2.php:165: $id = $_GET[\"movie\"]", inputs)
        self.assertNotIn("sqli_2.php:162", inputs)

        database = report.split("Database operation observations:", 1)[1].split(
            "Output branch observations:", 1
        )[0]
        self.assertIn("sqli_2.php:35", database)
        self.assertIn("sqli_2.php:167", database)
        self.assertIn("No supported prepare/bind/execute sequence detected.", report)
        self.assertIn("Function call: sqli_2.php:173 calls sqli(...).", report)
        sql_sinks = report.split("Sink observations:", 1)[1].split(
            "Source-flow evidence:", 1
        )[0]
        self.assertIn("Sink text (SQL/query) at sqli_2.php:37", sql_sinks)
        self.assertIn("Sink text (SQL/query) at sqli_2.php:177", sql_sinks)

        unresolved = report.split("Unresolved analysis candidates:", 1)[1].split(
            "Evidence and confidence limitations:", 1
        )[0]
        self.assertNotIn("Unresolved function definition sqli at sqli_2.php:39", unresolved)
        self.assertNotIn("Unresolved function call sqli at sqli_2.php:173", unresolved)
        self.assertNotIn("Unresolved unsupported conditional structure at sqli_2.php:170", unresolved)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Conditional textual relationship: [GET] movie", source_flow)
        self.assertIn("$id receives [GET] movie", source_flow)
        self.assertIn("Function parameter: $data receives $id", source_flow)
        self.assertIn("Helper branch condition: switch ($_COOKIE[\"security_level\"]), case \"0\"", source_flow)
        self.assertIn("Helper branch return: no_check($data) unchanged", source_flow)
        self.assertIn("Helper branch return expression: sqli_check_2($data)", source_flow)
        self.assertIn("Guard condition: if (isset($_GET[\"movie\"])) at sqli_2.php:162", source_flow)
        self.assertIn("Guard condition: if ($id) at sqli_2.php:170", source_flow)
        self.assertIn("Sink text (SQL/query) at sqli_2.php:177", source_flow)
        self.assertIn("transformation effectiveness is not inferred", source_flow.lower())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report)

    def test_real_bwapp_prepared_selector_tracks_request_to_binding_and_execution(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/sqli_2-ps.php")

        inputs = report.split("Input evidence:", 1)[1].split(
            "Unresolved conditional input evidence:", 1
        )[0]
        self.assertIn("[GET] movie", inputs)
        self.assertIn('sqli_2-ps.php:140: $id = $_GET["movie"]', inputs)

        prepared = report.split("Prepared-statement observations:", 1)[1].split(
            "Output branch observations:", 1
        )[0]
        self.assertIn("sqli_2-ps.php:142", prepared)
        self.assertIn("WHERE id =?", prepared)
        self.assertIn("prepare($sql)", prepared)
        self.assertIn("sqli_2-ps.php:149", prepared)
        self.assertIn("Bound parameter #1 uses $id", prepared)
        self.assertIn("sqli_2-ps.php:153", prepared)
        self.assertIn("does not establish that the entire application is secure", prepared)

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Conditional textual relationship: [GET] movie", source_flow)
        self.assertIn("$id receives [GET] movie", source_flow)
        self.assertIn("bound parameter #1 ($id)", source_flow)
        self.assertIn("sqli_2-ps.php:149", source_flow)
        self.assertIn("sqli_2-ps.php:153", source_flow)
        self.assertIn("Guard condition: if (isset($_GET[\"movie\"])) at sqli_2-ps.php:137", source_flow)
        self.assertIn("not treated as validation or sanitization", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_prepared_binding_traces_request_assignment_to_bound_parameter(self):
        report = self.analyze_fixture(
            "prepared_binding_flow.php",
            """<?php
if (isset($_GET['item'])) {
    $raw = $_GET['item'];
    $id = $raw;
    $sql = "SELECT name FROM items WHERE id = ?";
    if ($stmt = $db->prepare($sql)) {
        $stmt->bind_param("s", $id);
        $stmt->execute();
    }
}
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Conditional textual relationship: [GET] item", source_flow)
        self.assertIn("bound parameter #1 ($id)", source_flow)
        self.assertIn("prepared_binding_flow.php:3 $raw receives [GET] item", source_flow)
        self.assertIn("prepared_binding_flow.php:4 $id references $raw", source_flow)
        self.assertIn("Guard condition: if (isset($_GET['item']))", source_flow)
        self.assertIn("not treated as validation or sanitization", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_prepared_query_without_request_input_has_no_source_flow(self):
        report = self.analyze_fixture(
            "prepared_without_request.php",
            """<?php
$id = 7;
$sql = "SELECT name FROM items WHERE id = ?";
if ($stmt = $db->prepare($sql)) {
    $stmt->bind_param("i", $id);
    $stmt->execute();
}
""",
        )

        prepared = report.split("Prepared-statement observations:", 1)[1].split(
            "Output branch observations:", 1
        )[0]
        self.assertIn("1 positional placeholder", prepared)
        self.assertIn("Bound parameter #1 uses $id", prepared)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("No supported source-to-sink relationship established.", source_flow)
        self.assertNotIn("textual relationship", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_unrelated_request_variable_is_not_linked_to_prepared_binding(self):
        report = self.analyze_fixture(
            "prepared_unrelated_variable.php",
            """<?php
$request_id = $_GET['id'];
$fixed = 7;
$sql = "SELECT name FROM items WHERE id = ?";
if ($stmt = $db->prepare($sql)) {
    $stmt->bind_param("i", $fixed);
    $stmt->execute();
}
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("No supported source-to-sink relationship established.", source_flow)
        self.assertNotIn("[GET] id", source_flow)
        self.assertIn("Bound parameter #1 uses $fixed", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_ambiguous_prepared_binding_remains_unresolved(self):
        report = self.analyze_fixture(
            "prepared_ambiguous_binding.php",
            """<?php
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    $other = 2;
    $sql = "SELECT name FROM items WHERE id = ?";
    if ($stmt = $db->prepare($sql)) {
        $stmt->bind_param("ss", $id, $other);
        $stmt->execute();
    }
}
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("No supported source-to-sink relationship established.", source_flow)
        self.assertNotIn("bound parameter #1", source_flow)
        self.assertIn("Unresolved prepared-statement binding", report)
        self.assertIn("placeholder count", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_real_bwapp_stored_cookie_source_reports_request_reference(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/xss_stored_2.php")

        inputs = report.split("Input evidence:", 1)[1].split(
            "Unresolved conditional input evidence:", 1
        )[0]
        self.assertIn("[REQUEST] genre", inputs)
        self.assertIn('xss_stored_2.php:29: $genre = $_REQUEST["genre"]', inputs)
        self.assertNotIn("No direct GET/POST/REQUEST inputs detected.", inputs)

        unresolved = report.split("Unresolved analysis candidates:", 1)[1].split(
            "Evidence and confidence limitations:", 1
        )[0]
        self.assertIn("Unresolved unsupported conditional structure", unresolved)
        self.assertIn("xss_stored_2.php:31", unresolved)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertNotIn("Explicit textual relationship: [REQUEST] genre", source_flow)
        self.assertNotIn("Conditional textual relationship: [REQUEST] genre", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report)

    def test_real_bwapp_xss_get_tracks_guarded_helper_paths_to_echo(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/xss_get.php")

        inputs = report.split("Input evidence:", 1)[1].split(
            "Request presence evidence:", 1
        )[0]
        for parameter, line_number in (("firstname", 131), ("lastname", 132)):
            self.assertIn(f"[GET] {parameter}", inputs)
            self.assertIn(f"xss_get.php:{line_number}", inputs)
        self.assertNotIn("xss_get.php:128", inputs)
        presence_check = Path("/var/www/html/bWAPP/xss_get.php").read_text().splitlines()[127]
        self.assertIn('isset($_GET["firstname"])', presence_check)
        self.assertIn('isset($_GET["lastname"])', presence_check)
        self.assertIn("$firstname = $_GET[\"firstname\"]", inputs)
        self.assertIn("$lastname = $_GET[\"lastname\"]", inputs)

        unresolved = report.split("Unresolved analysis candidates:", 1)[1].split(
            "Evidence and confidence limitations:", 1
        )[0]
        self.assertNotIn("Unresolved function definition xss at xss_get.php:24", unresolved)
        self.assertNotIn("Unresolved function call xss at xss_get.php:144", unresolved)
        self.assertNotIn("Unresolved unsupported conditional structure at xss_get.php:134", unresolved)
        self.assertNotIn("Unresolved unsupported conditional structure at xss_get.php:141", unresolved)
        self.assertIn("function behavior and sanitization effectiveness are not inferred", report.lower())

        output = report.split("Output branch observations:", 1)[1].split(
            "Included-file analysis:", 1
        )[0]
        self.assertIn("Output branch observation at xss_get.php:144", output)
        self.assertIn("xss($firstname)", output)
        self.assertIn("xss($lastname)", output)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Conditional textual relationship: [GET] firstname", source_flow)
        self.assertIn("Conditional textual relationship: [GET] lastname", source_flow)
        self.assertIn("$firstname receives [GET] firstname", source_flow)
        self.assertIn("$lastname receives [GET] lastname", source_flow)
        self.assertIn("Guard condition: if (isset($_GET[\"firstname\"]) && isset($_GET[\"lastname\"])) at xss_get.php:128", source_flow)
        self.assertIn("Guard condition: if ($firstname == \"\" or $lastname == \"\") at xss_get.php:134; else (condition false)", source_flow)
        self.assertIn("Helper branch condition: switch ($_COOKIE[\"security_level\"])", source_flow)
        self.assertIn("Helper branch return expression: xss_check_4($data)", source_flow)
        self.assertIn("transformation effectiveness is not inferred", source_flow.lower())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report)

    def test_real_bwapp_xss_post_sources_keep_helper_output_unresolved(self):
        report = self.analyze_local_source("/var/www/html/bWAPP/xss_post.php")

        inputs = report.split("Input evidence:", 1)[1].split(
            "Request presence evidence:", 1
        )[0]
        for parameter, line_number in (("firstname", 131), ("lastname", 132)):
            self.assertIn(f"[POST] {parameter}", inputs)
            self.assertIn(f"xss_post.php:{line_number}", inputs)
        self.assertNotIn("xss_post.php:128", inputs)
        presence_check = Path("/var/www/html/bWAPP/xss_post.php").read_text().splitlines()[127]
        self.assertIn('isset($_POST["firstname"])', presence_check)
        self.assertIn('isset($_POST["lastname"])', presence_check)
        self.assertIn("$firstname = $_POST[\"firstname\"]", inputs)
        self.assertIn("$lastname = $_POST[\"lastname\"]", inputs)

        unresolved = report.split("Unresolved analysis candidates:", 1)[1].split(
            "Evidence and confidence limitations:", 1
        )[0]
        self.assertIn("Unresolved function definition xss at xss_post.php:24", unresolved)
        self.assertIn("Unresolved function call xss at xss_post.php:144", unresolved)
        self.assertIn('switch($_COOKIE["security_level"])', unresolved)
        self.assertIn("function behavior and sanitization effectiveness are not inferred", report.lower())

        output = report.split("Output branch observations:", 1)[1].split(
            "Included-file analysis:", 1
        )[0]
        self.assertIn("Output branch observation at xss_post.php:144", output)
        self.assertIn("xss($firstname)", output)
        self.assertIn("xss($lastname)", output)
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertNotIn("Explicit textual relationship: [POST] firstname", source_flow)
        self.assertNotIn("Explicit textual relationship: [POST] lastname", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report)

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

    def test_next_line_if_nested_block_tracks_guarded_provenance(self):
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
        self.assertIn("Conditional textual relationship: [GET] id", report)
        self.assertIn("Guard condition: if ($enabled)", report)
        self.assertIn("Guard condition: if ($other)", report)
        self.assertIn("[GET] id", report)
        self.assertNotIn("Unresolved unsupported conditional structure", report)
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

    def test_simple_identity_helper_reports_argument_return_provenance(self):
        report = self.analyze_fixture(
            "identity_return_flow.php",
            """<?php
function return_value($value) {
    return $value;
}
$input = $_GET['value'];
echo return_value($input);
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Explicit textual relationship: [GET] value", source_flow)
        self.assertIn("Function parameter: $value receives $input", source_flow)
        self.assertIn("Function return: identity_return_flow.php:3 returns $value", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_helper_return_branches_preserve_identity_and_transform_conditions(self):
        report = self.analyze_fixture(
            "branch_return_flow.php",
            """<?php
function render_value($value, $mode) {
    switch ($mode) {
        case 'raw':
            return $value;
        case 'escaped':
            return htmlspecialchars($value, ENT_QUOTES);
        case 'sql':
            return mysqli_real_escape_string($db, $value);
        default:
            return $value;
    }
}
$input = $_GET['value'];
echo render_value($input, $mode);
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Conditional textual relationship: [GET] value", source_flow)
        self.assertIn("Helper branch condition: switch ($mode), case 'raw'", source_flow)
        self.assertIn("Helper branch return: $value unchanged", source_flow)
        self.assertIn("Helper branch condition: switch ($mode), case 'escaped'", source_flow)
        self.assertIn("Helper branch return expression: htmlspecialchars($value, ENT_QUOTES)", source_flow)
        self.assertIn("Helper branch return expression: mysqli_real_escape_string($db, $value)", source_flow)
        self.assertIn("SQL escaping, not HTML output encoding", source_flow)
        self.assertIn("HTML output encoding, not SQL escaping", source_flow)
        self.assertIn("effectiveness is not inferred", report.lower())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_helper_transformations_are_classified_by_definition_not_name(self):
        sql_report = self.analyze_fixture(
            "sql_escape_helper.php",
            """<?php
function sql_escape($value) {
    return mysqli_real_escape_string($db, $value);
}
$input = $_GET['value'];
echo sql_escape($input);
""",
        )
        sql_flow = sql_report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("classified as SQL escaping, not HTML output encoding", sql_flow)
        self.assertNotIn("HTML output encoding, not SQL escaping", sql_flow)
        self.assertIn("Transformation effectiveness is not inferred", sql_flow)

        html_report = self.analyze_fixture(
            "html_escape_for_sql.php",
            """<?php
function html_escape($value) {
    return htmlspecialchars($value, ENT_QUOTES);
}
$input = $_GET['value'];
$query = html_escape($input);
mysqli_query($db, $query);
""",
        )
        html_flow = html_report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("HTML output encoding, not SQL escaping", html_flow)
        self.assertNotIn("classified as SQL escaping", html_flow)
        self.assertIn("Transformation effectiveness is not inferred", html_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", html_report)

    def test_addslashes_is_not_reported_as_html_output_encoding_or_sql_escape(self):
        report = self.analyze_fixture(
            "addslashes_html_context.php",
            """<?php
function slash_value($value) {
    return addslashes($value);
}
$input = $_GET['value'];
echo slash_value($input);
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("addslashes quote escaping observed", source_flow)
        self.assertIn("not HTML output encoding", source_flow)
        self.assertIn("HTML-context protection is not inferred", source_flow)
        self.assertNotIn("classified as SQL escaping", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_addslashes_sql_context_does_not_claim_effective_sql_protection(self):
        report = self.analyze_fixture(
            "addslashes_sql_context.php",
            """<?php
function slash_value($value) {
    return addslashes($value);
}
$input = $_GET['value'];
$escaped = slash_value($input);
$query = "SELECT * FROM items WHERE name='" . $escaped . "'";
mysqli_query($db, $query);
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("Sink text (SQL/query)", source_flow)
        self.assertIn("addslashes quote escaping observed", source_flow)
        self.assertIn("SQL-context effectiveness is not inferred", source_flow)
        self.assertNotIn("classified as SQL escaping", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_addslashes_used_in_mixed_contexts_gets_sink_specific_notes(self):
        report = self.analyze_fixture(
            "addslashes_mixed_contexts.php",
            """<?php
function slash_value($value) {
    return addslashes($value);
}
$input = $_GET['value'];
$escaped = slash_value($input);
echo $escaped;
$query = "SELECT * FROM items WHERE name='" . $escaped . "'";
mysqli_query($db, $query);
""",
        )
        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        html_sink, sql_sink = source_flow.split(
            "Sink text (SQL/query)", 1
        )
        self.assertIn("Sink text (output)", html_sink)
        self.assertIn("not HTML output encoding", html_sink)
        self.assertIn("HTML-context protection is not inferred", html_sink)
        self.assertNotIn("SQL-context effectiveness", html_sink)
        self.assertIn("addslashes quote escaping observed", sql_sink)
        self.assertIn("SQL-context effectiveness is not inferred", sql_sink)
        self.assertNotIn("HTML output encoding", sql_sink)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_unsupported_helper_branch_behavior_remains_unresolved(self):
        report = self.analyze_fixture(
            "unsupported_branch_return.php",
            """<?php
function choose_value($value, $mode) {
    if ($mode) {
        return $value;
    }
    return htmlspecialchars($value, ENT_QUOTES);
}
$input = $_GET['value'];
echo choose_value($input, $mode);
""",
        )

        self.assertIn("Unresolved function definition choose_value", report)
        self.assertIn("Unresolved function call choose_value", report)
        self.assertNotIn("Explicit textual relationship", report)
        self.assertNotIn("Conditional textual relationship", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_real_bwapp_iframe_helper_branches_report_conditional_provenance(self):
        bwapp_path = Path("/var/www/html/bWAPP/xss_get.php")
        bwapp_source = bwapp_path.read_text()
        helper_start = bwapp_source.index("function xss($data)")
        helper_end = bwapp_source.index("\n?>", helper_start)
        helper_source = bwapp_source[helper_start:helper_end].strip()
        self.assertIn('switch($_COOKIE["security_level"])', helper_source)
        self.assertIn("$data = no_check($data)", helper_source)

        external_source = Path("/var/www/html/bWAPP/functions_external.php").read_text()

        def extract_external_helper(name):
            start = external_source.index(f"function {name}(")
            end = external_source.index("\n}", start) + 2
            return external_source[start:end]

        external_helpers = "\n".join(
            extract_external_helper(name)
            for name in ("no_check", "xss_check_3", "xss_check_4")
        )

        fixture_source = (
            "<?php\n"
            + "\n" * max(0, bwapp_source[:helper_start].count("\n") - 1)
            + helper_source
            + "\n"
            + external_helpers
            + "\n$input = $_GET[\"ParamUrl\"];\necho xss($input);\n"
        )
        report = self.analyze_fixture("bwapp_helper_return_flow.php", fixture_source)

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("[GET] ParamUrl", source_flow)
        self.assertIn("Conditional textual relationship", source_flow)
        self.assertIn('case "0"', source_flow)
        self.assertIn('xss_check_4($data)', source_flow)
        self.assertIn('xss_check_3($data)', source_flow)
        self.assertIn("transformation effectiveness is not inferred", report.lower())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_helper_presence_without_argument_provenance_does_not_create_flow(self):
        report = self.analyze_fixture(
            "helper_without_input_provenance.php",
            """<?php
function return_value($value) {
    return $value;
}
$input = $_GET['value'];
$fixed = return_value('constant');
echo $fixed;
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("No supported source-to-sink relationship established.", source_flow)
        self.assertNotIn("Explicit textual relationship", source_flow)
        self.assertNotIn("Conditional textual relationship", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_guard_alone_and_unrelated_variables_do_not_create_provenance(self):
        report = self.analyze_fixture(
            "guard_without_assignment_provenance.php",
            """<?php
if ($_GET['value'] == 'safe') {
    $output = 'constant';
    echo $output;
}
if (isset($_GET['other'])) {
    $other_input = $_GET['other'];
}
if ($display) {
    $unrelated = 'fixed';
    echo $unrelated;
}
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("No supported source-to-sink relationship established.", source_flow)
        self.assertNotIn("textual relationship: [GET] value", source_flow)
        self.assertNotIn("textual relationship: [GET] other", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_unproven_guarded_assignment_does_not_propagate_to_sink(self):
        report = self.analyze_fixture(
            "guarded_unknown_assignment.php",
            """<?php
if (isset($_GET['value'])) {
    $copy = unknown_transform($_GET['value']);
    echo $copy;
}
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("No supported source-to-sink relationship established.", source_flow)
        self.assertIn("Unresolved function call unknown_transform", report)
        self.assertNotIn("textual relationship: [GET] value", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

    def test_guarded_reassignment_with_ambiguous_provenance_stays_unresolved(self):
        report = self.analyze_fixture(
            "guarded_ambiguous_reassignment.php",
            """<?php
if (isset($_GET['value'])) {
    $selected = $_GET['value'];
    if ($replace) {
        $selected = 'constant';
    }
    echo $selected;
}
""",
        )

        source_flow = report.split("Source-flow evidence:", 1)[1].split(
            "Local function analysis:", 1
        )[0]
        self.assertIn("No supported source-to-sink relationship established.", source_flow)
        self.assertIn("Unresolved conditional assignment", report)
        self.assertNotIn("textual relationship: [GET] value", source_flow)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

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
