"""Offline, table-driven regression benchmark for the supported PHP-flow subset."""

import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests" / "fixtures" / "php_benchmark"


CASES = (
    {
        "category": "SQL/query flow", "name": "query_flow.php", "label": "positive",
        "file": "sql/query_flow.php", "signal": True,
        "evidence": (
            "[GET] record_id at query_flow.php:2",
            "Explicit textual relationship: [GET] record_id",
            "Sink text (SQL/query) at query_flow.php:4",
        ),
    },
    {
        "category": "SQL/query flow", "name": "query_benign.php", "label": "benign",
        "file": "sql/query_benign.php", "signal": False,
        "evidence": ("Sink text (SQL/query)",),
        "no_evidence": ("Explicit textual relationship: [GET] request_id",),
    },
    {
        "category": "SQL/query flow", "name": "query_unresolved.php", "label": "unresolved",
        "file": "sql/query_unresolved.php", "signal": False,
        "evidence": ("Unresolved assignment at query_unresolved.php:3",),
        "no_evidence": ("Explicit textual relationship: [GET] filter",),
    },
    {
        "category": "SQL/query flow", "name": "query_alias.php", "label": "positive",
        "file": "sql/query_alias.php", "signal": True,
        "evidence": (
            "[GET] record_id at query_alias.php:2",
            "Assignment evidence: query_alias.php:3 $record_id references $raw_id",
            "Sink text (SQL/query) at query_alias.php:5",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "SQL/query flow", "name": "query_escape_helper.php", "label": "positive",
        "file": "sql/query_escape_helper.php", "signal": True,
        "evidence": (
            "Function transformed return expression: mysqli_real_escape_string",
            "SQL-context effectiveness is not inferred",
            "Sink text (SQL/query)",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "SQL/query flow", "name": "query_misleading.php", "label": "benign",
        "file": "sql/query_misleading.php", "signal": False,
        "evidence": ("NO INPUT DETECTED", "Sink text (SQL/query)"),
        "no_evidence": ("Explicit textual relationship: [GET]",),
    },
    {
        "category": "SQL/query flow", "name": "query_prepared.php", "label": "benign",
        "file": "sql/query_prepared.php", "signal": False,
        "evidence": ("Binding evidence: parameter #1 uses $record_id", "not concatenated into the SQL text"),
        "no_evidence": ("SQL injection candidate", "Request data is concatenated into the SQL text"),
    },
    {
        "category": "XSS output context", "name": "attribute_flow.php", "label": "positive",
        "file": "xss/attribute_flow.php", "signal": True,
        "evidence": (
            "[GET] label at attribute_flow.php:2",
            "Sink text (output) at attribute_flow.php:3",
            "Output context evidence: HTML attribute",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "XSS output context", "name": "output_benign.php", "label": "benign",
        "file": "xss/output_benign.php", "signal": False,
        "evidence": ("Sink text (output)",),
        "no_evidence": ("Output context evidence: HTML attribute", "Explicit textual relationship: [GET] label"),
    },
    {
        "category": "XSS output context", "name": "output_unresolved.php", "label": "unresolved",
        "file": "xss/output_unresolved.php", "signal": False,
        "evidence": ("Unresolved",),
        "no_evidence": ("Output context evidence: HTML attribute",),
    },
    {
        "category": "XSS output context", "name": "encoded_helper.php", "label": "positive",
        "file": "xss/encoded_helper.php", "signal": True,
        "evidence": (
            "[GET] message at encoded_helper.php:5",
            "Sink text (output) at encoded_helper.php:6",
            "Output context evidence: HTML text",
            "HTML output encoding, not SQL escaping",
            "context effectiveness is not inferred",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "XSS output context", "name": "static_misleading.php", "label": "benign",
        "file": "xss/static_misleading.php", "signal": False,
        "evidence": ("NO INPUT DETECTED", "Sink text (output)"),
        "no_evidence": ("Explicit textual relationship", "Output context evidence:"),
    },
    {
        "category": "Object-level access review", "name": "object_flow.php", "label": "positive",
        "file": "object_access/object_flow.php", "signal": True,
        "evidence": (
            "Object-level access-control review observations",
            "[GET] document_id at object_flow.php:2",
            "SQL/query at object_flow.php:4",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "Object-level access review", "name": "object_benign.php", "label": "benign",
        "file": "object_access/object_benign.php", "signal": False,
        "evidence": ("Sink text (SQL/query)",),
        "no_evidence": ("Object-level access-control review observations",),
    },
    {
        "category": "Object-level access review", "name": "object_unresolved.php", "label": "unresolved",
        "file": "object_access/object_unresolved.php", "signal": False,
        "evidence": ("Unresolved",),
        "no_evidence": ("Object-level access-control review observations",),
    },
    {
        "category": "Object-level access review", "name": "object_guard.php", "label": "positive",
        "file": "object_access/object_guard.php", "signal": True,
        "evidence": (
            "Object-level access-control review observations",
            "[GET] document_id at object_guard.php:2",
            "SQL/query at object_guard.php:5",
            "Authorization-like condition observed",
            "does not establish that it checks the requested object's owner",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "Object-level access review", "name": "object_misleading.php", "label": "benign",
        "file": "object_access/object_misleading.php", "signal": False,
        "evidence": ("NO INPUT DETECTED", "Sink text (SQL/query)"),
        "no_evidence": ("Object-level access-control review observations",),
    },
    {
        "category": "URL-fetch/SSRF review", "name": "url_flow.php", "label": "positive",
        "file": "url_fetch/url_flow.php", "signal": True,
        "evidence": (
            "Request input [GET] url at url_flow.php:2",
            "file_get_contents() at url_flow.php:3",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "URL-fetch/SSRF review", "name": "url_benign.php", "label": "benign",
        "file": "url_fetch/url_benign.php", "signal": False,
        "evidence": ("No supported request-controlled flow to file_get_contents() was established",),
        "no_evidence": ("Request input [GET] url",),
    },
    {
        "category": "URL-fetch/SSRF review", "name": "url_unresolved.php", "label": "unresolved",
        "file": "url_fetch/url_unresolved.php", "signal": False,
        "evidence": (
            "No supported request-controlled flow to file_get_contents() was established",
            "Unresolved",
        ),
        "no_evidence": ("Request input [GET] url",),
    },
    {
        "category": "URL-fetch/SSRF review", "name": "url_format_check.php", "label": "positive",
        "file": "url_fetch/url_format_check.php", "signal": True,
        "evidence": (
            "Request input [GET] url at url_format_check.php:2",
            "file_get_contents() at url_format_check.php:4",
            "Recognized URL-format validation evidence",
            "does not establish an allowed host, scheme",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "URL-fetch/SSRF review", "name": "url_misleading.php", "label": "benign",
        "file": "url_fetch/url_misleading.php", "signal": False,
        "evidence": ("Sink text (Dangerous server-side operation: file_get_contents)",),
        "no_evidence": ("Request input [GET] url", "has a supported flow to file_get_contents()"),
    },
    {
        "category": "Command-execution review", "name": "command_flow.php", "label": "positive",
        "file": "command/command_flow.php", "signal": True,
        "evidence": (
            "[GET] command at command_flow.php:2",
            "shell_exec() at command_flow.php:3",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "Command-execution review", "name": "command_benign.php", "label": "benign",
        "file": "command/command_benign.php", "signal": False,
        "evidence": ("No supported request-controlled flow to an OS command-execution function",),
        "no_evidence": ("Request input [GET] command",),
    },
    {
        "category": "Command-execution review", "name": "command_unresolved.php", "label": "unresolved",
        "file": "command/command_unresolved.php", "signal": False,
        "evidence": (
            "Unresolved",
            "No supported request-controlled flow to an OS command-execution function was established",
        ),
        "no_evidence": ("Request input [GET] command",),
    },
    {
        "category": "Command-execution review", "name": "command_escape_alias.php", "label": "positive",
        "file": "command/command_escape_alias.php", "signal": True,
        "evidence": (
            "[GET] argument at command_escape_alias.php:2",
            "shell_exec() at command_escape_alias.php:6",
            "Recognized command argument transformation: escapeshellarg($argument)",
            "safe argument boundaries, option handling, command composition",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "Command-execution review", "name": "command_misleading.php", "label": "benign",
        "file": "command/command_misleading.php", "signal": False,
        "evidence": ("NO INPUT DETECTED", "Sink text (Dangerous server-side operation: shell_exec)"),
        "no_evidence": ("Request input [GET] command", "has a supported flow to shell_exec()"),
    },
    {
        "category": "File-access/path review", "name": "path_flow.php", "label": "positive",
        "file": "file_access/path_flow.php", "signal": True,
        "evidence": (
            "[GET] path at path_flow.php:2",
            "file_get_contents() at path_flow.php:3",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "File-access/path review", "name": "path_benign.php", "label": "benign",
        "file": "file_access/path_benign.php", "signal": False,
        "evidence": ("No supported request-controlled flow to file_get_contents() or readfile()",),
        "no_evidence": ("Request input [GET] path",),
    },
    {
        "category": "File-access/path review", "name": "path_unresolved.php", "label": "unresolved",
        "file": "file_access/path_unresolved.php", "signal": False,
        "evidence": (
            "Unresolved assignment at path_unresolved.php:3",
            "No supported request-controlled flow to file_get_contents() or readfile()",
        ),
        "no_evidence": ("Request input [GET] path",),
    },
    {
        "category": "File-access/path review", "name": "path_basename.php", "label": "positive",
        "file": "file_access/path_basename.php", "signal": True,
        "evidence": (
            "[GET] path at path_basename.php:2",
            "file_get_contents() at path_basename.php:5",
            "Path transformation evidence: basename($path)",
            "does not establish base-directory containment",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
    {
        "category": "File-access/path review", "name": "path_misleading.php", "label": "benign",
        "file": "file_access/path_misleading.php", "signal": False,
        "evidence": ("Sink text (Dangerous server-side operation: file_get_contents)",),
        "no_evidence": ("Request input [GET] path", "has a supported request-controlled flow to file_get_contents()"),
    },
    {
        "category": "File-upload review", "name": "upload_flow.php", "label": "positive",
        "file": "upload/upload_flow.php", "signal": True,
        "evidence": (
            "Upload source: $_FILES['avatar']['tmp_name'] at upload_flow.php:2",
            "Storage sink: move_uploaded_file() at upload_flow.php:3",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED.",
        ),
    },
    {
        "category": "File-upload review", "name": "upload_benign.php", "label": "benign",
        "file": "upload/upload_benign.php", "signal": False,
        "evidence": ("No $_FILES upload handling detected.",),
        "no_evidence": ("Storage sink: move_uploaded_file()",),
    },
    {
        "category": "File-upload review", "name": "upload_unresolved.php", "label": "unresolved",
        "file": "upload/upload_unresolved.php", "signal": False,
        "evidence": ("Unresolved upload handling: $_FILES['archive']", "Vulnerability status: UNCONFIRMED."),
        "no_evidence": ("Storage sink: move_uploaded_file()",),
    },
    {
        "category": "File-upload review", "name": "upload_checks.php", "label": "positive",
        "file": "upload/upload_checks.php", "signal": True,
        "evidence": (
            "Upload source: $_FILES['document']['tmp_name'] at upload_checks.php:3",
            "Storage sink: move_uploaded_file() at upload_checks.php:6",
            "Observed filename/extension check",
            "Observed MIME-type check",
            "Observed upload error check",
            "Observed upload size check",
            "none is treated as sufficient validation or proof of safety",
            "Severity: NEEDS_REVIEW",
            "Vulnerability status: UNCONFIRMED.",
        ),
    },
    {
        "category": "File-upload review", "name": "upload_misleading.php", "label": "benign",
        "file": "upload/upload_misleading.php", "signal": False,
        "evidence": ("NO INPUT DETECTED",),
        "no_evidence": ("Storage sink: move_uploaded_file()", "Upload source: $_FILES"),
    },
)

# One explanation per fixture makes the label auditable: positive means the
# supported static pattern is present, benign means its suspicious-looking
# syntax has no supported source-to-sink relationship, and unresolved means
# the available syntax is intentionally outside the traced subset.
CASE_RATIONALES = {
    "query_flow.php": "GET data is concatenated into SQL text passed to a query sink.",
    "query_benign.php": "A request value is unrelated to the static SQL query.",
    "query_unresolved.php": "The request value passes through an unsupported query builder.",
    "query_alias.php": "A simple local alias carries GET data into concatenated SQL text.",
    "query_escape_helper.php": "A recognized SQL escaping helper is evidence, but its effectiveness is not proven.",
    "query_misleading.php": "The variable name looks untrusted, but its value is a local constant.",
    "query_prepared.php": "Request data is bound as a parameter and is not concatenated into query text.",
    "attribute_flow.php": "GET data reaches a quoted HTML attribute output context.",
    "output_benign.php": "A request value is unused while only fixed HTML is emitted.",
    "output_unresolved.php": "The request value passes through an unsupported output helper.",
    "encoded_helper.php": "Request data reaches HTML output through a recognized encoder; effectiveness remains unresolved.",
    "static_misleading.php": "An output-like variable name holds only fixed markup.",
    "object_flow.php": "A request identifier reaches a database lookup without recognized authorization evidence.",
    "object_benign.php": "A search input is unrelated to a fixed query and is not an object identifier flow.",
    "object_unresolved.php": "The identifier is returned by an unsupported helper before the lookup.",
    "object_guard.php": "A principal comparison is observed but does not prove complete or effective object authorization.",
    "object_misleading.php": "An object-like variable name contains a fixed identifier rather than request data.",
    "url_flow.php": "A GET value reaches the supported file_get_contents URL-fetch sink.",
    "url_benign.php": "A request value is unrelated to a fixed URL fetch.",
    "url_unresolved.php": "A request URL reaches an unsupported object-method HTTP client call.",
    "url_format_check.php": "URL-format validation is observed, but host and destination safety are not established.",
    "url_misleading.php": "The URL variable is a fixed local literal, not request-controlled.",
    "command_flow.php": "A GET value reaches shell_exec through a supported assignment.",
    "command_benign.php": "The command variable contains a fixed literal and no request data.",
    "command_unresolved.php": "The command is built through unsupported helper behavior.",
    "command_escape_alias.php": "An aliased request argument reaches shell_exec through escapeshellarg; composition safety remains unresolved.",
    "command_misleading.php": "The command variable name looks dangerous, but it holds a fixed local string.",
    "path_flow.php": "A GET path reaches the supported file read sink.",
    "path_benign.php": "A request value is disconnected from the fixed file path being read.",
    "path_unresolved.php": "The request path passes through an unsupported path builder.",
    "path_basename.php": "An alias and basename transformation reach a file read, without proving root containment.",
    "path_misleading.php": "The path variable contains a fixed path rather than request data.",
    "upload_flow.php": "A $_FILES temporary path alias reaches move_uploaded_file.",
    "upload_benign.php": "A normal POST field and upload-like variable name do not create $_FILES evidence.",
    "upload_unresolved.php": "A whole $_FILES entry is passed to an unsupported handler with no recognized storage flow.",
    "upload_checks.php": "Extension, MIME, upload-error, and size checks are observed but are not proof of safety.",
    "upload_misleading.php": "An upload-like variable name contains a local string and never references $_FILES.",
}


class PHPAnalyzerBenchmarkTests(unittest.TestCase):
    """Measure report behavior only against this labeled synthetic fixture set."""

    def setUp(self):
        # Import inside the method so unittest does not rediscover and rerun
        # the entire PHP-flow test class as part of this focused benchmark.
        from tests.test_php_flow import PHPFlowTests

        self.harness = PHPFlowTests("runTest")
        self.harness.setUp()

    def tearDown(self):
        self.harness.tearDown()

    def test_labeled_php_analyzer_benchmark(self):
        fields = ("tp", "tn", "fp", "fn", "unresolved")
        counts = {
            category: {field: 0 for field in fields}
            for category in dict.fromkeys(case["category"] for case in CASES)
        }
        errors = []
        for case in CASES:
            fixture = FIXTURE_ROOT / case["file"]
            self.assertTrue(fixture.is_file(), f"missing synthetic fixture: {fixture}")
            if case["name"] not in CASE_RATIONALES:
                errors.append(f"{case['name']}: expected-result rationale is missing")
            report = self.harness.analyze_local_source(fixture)
            for fragment in case["evidence"]:
                if fragment not in report:
                    errors.append(f"{case['name']}: missing expected evidence {fragment!r}")
            for fragment in case.get("no_evidence", ()):
                if fragment in report:
                    errors.append(f"{case['name']}: unexpected evidence {fragment!r}")
            if "Vulnerability status: UNCONFIRMED" not in report:
                errors.append(f"{case['name']}: status was not UNCONFIRMED")

            if case["label"] == "positive":
                observed = all(fragment in report for fragment in case["evidence"])
                counts[case["category"]]["tp" if observed else "fn"] += 1
                if observed and "Severity: NEEDS_REVIEW" not in report:
                    errors.append(f"{case['name']}: positive pattern lacks conservative severity")
            elif case["label"] == "benign":
                observed = any(fragment in report for fragment in case.get("no_evidence", ()))
                counts[case["category"]]["fp" if observed else "tn"] += 1
            else:
                counts[case["category"]]["unresolved"] += 1
                if any(fragment in report for fragment in case.get("no_evidence", ())):
                    errors.append(f"{case['name']}: unresolved input was reported as a supported flow")

        print("Synthetic PHP benchmark only; unresolved cases are excluded from rate denominators:")
        for category, result in counts.items():
            positive_total = result["tp"] + result["fn"]
            benign_total = result["fp"] + result["tn"]
            false_positive_rate = result["fp"] / benign_total if benign_total else 0.0
            missed_case_rate = result["fn"] / positive_total if positive_total else 0.0
            print(
                f"  {category}: TP={result['tp']} TN={result['tn']} FP={result['fp']} "
                f"FN={result['fn']} unresolved={result['unresolved']} "
                f"FP rate={false_positive_rate:.0%} missed-pattern rate={missed_case_rate:.0%}"
            )
        self.assertEqual(errors, [], "\n".join(errors))
        for category, result in counts.items():
            self.assertEqual(result["fn"], 0, f"{category}: supported positive-pattern case was missed")
            self.assertEqual(result["fp"], 0, f"{category}: benign synthetic case produced a positive observation")


if __name__ == "__main__":
    unittest.main()
