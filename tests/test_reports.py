import ast
import contextlib
import hashlib
import io
import json
import re
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, quote_from_bytes, urlsplit, urlunsplit


class FindingReportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        tree = ast.parse(source_path.read_text())
        names = {
            "_build_findings_summary",
            "_escape_report_header_value",
            "_escape_report_user_field",
            "_safe_report_parameter_name",
            "_render_report_endpoint",
            "_render_report_target",
            "_report_target_filename_component",
            "_report_display_entries",
            "_safe_report_display_text",
            "_safe_report_output_text",
            "_split_saved_report_lines",
            "list_reports",
            "view_report",
            "save_report",
            "_build_review_queue",
            "_build_review_progress",
            "show_findings_summary",
            "show_review_queue",
            "show_review_progress",
            "_reviewable_report_names",
            "_save_review_note",
            "review_note_workflow",
            "_is_safe_review_note_filename",
            "_read_review_notes",
            "_sanitize_reviewer_text",
            "_normalize_validation_record",
            "_latest_validation_status",
            "review_notes_workflow",
            "validation_note_workflow",
            "_report_remediation",
            "_candidate_report_title_and_impact",
            "_normalize_structured_test_result",
            "_report_evidence_location",
            "_redact_potential_secrets",
            "record_finding",
            "record_candidate",
            "show_help",
            "hackerone_policy_review_checklist",
        }
        functions = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in names
        ]
        namespace = {
            "REPORTS_DIR": self.root / "reports",
            "_REPORT_DISPLAY_ALIASES": {},
            "Path": Path,
            "re": re,
            "hashlib": hashlib,
            "secrets": secrets,
            "quote_from_bytes": quote_from_bytes,
            "quote": quote,
            "urlsplit": urlsplit,
            "urlunsplit": urlunsplit,
            "datetime": datetime,
            "json": json,
            "check_scope": lambda target, announce=True: True,
            "_VALIDATION_STATUSES": {
                "OBSERVED", "UNVERIFIED", "VALIDATED", "NOT_REPRODUCIBLE", "FALSE_POSITIVE",
            },
            "_VALIDATION_DETAIL_FIELDS": (
                "endpoint", "category", "severity", "severity_justification", "preconditions",
                "reproduction_steps", "expected_behavior", "actual_behavior", "evidence",
                "impact", "limitations", "remediation",
            ),
            "_VALIDATION_TRANSITIONS": {
                "OBSERVED": {"OBSERVED", "UNVERIFIED", "VALIDATED", "NOT_REPRODUCIBLE", "FALSE_POSITIVE"},
                "UNVERIFIED": {"OBSERVED", "UNVERIFIED", "VALIDATED", "NOT_REPRODUCIBLE", "FALSE_POSITIVE"},
                "VALIDATED": {"UNVERIFIED"},
                "NOT_REPRODUCIBLE": {"UNVERIFIED"},
                "FALSE_POSITIVE": {"UNVERIFIED"},
            },
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
        self.record_finding = namespace["record_finding"]
        self.record_candidate = namespace["record_candidate"]
        self.build_summary = namespace["_build_findings_summary"]
        self.build_review_queue = namespace["_build_review_queue"]
        self.show_review_queue = namespace["show_review_queue"]
        self.reviewable_report_names = namespace["_reviewable_report_names"]
        self.save_review_note = namespace["_save_review_note"]
        self.read_review_notes = namespace["_read_review_notes"]
        self.build_review_progress = namespace["_build_review_progress"]
        self.show_review_progress = namespace["show_review_progress"]
        self.show_findings_summary = namespace["show_findings_summary"]
        self.namespace = namespace
        self.show_help = namespace["show_help"]
        self.save_report = namespace["save_report"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_report(self, name, text):
        reports = self.root / "reports"
        reports.mkdir(exist_ok=True)
        path = reports / name
        path.write_text(text)
        return path

    def report_alias(self, report_name):
        return next(
            alias
            for alias, name in self.namespace["_REPORT_DISPLAY_ALIASES"].items()
            if name == report_name
        )

    def validation_details(self, **overrides):
        details = {
            "endpoint": "http://127.0.0.1/bWAPP/demo.php?token=synthetic-secret",
            "category": "Output handling",
            "severity": "Low",
            "severity_justification": "Limited to the local demonstration page.",
            "preconditions": "Use the local synthetic fixture.",
            "reproduction_steps": "1. Open the local fixture.\n2. Submit the harmless value.",
            "expected_behavior": "The value is encoded as text.",
            "actual_behavior": "The value remains in an HTML attribute.",
            "evidence": (
                "Authorization: Bearer synthetic-bearer\n"
                "Cookie: session=synthetic-session\n"
                "X-API-Key: synthetic-api-secret\n"
                "Contact synthetic.user@example.test; observed only in the local fixture."
            ),
            "impact": "Potential client-side interpretation; no execution demonstrated.",
            "limitations": "Browser execution and real-world impact were not tested.",
            "remediation": "Apply context-appropriate output encoding.",
        }
        details.update(overrides)
        return details

    def test_empty_report_directory_has_read_only_empty_summary(self):
        report_dir = self.root / "reports"
        summary = self.build_summary(report_dir)

        self.assertIn("JARVIS FINDINGS SUMMARY", summary)
        self.assertIn("Reports read: 0", summary)
        self.assertIn("No saved report observations found.", summary)
        self.assertFalse(report_dir.exists())

    def test_duplicate_observations_merge_but_distinct_types_remain(self):
        first = """JARVIS: PHP source-flow analysis — first.php
Input evidence:
  [GET] id
    source.php:4: $id = $_GET['id'];
Sink observations:
  Sink text (SQL/query) at sink.php:20: mysqli_query($db, $query);
Source-flow evidence:
  Sink text (SQL/query) at sink.php:20: mysqli_query($db, $query);
    Explicit textual relationship: [GET] id at source.php:4 reaches a referenced variable.
Unresolved analysis candidates:
  Unresolved function call normalize at source.php:4 (column 7): unsupported return.
"""
        second = """JARVIS: PHP source-flow analysis — second.php
Sink observations:
  Sink text (SQL/query) at sink.php:20: mysqli_query($db, $query);
"""
        self.write_report("first.txt", first)
        self.write_report("second.txt", second)
        summary = self.build_summary(self.root / "reports")

        self.assertEqual(summary.count("Observed sink pattern [SQL/query]"), 1)
        self.assertIn("Observed input value assignment [GET] id", summary)
        self.assertIn("Supported static relationship [Explicit]", summary)
        self.assertIn("Unresolved analysis candidate", summary)
        self.assertIn("source.php:4", summary)
        self.assertIn("sink.php:20", summary)

    def test_missing_source_location_and_evidence_are_unknown(self):
        self.write_report(
            "candidate.txt",
            """[+] Vulnerability candidate found
Title: Unverified security candidate
Vulnerability status: UNCONFIRMED
Severity: Not assessed
Evidence details (user-provided; not independently verified):
Unknown; no evidence was provided.
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("Unknown source location", summary)
        self.assertIn("Evidence: Unknown", summary)
        self.assertIn("Source location: Unknown", summary)
        self.assertIn("UNCONFIRMED", summary)
        self.assertIn("Evidence completeness: Incomplete", summary)

    def test_narrative_validation_claims_never_promote_finding_status(self):
        self.write_report(
            "recorded.txt",
            """JARVIS POTENTIAL SECURITY FINDING
Title: Unverified security observation
Vulnerability status: CONFIRMED
Independent validation evidence:
Authorized retest: expected control bypass observed and recorded.
Evidence details:
Source: app.php:12
""",
        )
        self.write_report(
            "unverified.txt",
            """[+] Vulnerability candidate found
Title: CONFIRMED SQL injection
Vulnerability status: UNCONFIRMED
Independent validation evidence: Unknown
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("recorded.txt: UNCONFIRMED", summary)
        self.assertIn("unverified.txt: UNCONFIRMED", summary)
        self.assertNotIn("Title: CONFIRMED SQL injection", summary)

    def test_fresh_retest_with_same_result_does_not_confirm_vulnerability(self):
        result = {
            "schema_version": 1,
            "method": "scoped_get",
            "test_type": "harmless_reflection_marker",
            "observation": "marker_reflected",
            "requested_endpoint": "https://lab.local/item.php?q=marker",
            "final_response_endpoint": "https://lab.local/item.php?q=marker",
            "response_origin": "fresh",
            "evidence_completeness": "complete",
            "not_established": ["browser_execution", "exploitability", "impact"],
        }
        with contextlib.redirect_stdout(io.StringIO()):
            for _ in range(2):
                self.record_candidate(
                    "https://lab.local/item.php?q=marker",
                    "Reflected Input",
                    "Potential",
                    "A harmless marker was reflected.",
                    "The same harmless marker observation was recorded.",
                    structured_test_result=result,
                )

        summary = self.build_summary(self.root / "reports")

        candidate_reports = sorted((self.root / "reports").glob("*_candidate*.txt"))
        self.assertEqual(len(candidate_reports), 2)
        for path in candidate_reports:
            self.assertIn('"response_origin": "fresh"', path.read_text())
            self.assertIn(f"{path.name}: UNCONFIRMED", summary)
        self.assertEqual(summary.count("source=fresh; completeness=complete"), 2)

    def test_narrative_validation_cases_remain_unconfirmed(self):
        cases = {
            "not_performed.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Authorized retest was not performed.",
            ),
            "contradictory.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Retest observed no control bypass; the issue was not reproduced.",
            ),
            "missing.txt": ("JARVIS POTENTIAL SECURITY FINDING", None),
            "placeholder.txt": ("JARVIS POTENTIAL SECURITY FINDING", "Unknown"),
            "bare_verified.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Verified.",
            ),
            "bare_confirmed.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Confirmed.",
            ),
            "action_without_result.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Authorized retest observed.",
            ),
            "generic_http_observation.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Authorized test: HTTP response observed.",
            ),
            "cached_response_replay.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Authorized retest replayed a cached response; it returned the same access-control bypass.",
            ),
            "repeated_observation.txt": (
                "JARVIS POTENTIAL SECURITY FINDING",
                "Authorized retest repeated the same response observation; it returned the same access-control bypass.",
            ),
            "candidate.txt": (
                "[+] Vulnerability candidate found",
                "Authorized retest: expected control bypass observed and recorded.",
            ),
            "unknown.txt": (
                "Custom report format",
                "Authorized retest: expected control bypass observed and recorded.",
            ),
        }
        for name, (header, validation) in cases.items():
            validation_section = (
                f"Independent validation evidence:\n{validation}\n"
                if validation is not None else ""
            )
            self.write_report(
                name,
                f"{header}\nVulnerability status: CONFIRMED\n{validation_section}",
            )

        summary = self.build_summary(self.root / "reports")

        for name in cases:
            self.assertIn(f"{name}: UNCONFIRMED", summary)

    def test_candidate_structured_reflection_observation_is_reported_but_not_confirmed(self):
        result = {
            "schema_version": 1,
            "method": "scoped_get",
            "test_type": "harmless_reflection_marker",
            "observation": "marker_reflected",
            "requested_endpoint": "https://lab.local/item.php?q=JARVIS_TEST_12345",
            "final_response_endpoint": "https://lab.local/item.php?q=JARVIS_TEST_12345",
            "response_origin": "fresh",
            "evidence_completeness": "complete",
            "not_established": ["browser_execution", "exploitability", "impact"],
        }
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "https://lab.local/item.php?q=JARVIS_TEST_12345",
                "Reflected Input",
                "Potential High",
                "A harmless marker was reflected.",
                "Marker response observed.",
                observed_evidence="Harmless marker appeared in HTML text.",
                evidence_source="JARVIS active GET reflection check",
                evidence_endpoint="https://lab.local/item.php?q=JARVIS_TEST_12345",
                structured_test_result=result,
            )

        report_path = next((self.root / "reports").glob("*_candidate.txt"))
        report = report_path.read_text()
        self.assertIn("JARVIS STRUCTURED TEST RESULT BEGIN", report)
        self.assertIn('"response_origin": "fresh"', report)
        self.assertIn('"observation": "marker_reflected"', report)
        self.assertIn('"not_established": ["browser_execution", "exploitability", "impact"]', report)
        self.assertIn("%5BREDACTED%5D", report)
        self.assertNotIn("JARVIS_TEST_12345", report)
        self.assertIn("Vulnerability status: UNCONFIRMED", report)

        # Even an edited stored status cannot be promoted by the structured
        # observation: reflection is not type-specific proof of exploitability.
        report = report.replace(
            "Vulnerability status: UNCONFIRMED; no independent validation evidence is recorded.",
            "Vulnerability status: CONFIRMED",
            1,
        )
        report_path.write_text(report)
        summary = self.build_summary(self.root / "reports")
        self.assertIn(f"{report_path.name}: UNCONFIRMED", summary)
        self.assertIn(
            "Saved structured test records (report text; not independently authenticated):",
            summary,
        )
        self.assertIn("source=fresh; completeness=complete", summary)

    def test_cached_structured_observation_is_recorded_as_cached_and_unconfirmed(self):
        result = {
            "schema_version": 1,
            "method": "scoped_get",
            "test_type": "harmless_reflection_marker",
            "observation": "marker_reflected",
            "requested_endpoint": "https://lab.local/item.php?q=marker",
            "final_response_endpoint": "https://lab.local/item.php?q=marker",
            "response_origin": "cached",
            "evidence_completeness": "complete",
            "not_established": ["browser_execution", "exploitability", "impact"],
        }
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "https://lab.local/item.php?q=marker",
                "Reflected Input",
                "Potential",
                "Cached observation candidate.",
                "Marker appeared.",
                structured_test_result=result,
            )

        report = next((self.root / "reports").glob("*_candidate.txt")).read_text()
        self.assertIn('"response_origin": "cached"', report)
        summary = self.build_summary(self.root / "reports")
        self.assertIn("source=cached; completeness=complete", summary)
        self.assertIn("UNCONFIRMED", summary)

    def test_malformed_structured_test_result_is_ignored(self):
        result = {
            "schema_version": 1,
            "method": "scoped_get",
            "test_type": "harmless_reflection_marker",
            "observation": "marker_reflected",
            "requested_endpoint": "https://lab.local/item.php",
            "final_response_endpoint": "https://lab.local/item.php",
            "response_origin": "fresh",
            "evidence_completeness": "complete",
            "not_established": ["browser_execution", "exploitability", "impact"],
            "vulnerability_status": "CONFIRMED",
        }
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "https://lab.local/item.php",
                "Reflected Input",
                "Potential",
                "Malformed record candidate.",
                "Marker appeared.",
                structured_test_result=result,
            )

        report = next((self.root / "reports").glob("*_candidate.txt")).read_text()
        self.assertNotIn("JARVIS STRUCTURED TEST RESULT BEGIN", report)
        summary = self.build_summary(self.root / "reports")
        self.assertIn("UNCONFIRMED", summary)
        self.assertIn("None recorded.", summary)

    def test_heuristic_only_candidate_remains_unconfirmed_without_structured_result(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "https://lab.local/item.php?file=readme",
                "High-Risk Input",
                "",
                "A parameter-name heuristic selected an input for review.",
                "The name file was inventoried; behavior was not tested.",
            )

        report_path = next((self.root / "reports").glob("*_candidate.txt"))
        report = report_path.read_text()
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Severity: Not assessed", report)
        self.assertNotIn("JARVIS STRUCTURED TEST RESULT BEGIN", report)
        summary = self.build_summary(self.root / "reports")
        self.assertIn(f"{report_path.name}: UNCONFIRMED", summary)
        self.assertIn("None recorded.", summary)

    def test_missing_and_contradictory_structured_fields_are_ignored(self):
        base_result = {
            "schema_version": 1,
            "method": "scoped_get",
            "test_type": "harmless_reflection_marker",
            "observation": "marker_reflected",
            "requested_endpoint": "https://lab.local/item.php?q=marker",
            "final_response_endpoint": "https://lab.local/item.php?q=marker",
            "response_origin": "fresh",
            "evidence_completeness": "complete",
            "not_established": ["browser_execution", "exploitability", "impact"],
        }
        missing_endpoint = dict(base_result)
        del missing_endpoint["final_response_endpoint"]
        malformed_method = dict(base_result, method="unknown-method")
        contradictory_absence = dict(
            base_result,
            observation="marker_not_reflected",
            evidence_completeness="incomplete",
        )

        with contextlib.redirect_stdout(io.StringIO()):
            for result in (missing_endpoint, malformed_method, contradictory_absence):
                self.record_candidate(
                    "https://lab.local/item.php?q=marker",
                    "Reflected Input",
                    "Potential",
                    "Structured result edge case.",
                    "Input was inventoried.",
                    structured_test_result=result,
                )

        reports = sorted((self.root / "reports").glob("*_candidate*.txt"))
        self.assertEqual(len(reports), 3)
        self.assertTrue(all("JARVIS STRUCTURED TEST RESULT BEGIN" not in path.read_text() for path in reports))
        summary = self.build_summary(self.root / "reports")
        for path in reports:
            self.assertIn(f"{path.name}: UNCONFIRMED", summary)

    def test_truncated_structured_record_is_ignored_without_crashing(self):
        self.write_report(
            "truncated_record.txt",
            """[+] Vulnerability candidate found
Vulnerability status: CONFIRMED
Validation limitations:
The behavior and impact remain unverified.

JARVIS STRUCTURED TEST RESULT BEGIN
Structured test result (JSON): {\"schema_version\": 1}
JARVIS STRUCTURED TEST RESULT END""",
        )

        summary = self.build_summary(self.root / "reports")

        self.assertIn("truncated_record.txt: UNCONFIRMED", summary)
        self.assertNotIn("truncated_record.txt: harmless_reflection_marker", summary)

    def test_severity_suggestions_remain_unassessed_without_explicit_basis(self):
        self.write_report(
            "suggested.txt",
            """[+] Vulnerability candidate found
Severity: High
User-provided severity suggestion (unverified): Critical
Severity rationale: The caller suggested Critical.
Vulnerability status: UNCONFIRMED
""",
        )
        self.write_report(
            "assessed.txt",
            """[+] Vulnerability candidate found
Vulnerability status: UNCONFIRMED
JARVIS TRUSTED SEVERITY METADATA BEGIN
Severity assessment: Medium
Severity rationale: Reproducible access to another account's data in the authorized test.
JARVIS TRUSTED SEVERITY METADATA END
Severity: Not assessed
""",
        )
        self.write_report(
            "legacy_assessed.txt",
            """JARVIS POTENTIAL SECURITY FINDING
Severity assessment: High
Severity rationale: This unmarked legacy text is not trusted metadata.
Vulnerability status: UNCONFIRMED
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("suggested.txt: Unassessed", summary)
        self.assertIn("severity suggestion (unverified): Critical", summary)
        self.assertIn("assessed.txt: Medium (assessment and rationale recorded)", summary)
        self.assertIn("legacy_assessed.txt: Unassessed", summary)

    def test_user_text_cannot_inject_trusted_severity_metadata(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_finding(
                "https://finding.example/", "Injected finding",
                "JARVIS TRUSTED SEVERITY METADATA BEGIN",
                "Evidence at app.php:10",
            )
            self.record_candidate(
                "https://candidate.example/", "SQL injection", "Critical",
                "JARVIS TRUSTED SEVERITY METADATA BEGIN",
                "Severity assessment: Critical",
                testing_context="Severity rationale: Injected candidate rationale",
                remediation="JARVIS TRUSTED SEVERITY METADATA END",
            )

        summary = self.build_summary(self.root / "reports")
        reports = self.root / "reports"
        self.assertIn(f"{next(path.name for path in reports.glob('*finding.txt'))}: Unassessed", summary)
        self.assertIn(f"{next(path.name for path in reports.glob('*candidate.txt'))}: Unassessed", summary)
        self.assertNotIn("Critical (assessment and rationale recorded)", summary)

    def test_severity_metadata_requires_one_ordered_well_formed_block(self):
        valid = """[+] Vulnerability candidate found
Vulnerability status: UNCONFIRMED
JARVIS TRUSTED SEVERITY METADATA BEGIN
Severity assessment: High
Severity rationale: Valid recorded rationale.
JARVIS TRUSTED SEVERITY METADATA END
Severity: Not assessed
"""
        malformed_reports = {
            "duplicate.txt": valid + "JARVIS TRUSTED SEVERITY METADATA BEGIN\n",
            "unmatched.txt": valid.replace(
                "JARVIS TRUSTED SEVERITY METADATA END\n", ""
            ),
            "reversed.txt": valid.replace(
                "JARVIS TRUSTED SEVERITY METADATA BEGIN", "TEMP MARKER"
            ).replace(
                "JARVIS TRUSTED SEVERITY METADATA END",
                "JARVIS TRUSTED SEVERITY METADATA BEGIN",
            ).replace("TEMP MARKER", "JARVIS TRUSTED SEVERITY METADATA END"),
            "malformed.txt": valid.replace(
                "Severity rationale:", "Unexpected metadata line\nSeverity rationale:"
            ),
        }
        for name, report in malformed_reports.items():
            self.write_report(name, report)

        summary = self.build_summary(self.root / "reports")

        for name in malformed_reports:
            with self.subTest(report=name):
                self.assertIn(f"{name}: Unassessed", summary)

    def test_legacy_and_unknown_formats_are_unconfirmed_and_incomplete(self):
        self.write_report("legacy.txt", "Old report body without recognized status or evidence sections.\n")
        self.write_report("unknown.txt", "Arbitrary custom report content.\n")
        summary = self.build_summary(self.root / "reports")

        self.assertIn("legacy.txt: UNCONFIRMED", summary)
        self.assertIn("unknown.txt: UNCONFIRMED", summary)
        self.assertIn("Unrecognized report format", summary)
        self.assertIn("Unknown report content", summary)
        self.assertIn("Evidence completeness: Incomplete", summary)

    def test_legacy_php_flow_sections_extract_inputs_sinks_and_unverified_flow_claims(self):
        self.write_report(
            "legacy_flow.txt",
            """JARVIS: PHP source-flow analysis — catalog.php
Input evidence:
  [GET] title
    Line 18: if (isset($_GET['title']))
Source-flow evidence:
  - Input assignment
    Line 19: $title = $_GET['title'];
  - Input reaches function call
    Line 20: $value = wrap($title);
Query-flow evidence:
  - SELECT query construction
    Line 22: $sql = "SELECT * FROM catalog WHERE title = '" . $title;
  - Database query execution
    Line 24: $rows = mysqli_query($db, $sql);
Data-flow verification:
  [GET] title → $title
  SQL flow: Line 22: $sql = "SELECT * FROM catalog WHERE title = '" . $title;
  Output sink for $title: Line 26: echo $title;
XSS output flow:
  [GET] title → $title → escape_name() → echo
Review status:
  SOURCE FLOW DETECTED
  This analysis does not confirm a vulnerability.
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("legacy_flow.txt: PHP source-flow analysis: catalog.php", summary)
        self.assertIn("Observed request guard [GET] title", summary)
        self.assertIn("Observed input value assignment [GET] title", summary)
        self.assertIn("Reported source-flow step (unverified)", summary)
        self.assertIn("catalog.php:20", summary)
        self.assertIn("catalog.php:18", summary)
        self.assertIn("Observed query construction pattern", summary)
        self.assertIn("Observed sink pattern [SQL/database execution]", summary)
        self.assertIn("catalog.php:24", summary)
        self.assertIn("Observed sink pattern [output]", summary)
        self.assertIn("catalog.php:26", summary)
        self.assertIn("Legacy reported source-to-sink claim (unverified)", summary)
        self.assertIn("[GET] title → $title → escape_name() → echo", summary)
        self.assertIn("legacy_flow.txt: UNCONFIRMED", summary)
        self.assertNotIn("Supported static relationship", summary)

    def test_presence_flag_is_not_summarized_as_submitted_request_value(self):
        self.write_report(
            "old_presence.txt",
            """JARVIS: PHP source-flow analysis — form.php
Input evidence:
  [POST] entry_all
    Line 248: $entry_all = isset($_POST["entry_all"]) ? 1 : 0;
Unresolved analysis candidates:
  Unresolved assignment at form.php:248: $entry_all = isset($_POST["entry_all"]) ? 1 : 0; (expression semantics are unsupported).
Review status:
  INPUT DETECTED
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("Observed presence-check assignment [POST] entry_all", summary)
        self.assertIn("form.php:248", summary)
        self.assertIn("Unresolved analysis candidate", summary)
        self.assertIn("Presence-check limitation", summary)
        self.assertIn("does not establish that the submitted parameter value reaches a sink", summary)
        self.assertNotIn("Observed input value assignment [POST] entry_all", summary)
        self.assertNotIn("Observed input pattern [POST] entry_all", summary)
        self.assertNotIn("Supported static relationship", summary)

    def test_php_form_controls_are_not_promoted_to_request_sources(self):
        self.write_report(
            "form_control_flow.txt",
            """JARVIS: PHP source-flow analysis — stored.php
Form control observations:
  [textarea] name=entry at stored.php:4 (form control only; not evidence that PHP reads or uses this value).
Input evidence:
  No direct GET/POST/REQUEST inputs detected.
Source-flow evidence:
  No supported source-to-sink relationship established.
Local function analysis:
  Unsupported helper bodies are unresolved.
Database operation observations:
  Database write execution (INSERT) using $sql at stored.php:12.
Output branch observations:
  Output branch observation at stored.php:20: echo $row->entry;
Unresolved request-reference evidence:
  [POST] entry (expression value unresolved)
    stored.php:8: xss($_POST['entry'])
Review status:
  UNRESOLVED INPUT EVIDENCE
Vulnerability status: UNCONFIRMED
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("Unresolved request reference [POST] entry", summary)
        self.assertNotIn("Observed input pattern [POST] entry", summary)
        self.assertNotIn("Observed input value assignment [POST] entry", summary)
        self.assertIn("form_control_flow.txt: UNCONFIRMED", summary)

    def test_saved_php_include_edges_and_unsupported_statements_are_preserved(self):
        self.write_report(
            "stored_flow.txt",
            """JARVIS: PHP source-flow analysis — stored.php
Input evidence:
  No direct GET/POST/REQUEST inputs detected.
Included-file analysis:
  Include evidence: stored.php:19 -> database.php:1 (include; static path database.php)
  Unresolved conditional/nested include at stored.php:32: include("database.php");
  Unresolved assignment at stored.php:248: $flag = isset($_POST["flag"]) ? 1 : 0; (expression semantics are unsupported).
Review status:
  NO INPUT DETECTED
  Unsupported syntax and conditional flow remain unresolved.
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("Included-file relationship observation", summary)
        self.assertIn("stored.php:19 -> database.php:1", summary)
        self.assertIn("Unresolved analysis candidate", summary)
        self.assertIn("stored.php:32", summary)
        self.assertIn("stored.php:248", summary)
        self.assertIn("Saved analysis status: NO INPUT DETECTED", summary)
        self.assertIn("this is not a safety determination", summary)
        self.assertNotIn("Supported static relationship", summary)
        self.assertNotIn("Unknown report content: No recognized evidence", summary)

    def test_summary_preserves_incomplete_review_status_for_unresolved_include(self):
        self.write_report(
            "incomplete_include.txt",
            """JARVIS: PHP source-flow analysis — entry.php
Input evidence:
  No direct GET/POST/REQUEST inputs detected.
Included-file analysis:
  Unresolved out-of-root include at entry.php:2: ../outside.php
Vulnerability status: UNCONFIRMED
Review status:
  ANALYSIS INCOMPLETE — NO INPUT DETECTED
""",
        )

        summary = self.build_summary(self.root / "reports")

        self.assertIn(
            "Saved analysis status: ANALYSIS INCOMPLETE — NO INPUT DETECTED; "
            "this is not vulnerability confirmation.",
            summary,
        )
        self.assertIn("Unresolved analysis candidate", summary)
        self.assertIn("entry.php:2", summary)
        self.assertIn("incomplete_include.txt: UNCONFIRMED", summary)

    def test_candidate_placeholders_are_unknown_and_potential_severity_stays_unverified(self):
        self.write_report(
            "candidate.txt",
            """[+] Vulnerability candidate found
Type: Broken Access Control
Potential severity: High
Evidence: saved
Description:
Describe the issue
Evidence details:
Describe your evidence
Status: Requires manual verification
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("candidate.txt: Unassessed; user-provided severity suggestion (unverified): High", summary)
        self.assertIn("Recorded candidate evidence: Unknown; no evidence was recorded.", summary)
        self.assertNotIn("Recorded candidate evidence: Describe your evidence", summary)
        self.assertNotIn("Recorded candidate evidence: saved", summary)
        self.assertIn("Evidence: Unknown", summary)

    def test_saved_no_input_report_is_not_treated_as_safe_or_unrecognized(self):
        self.write_report(
            "no_input.txt",
            """JARVIS: PHP source-flow analysis — sample.php
Input evidence:
  No direct GET/POST/REQUEST inputs detected.
Review status:
  NO INPUT DETECTED
  Unsupported syntax and conditional flow remain unresolved.
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("Saved analysis reports no direct GET/POST/REQUEST input evidence", summary)
        self.assertIn("NO INPUT DETECTED", summary)
        self.assertIn("Unresolved analysis candidate", summary)
        self.assertIn("no_input.txt: UNCONFIRMED", summary)
        self.assertNotIn("no_input.txt: Safe", summary)
        self.assertNotIn("no_input.txt: Unrecognized report format", summary)

    def test_manual_review_priority_uses_evidence_completeness_not_severity(self):
        self.write_report(
            "high_evidence.txt",
            """JARVIS: PHP source-flow analysis — account.php
Input evidence:
  [POST] account
    account.php:8: $account = $_POST['account'];
Sink observations:
  Sink text (output) at account.php:21: echo render($account);
Unresolved analysis candidates:
  Unresolved function call render at account.php:21 (column 13): return relationship is unsupported.
Vulnerability status: UNCONFIRMED
""",
        )
        self.write_report(
            "medium_evidence.txt",
            """JARVIS: PHP source-flow analysis — profile.php
Input evidence:
  [GET] name
    profile.php:12: $name = $_GET['name'];
Potential severity: Critical
Vulnerability status: UNCONFIRMED
""",
        )
        self.write_report(
            "low_placeholder.txt",
            """[+] Vulnerability candidate found
Type: Unknown candidate
Evidence details:
Describe your evidence
Potential severity: High
""",
        )
        self.write_report(
            "low_missing_location.txt",
            """[+] Vulnerability candidate found
Type: Review request
Evidence details:
Observed behavior was described, but no source file or line was recorded.
""",
        )

        summary = self.build_summary(self.root / "reports")

        self.assertIn("high_evidence.txt: High —", summary)
        self.assertIn("Located request-value evidence and a located sink", summary)
        self.assertIn("medium_evidence.txt: Medium —", summary)
        self.assertIn("medium_evidence.txt: Unassessed; user-provided severity suggestion (unverified): Critical", summary)
        self.assertIn("low_placeholder.txt: Low — Only placeholder or missing evidence", summary)
        self.assertIn("low_missing_location.txt: Low —", summary)
        self.assertIn("lacks an identifiable request-value source or sink location", summary)
        self.assertIn("Priority guides review order only; it is not a vulnerability or severity rating.", summary)

    def test_web_and_aggregate_php_report_formats_are_recognized_conservatively(self):
        self.write_report(
            "web.txt",
            """JARVIS WEB INFORMATION REPORT
Page title   : Local training page
Security Headers:
[MISSING] Content-Security-Policy - Example guidance.
Note:
Missing security headers are observations and are not automatically confirmed vulnerabilities.
""",
        )
        self.write_report(
            "web_header_evidence.txt",
            """JARVIS WEB INFORMATION REPORT
Page title   : Local training page
Security Headers:
[PRESENT] Content-Security-Policy - Helps reduce content-injection risks.
  Observed value: default-src 'self'
[MISSING] X-Frame-Options - Helps reduce clickjacking risks.
Note:
Missing security headers are observations and are not automatically confirmed vulnerabilities.
""",
        )
        self.write_report(
            "review.txt",
            """JARVIS PHP REVIEW REPORT
Directory: /local/lab
PHP files found: 12
Training-page classification:
  SQL Injection: 3
  Cross-Site Scripting: 2
Manual review status:
  These classifications do NOT confirm vulnerabilities.
Recommended next step:
  Manually verify any candidate before reporting.
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("web.txt: Local training page", summary)
        self.assertIn("Observed web security-header pattern", summary)
        self.assertIn("web_header_evidence.txt: Local training page", summary)
        self.assertIn("Observed web security-header pattern: [MISSING] X-Frame-Options", summary)
        self.assertIn("review.txt: JARVIS PHP REVIEW REPORT", summary)
        self.assertIn("Training-page classification (not a finding)", summary)
        self.assertIn("SQL Injection: 3 pages", summary)
        self.assertIn("review.txt: Manually verify any candidate before reporting.", summary)
        self.assertIn("web.txt: UNCONFIRMED", summary)
        self.assertIn("web_header_evidence.txt: UNCONFIRMED", summary)
        self.assertIn("review.txt: Unassessed", summary)
        self.assertNotIn("review.txt: Unrecognized report format", summary)

    def test_legacy_audit_header_report_without_values_remains_readable_and_unconfirmed(self):
        self.write_report(
            "legacy_audit.txt",
            """JARVIS LEGACY AUDIT REPORT
Target: https://lab.example/
HTTP Status: 200
Security Header Observations:
  Content-Security-Policy: MISSING
  X-Frame-Options: PRESENT
Note: Header observations are not automatically confirmed vulnerabilities.
""",
        )

        summary = self.build_summary(self.root / "reports")

        self.assertIn("legacy_audit.txt: Web information report", summary)
        self.assertIn(
            "Observed web security-header pattern: Content-Security-Policy: MISSING",
            summary,
        )
        self.assertIn("legacy_audit.txt: UNCONFIRMED", summary)
        self.assertNotIn("legacy_audit.txt: Unrecognized report format", summary)

    def test_not_recorded_header_is_not_missing_or_confirmation_evidence(self):
        self.write_report(
            "header_not_recorded.txt",
            """JARVIS POTENTIAL SECURITY FINDING
Title: Header evidence unavailable
HTTP Status: 200
Security Header Observations:
  Content-Security-Policy: NOT RECORDED
Vulnerability status: CONFIRMED
Independent validation evidence:
NOT RECORDED
""",
        )

        summary = self.build_summary(self.root / "reports")

        self.assertIn("header_not_recorded.txt: UNCONFIRMED", summary)
        self.assertNotIn(
            "Observed web security-header pattern: Content-Security-Policy: NOT RECORDED",
            summary,
        )
        self.assertNotIn(
            "Observed web security-header pattern: Content-Security-Policy: MISSING",
            summary,
        )

    def test_legacy_finding_extracts_multiline_title_evidence_and_remediation(self):
        self.write_report(
            "old_finding.txt",
            """JARVIS POTENTIAL SECURITY FINDING
Title:
Input handling review

Description:
An input was flagged for manual review.

Evidence:
POST parameter 'account' was present in the saved observation.

Remediation:
Review the validation and authorization checks for this input.

Status:
NEEDS HUMAN REVIEW
""",
        )
        summary = self.build_summary(self.root / "reports")

        self.assertIn("old_finding.txt: Input handling review", summary)
        self.assertIn("User-provided finding evidence", summary)
        self.assertIn("POST parameter 'account' was present", summary)
        self.assertIn("old_finding.txt: Review the validation and authorization checks", summary)
        self.assertIn("old_finding.txt: UNCONFIRMED", summary)
        self.assertIn("old_finding.txt: Unassessed", summary)

    def test_summary_command_is_read_only_scoped_and_helpful(self):
        source = self.write_report(
            "simple.txt",
            """JARVIS: PHP source-flow analysis — sample.php
Sink observations:
  Sink text (output) at sample.php:8: echo $value;
""",
        )
        original = source.read_bytes()
        outside = self.root / "outside.txt"
        outside.write_text("OUTSIDE REPORT ROOT SECRET")
        try:
            (self.root / "reports" / "linked.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            pass

        summary = self.build_summary(self.root / "reports")
        self.assertIn("sample.php:8", summary)
        self.assertNotIn("OUTSIDE REPORT ROOT SECRET", summary)
        self.assertEqual(source.read_bytes(), original)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.show_help()
        self.assertIn("summary", output.getvalue())
        self.assertIn("review-queue", output.getvalue())
        self.assertIn("review-note", output.getvalue())

        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            input="review-queue\nexit\n",
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )
        self.assertIn("JARVIS REVIEW QUEUE", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^@[A-Za-z0-9_-]+$")
        self.assertNotIn("simple.txt", result.stdout)
        self.assertIn("sample.php:8", result.stdout)
        self.assertEqual(source.read_bytes(), original)

    def test_hackerone_policy_checklist_is_manual_and_covers_supplied_exclusions(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["hackerone_policy_review_checklist"]()
        rendered = output.getvalue()

        for required in (
            "exact asset, scheme, port, and path",
            "Confirm every proposed testing method is allowed",
            "Manually reproduce a security impact",
            "safe, repeatable steps",
            "current official program policy",
            "Claude Code permission-modal bypass remediation",
            "other users' accounts, private data, or causing disruption",
            "minimum evidence needed",
            "denial of service",
            "brute force",
            "social engineering",
            "Clickjacking requires a sensitive action",
            "missing cookie flags alone",
            "Generic TLS",
            "Model jailbreaks",
            "remain unverified until manually validated",
        ):
            self.assertIn(required, rendered)
        self.assertNotIn("CONFIRMED", rendered)

    def test_hackerone_scope_template_is_separate_and_not_authorizing(self):
        template = (
            Path(__file__).resolve().parents[1]
            / "templates"
            / "anthropic_scope.draft.txt"
        ).read_text()

        self.assertIn("NOT AUTHORIZED FOR LIVE TESTING", template)
        self.assertIn("not loaded by JARVIS", template)
        self.assertNotRegex(template, r"(?i)anthropic\.com")
        self.assertNotIn("ALLOW http", template)

        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            input="hackerone-review\nexit\n",
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )
        self.assertIn("Anthropic HackerOne Policy Review Checklist", result.stdout)
        self.assertIn("not current authorization", result.stdout)

    def test_legacy_report_filename_is_listed_as_safe_alias_and_alias_opens_file(self):
        filename = "http___user_pass_lab_token_legacy-secret\nforged.txt"
        report = self.write_report(filename, "Legacy report marker\nVulnerability status: UNCONFIRMED\n")
        original = report.read_bytes()

        listing = io.StringIO()
        with contextlib.redirect_stdout(listing):
            self.namespace["list_reports"]()

        listed = listing.getvalue()
        self.assertNotIn("legacy-secret", listed)
        self.assertNotIn("user_pass", listed)
        self.assertNotIn("forged", listed)
        aliases = [
            line.strip()[2:]
            for line in listed.splitlines()
            if line.strip().startswith("- @")
        ]
        self.assertEqual(len(aliases), 1)
        self.assertRegex(aliases[0], r"^@[A-Za-z0-9_-]+$")

        viewed = io.StringIO()
        with contextlib.redirect_stdout(viewed):
            self.namespace["view_report"](aliases[0])

        self.assertIn("Legacy report marker", viewed.getvalue())
        self.assertEqual(report.read_bytes(), original)

    def test_view_legacy_report_redacts_urls_and_escapes_terminal_controls(self):
        report = self.write_report(
            "legacy-content.txt",
            "Target: https://alice:pw@legacy.example/path?token=tok-secret&api_key=key-secret\n"
            "Old field:\r\nVulnerability status: CONFIRMED\x1b[2J\u2028tail\n",
        )
        original = report.read_bytes()

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["view_report"]("legacy-content.txt")

        displayed = output.getvalue()
        for secret in ("alice", "pw", "tok-secret", "key-secret"):
            self.assertNotIn(secret, displayed)
        self.assertNotIn("\r", displayed)
        self.assertNotIn("\x1b", displayed)
        self.assertNotIn("\u2028", displayed)
        self.assertIn(r"\r", displayed)
        self.assertIn(r"\x1b[2J", displayed)
        self.assertIn(r"\u2028", displayed)
        self.assertNotIn("\nVulnerability status: CONFIRMED", displayed)
        self.assertIn("  | Vulnerability status: CONFIRMED", displayed)
        self.assertIn("token=%5BREDACTED%5D", displayed)
        self.assertIn("api_key=%5BREDACTED%5D", displayed)
        self.assertEqual(report.read_bytes(), original)

    def test_report_aliases_are_unique_and_direct_filenames_remain_supported(self):
        first = self.write_report("legacy_token_first-secret.txt", "FIRST REPORT\n")
        second = self.write_report("legacy_token_second-secret.txt", "SECOND REPORT\n")
        numbered = self.write_report("@1.txt", "NUMBERED FILENAME REPORT\n")

        listing = io.StringIO()
        with contextlib.redirect_stdout(listing):
            self.namespace["list_reports"]()
        text = listing.getvalue()
        aliases = [
            line.strip()[2:]
            for line in text.splitlines()
            if line.strip().startswith("- @")
        ]
        self.assertEqual(len(aliases), 3)
        self.assertEqual(len(set(aliases)), 3)
        self.assertNotIn("first-secret", text)
        self.assertNotIn("second-secret", text)

        alias_output = io.StringIO()
        with contextlib.redirect_stdout(alias_output):
            for alias in aliases:
                self.namespace["view_report"](alias)
        self.assertIn("FIRST REPORT", alias_output.getvalue())
        self.assertIn("SECOND REPORT", alias_output.getvalue())
        self.assertIn("NUMBERED FILENAME REPORT", alias_output.getvalue())

        direct_output = io.StringIO()
        with contextlib.redirect_stdout(direct_output):
            self.namespace["view_report"](numbered.name)
            self.namespace["view_report"](first.name)
            self.namespace["view_report"](second.name)
        self.assertIn("NUMBERED FILENAME REPORT", direct_output.getvalue())
        self.assertIn("FIRST REPORT", direct_output.getvalue())
        self.assertIn("SECOND REPORT", direct_output.getvalue())

    def test_alias_hash_collisions_receive_distinct_selectable_aliases(self):
        self.write_report("collision-a.txt", "FIRST COLLISION REPORT\n")
        self.write_report("collision-b.txt", "SECOND COLLISION REPORT\n")

        with patch.object(self.namespace["secrets"], "token_urlsafe", return_value="duplicate"):
            listing = io.StringIO()
            with contextlib.redirect_stdout(listing):
                self.namespace["list_reports"]()
            aliases = [
                line.strip()[2:]
                for line in listing.getvalue().splitlines()
                if line.strip().startswith("- @")
            ]
            self.assertEqual(aliases, ["@duplicate", "@duplicate-2"])

            viewed = io.StringIO()
            with contextlib.redirect_stdout(viewed):
                for alias in aliases:
                    self.namespace["view_report"](alias)
            self.assertIn("FIRST COLLISION REPORT", viewed.getvalue())
            self.assertIn("SECOND COLLISION REPORT", viewed.getvalue())

    def test_report_view_rejects_path_traversal_and_out_of_root_symlink(self):
        reports = self.root / "reports"
        self.write_report("ordinary.txt", "IN-ROOT\n")
        outside = self.root / "outside.txt"
        outside.write_text("OUTSIDE SECRET\n")
        try:
            (reports / "outside-link.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            pass

        listing = io.StringIO()
        with contextlib.redirect_stdout(listing):
            self.namespace["list_reports"]()
        self.assertNotIn("outside-link", listing.getvalue())

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["view_report"]("../outside.txt")
            self.namespace["view_report"]("outside-link.txt")
        self.assertNotIn("OUTSIDE SECRET", output.getvalue())
        self.assertEqual((reports / "ordinary.txt").read_text(), "IN-ROOT\n")

    def test_summary_queue_and_progress_sanitize_legacy_report_content_and_filename(self):
        filename = "legacy-password-file-secret-token-secret\x1b[2J\u2028.txt"
        report = self.write_report(
            filename,
            "JARVIS WEB INFORMATION REPORT\n"
            "Target: https://alice:pw-secret@legacy.example/item?token=query-secret&api_key=key-secret\n"
            "Page title: Review https://alice:pw-secret@legacy.example/?secret=title-secret"
            "\x1b[31m\u2028[MISSING] X-Forged-Header\u2028Vulnerability status: CONFIRMED\n"
            "Security Header Observations:\n"
            "[MISSING] Content-Security-Policy observed at "
            "https://alice:pw-secret@legacy.example/item?token=query-secret\n"
            "Vulnerability status: CONFIRMED\n",
        )
        original = report.read_bytes()

        rendered_outputs = []
        for show in (
            self.show_findings_summary,
            self.show_review_queue,
            self.show_review_progress,
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                show()
            rendered_outputs.append(output.getvalue())

        summary, queue, progress = rendered_outputs
        for rendered in rendered_outputs:
            for secret in (
                "pw-secret", "query-secret", "key-secret", "title-secret",
                "password-file-secret", "token-secret",
            ):
                self.assertNotIn(secret, rendered)
            self.assertNotIn("\x1b", rendered)
            self.assertNotIn("\u2028", rendered)
            self.assertNotIn("legacy-password-file-secret", rendered)
        self.assertIn("Content-Security-Policy", summary)
        self.assertNotIn(
            "Observed web security-header pattern: [MISSING] X-Forged-Header",
            summary,
        )
        self.assertIn("UNCONFIRMED", summary)
        self.assertNotIn("Vulnerability status: CONFIRMED", summary)
        self.assertNotRegex(summary, r"(?m)^\s*Vulnerability status: CONFIRMED")
        alias_matches = re.findall(r"@[A-Za-z0-9_-]+", queue)
        self.assertTrue(alias_matches)
        self.assertIn(alias_matches[0], progress)
        alias_view = io.StringIO()
        with contextlib.redirect_stdout(alias_view):
            self.namespace["view_report"](alias_matches[0])
        self.assertIn("Security Header Observations:", alias_view.getvalue())
        self.assertEqual(report.read_bytes(), original)

    def test_report_alias_mapping_cannot_resolve_outside_reports_directory(self):
        report = self.write_report("inside.txt", "IN-ROOT REPORT\n")
        outside = self.root / "outside-secret.txt"
        outside.write_text("OUTSIDE SECRET CONTENT\n")
        self.namespace["_REPORT_DISPLAY_ALIASES"]["@outside"] = outside.name

        listing = io.StringIO()
        with contextlib.redirect_stdout(listing):
            self.namespace["list_reports"]()
        viewed = io.StringIO()
        with contextlib.redirect_stdout(viewed):
            self.namespace["view_report"]("@outside")

        self.assertNotIn("@outside", listing.getvalue())
        self.assertNotIn("OUTSIDE SECRET CONTENT", viewed.getvalue())
        self.assertIn("IN-ROOT REPORT", report.read_text())

    def test_review_queue_sorts_by_evidence_priority_without_promoting_status(self):
        self.write_report(
            "low.txt",
            """JARVIS: PHP source-flow analysis — quiet.php
Unresolved analysis candidates:
  Unresolved include at quiet.php:8: dynamic path.
Vulnerability status: UNCONFIRMED
""",
        )
        self.write_report(
            "high.txt",
            """JARVIS: PHP source-flow analysis — account.php
Input evidence:
  [POST] account
    account.php:8: $account = $_POST['account'];
Sink observations:
  Sink text (output) at account.php:21: echo render($account);
Unresolved analysis candidates:
  Unresolved function call render at account.php:21: return is unsupported.
Vulnerability status: UNCONFIRMED
""",
        )
        self.write_report(
            "medium.txt",
            """JARVIS: PHP source-flow analysis — profile.php
Input evidence:
  [GET] name
    profile.php:12: $name = $_GET['name'];
Vulnerability status: UNCONFIRMED
""",
        )

        queue = self.build_review_queue(self.root / "reports")

        self.assertLess(queue.index(self.report_alias("high.txt")), queue.index(self.report_alias("medium.txt")))
        self.assertLess(queue.index(self.report_alias("medium.txt")), queue.index(self.report_alias("low.txt")))
        self.assertIn("account.php:8", queue)
        self.assertIn("account.php:21", queue)
        self.assertIn("Unresolved function call render", queue)
        self.assertIn("Priority reflects evidence completeness and is not a severity", queue)
        self.assertIn("Vulnerability status: UNCONFIRMED", queue)

    def test_review_queue_preserves_incomplete_status_and_unresolved_include(self):
        self.write_report(
            "incomplete_include.txt",
            """JARVIS: PHP source-flow analysis — entry.php
Included-file analysis:
  Unresolved out-of-root include at entry.php:2: ../outside.php
Vulnerability status: UNCONFIRMED
Review status:
  ANALYSIS INCOMPLETE — NO INPUT DETECTED
""",
        )

        queue = self.build_review_queue(self.root / "reports")

        self.assertIn("ANALYSIS INCOMPLETE — NO INPUT DETECTED", queue)
        self.assertIn("Unresolved out-of-root include", queue)
        self.assertIn("entry.php:2", queue)
        self.assertIn("Vulnerability status: UNCONFIRMED", queue)

    def test_review_progress_counts_incomplete_report_only_after_valid_note(self):
        self.write_report(
            "incomplete_review.txt",
            """JARVIS: PHP source-flow analysis — account.php
Input evidence:
  [POST] account
    account.php:8: $account = $_POST['account'];
Sink observations:
  Sink text (output) at account.php:21: echo render($account);
Unresolved analysis candidates:
  Unresolved include at account.php:2: ../outside.php is outside the permitted root.
Vulnerability status: UNCONFIRMED
Review status:
  ANALYSIS INCOMPLETE — NO INPUT DETECTED
""",
        )

        progress_without_note = self.build_review_progress(self.root / "reports")

        self.assertIn("Reports with at least one valid review note: 0", progress_without_note)
        self.assertIn("Reports without review notes: 1", progress_without_note)
        self.assertIn("High: 1", progress_without_note)
        self.assertIn("Needs more evidence: 0", progress_without_note)

        self.save_review_note(
            self.root / "reports",
            "incomplete_review.txt",
            "Needs more evidence",
            "Reviewed unresolved include",
            "The external file remains unanalyzed",
        )
        progress_with_note = self.build_review_progress(self.root / "reports")

        self.assertIn("Reports with at least one valid review note: 1", progress_with_note)
        self.assertIn("Reports without review notes: 0", progress_with_note)
        self.assertIn("High: 0", progress_with_note)
        self.assertIn("Needs more evidence: 1", progress_with_note)

    def test_review_queue_clarifies_reviewed_reports_are_in_priority_counts(self):
        report = self.write_report(
            "reviewed_low.txt",
            "JARVIS: PHP source-flow analysis — quiet.php\n"
            "Unresolved analysis candidates:\n"
            "  Unresolved include at quiet.php:8: dynamic path.\n"
            "Vulnerability status: UNCONFIRMED\n",
        )
        self.save_review_note(
            self.root / "reports",
            report.name,
            "Needs more evidence",
            "Reviewed evidence",
            "Runtime behavior remains unknown",
        )

        queue = self.build_review_queue(self.root / "reports")
        progress = self.build_review_progress(self.root / "reports")

        self.assertIn(
            "Priority counts include all saved reports, including reports with review notes; "
            "review-progress counts only outstanding reports.",
            queue,
        )
        self.assertIn(self.report_alias("reviewed_low.txt"), queue)
        self.assertIn("Reports with at least one valid review note: 1", progress)
        self.assertIn("Reports without review notes: 0", progress)
        self.assertIn("Low: 0", progress)

    def test_review_queue_handles_missing_evidence_fields_gracefully(self):
        self.write_report(
            "sparse.txt",
            """[+] Vulnerability candidate found
Type: Unknown candidate
Evidence details:
Unknown; no evidence was provided.
""",
        )
        queue = self.build_review_queue(self.root / "reports")

        self.assertIn(self.report_alias("sparse.txt"), queue)
        self.assertIn("Priority: Low", queue)
        self.assertIn("Source locations: Unknown", queue)
        self.assertIn("Sink locations: Unknown", queue)
        self.assertIn("Unknown; no unresolved question was recorded", queue)
        self.assertIn("Evidence completeness", queue)
        self.assertIn("Verify the originating input and relevant sink", queue)
        self.assertIn("Vulnerability status: UNCONFIRMED", queue)

    def test_review_queue_empty_and_missing_directories_are_read_only(self):
        missing_dir = self.root / "missing-reports"
        queue = self.build_review_queue(missing_dir)
        self.assertIn("JARVIS REVIEW QUEUE", queue)
        self.assertIn("No saved reports available for review.", queue)
        self.assertFalse(missing_dir.exists())

        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.show_review_queue()
        self.assertIn("No saved reports available for review.", output.getvalue())

    def test_review_views_exclude_all_symlinks_and_keep_counts_consistent(self):
        ordinary = self.write_report("ordinary.txt", "Vulnerability status: UNCONFIRMED\n")
        reports = self.root / "reports"
        outside = self.root / "outside.txt"
        outside.write_text("outside report data\n")
        (reports / "inside-link.txt").symlink_to(ordinary)
        (reports / "outside-link.txt").symlink_to(outside)
        (reports / "broken-link.txt").symlink_to(reports / "missing.txt")

        queue = self.build_review_queue(reports)
        progress = self.build_review_progress(reports)

        self.assertEqual(self.reviewable_report_names(reports), ["ordinary.txt"])
        self.assertIn("Saved reports read: 1", queue)
        self.assertIn(self.report_alias("ordinary.txt"), queue)
        self.assertNotIn("inside-link.txt", queue)
        self.assertNotIn("outside-link.txt", queue)
        self.assertNotIn("broken-link.txt", queue)
        self.assertIn("Saved reports: 1", progress)
        self.assertNotIn("inside-link.txt", progress)
        self.assertNotIn("outside-link.txt", progress)
        self.assertNotIn("broken-link.txt", progress)
        self.assertEqual(ordinary.read_text(), "Vulnerability status: UNCONFIRMED\n")
        self.assertEqual(outside.read_text(), "outside report data\n")

    def test_review_note_persists_timestamped_reviewer_record_without_changing_report(self):
        report = self.write_report(
            "manual.txt",
            "Vulnerability status: UNCONFIRMED\nAutomated evidence: original\n",
        )
        original = report.read_bytes()

        note = self.save_review_note(
            self.root / "reports",
            "1",
            "Verified in authorized lab",
            "Reproduced only in the isolated local lab with the recorded request.",
            "Production behavior and impact remain untested.",
        )

        notes_path = self.root / "reports" / "review_notes" / "notes.jsonl"
        lines = notes_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        saved = json.loads(lines[0])
        self.assertEqual(saved, note)
        self.assertEqual(saved["report_filename"], "manual.txt")
        parsed_timestamp = datetime.fromisoformat(saved["reviewed_at"])
        self.assertIsNotNone(parsed_timestamp.tzinfo)
        self.assertIsNotNone(parsed_timestamp.utcoffset())
        self.assertEqual(saved["reviewer_conclusion"], "Verified in authorized lab")
        self.assertIn("not independently verified by JARVIS", saved["conclusion_attribution"])
        self.assertIn("isolated local lab", saved["supporting_evidence"])
        self.assertIn("remain untested", saved["remaining_uncertainties"])
        self.assertEqual(report.read_bytes(), original)
        self.assertIn("Vulnerability status: UNCONFIRMED", report.read_text())

        self.save_review_note(
            self.root / "reports", "manual.txt", "Needs more evidence", "Evidence two", "Unknown"
        )
        self.assertEqual(len(notes_path.read_text(encoding="utf-8").splitlines()), 2)
        self.assertEqual(report.read_bytes(), original)
        summary = self.build_summary(self.root / "reports")
        self.assertIn("UNVERIFIED: 1", summary)
        self.assertIn("VALIDATED: 0", summary)

    def test_structured_validation_record_is_redacted_and_does_not_rewrite_report(self):
        report = self.write_report(
            "manual.txt",
            "JARVIS POTENTIAL SECURITY FINDING\nVulnerability status: UNCONFIRMED\n",
        )
        original_report = report.read_bytes()
        details = self.validation_details()
        with contextlib.redirect_stdout(io.StringIO()):
            note = self.save_review_note(
                self.root / "reports",
                "manual.txt",
                "Verified in authorized lab",
                details["evidence"],
                details["limitations"],
                validation_status="VALIDATED",
                validation_details=details,
            )

        self.assertEqual(note["validation_status"], "VALIDATED")
        self.assertEqual(
            note["validation_details"]["endpoint"],
            "http://127.0.0.1/bWAPP/demo.php?token=%5BREDACTED%5D",
        )
        for secret in (
            "synthetic-secret", "synthetic-bearer", "synthetic-session",
            "synthetic-api-secret", "synthetic.user@example.test",
        ):
            self.assertNotIn(secret, json.dumps(note))
        self.assertIn("[REDACTED]", note["validation_details"]["evidence"])
        parsed, malformed, error = self.read_review_notes(self.root / "reports")
        self.assertIsNone(error)
        self.assertEqual(malformed, 0)
        self.assertEqual(parsed[0]["validation_status"], "VALIDATED")

        summary = self.build_summary(self.root / "reports")
        self.assertIn("VALIDATED: 1", summary)
        self.assertIn("UNVERIFIED: 0", summary)
        self.assertIn("reviewer-reported, not authenticated by JARVIS", summary)
        self.assertIn("manual.txt: UNCONFIRMED", summary)
        self.assertEqual(report.read_bytes(), original_report)

    def test_reviewer_text_redacts_sensitive_colon_and_equals_assignments(self):
        sanitize = self.namespace["_sanitize_reviewer_text"]

        result = sanitize(
            "Cookie=secret_value\nAuthorization: Bearer another_secret\n"
            "ordinary text remains"
        )

        self.assertNotIn("secret_value", result)
        self.assertNotIn("another_secret", result)
        self.assertIn("Cookie: [REDACTED]", result)
        self.assertIn("Authorization: [REDACTED]", result)
        self.assertIn("ordinary text remains", result)

    def test_validated_status_rejects_incomplete_or_nonreproducible_records(self):
        self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        base = self.validation_details()
        invalid_details = [
            {**base, "evidence": "Unknown"},
            {**base, "reproduction_steps": "1. Open the fixture."},
            {**base, "actual_behavior": base["expected_behavior"]},
            {**base, "severity_justification": "Not provided"},
        ]
        for details in invalid_details:
            with self.subTest(details=details):
                with self.assertRaises(ValueError):
                    self.save_review_note(
                        self.root / "reports", "manual.txt",
                        "Verified in authorized lab", details["evidence"], details["limitations"],
                        validation_status="VALIDATED", validation_details=details,
                    )
        self.assertFalse((self.root / "reports" / "review_notes" / "notes.jsonl").exists())

    def test_validation_note_cli_records_manual_status_and_summary_without_network(self):
        report = self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        details = self.validation_details()
        details["reproduction_steps"] = "1. Open the local fixture; 2. Submit the harmless value."
        details["evidence"] = (
            "Authorization: Bearer synthetic-bearer; Cookie: session=synthetic-session; "
            "X-API-Key: synthetic-api-secret; Contact synthetic.user@example.test"
        )
        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        commands = ["validation-note", "1", "VALIDATED"]
        commands.extend(details[field] for field in self.namespace["_VALIDATION_DETAIL_FIELDS"])
        commands.extend(["summary", "review-notes", "manual.txt", "exit", "exit"])
        result = subprocess.run(
            [sys.executable, str(script)],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )
        self.assertIn("Reviewer validation record appended", result.stdout)
        self.assertIn("VALIDATED: 1", result.stdout)
        self.assertIn("Report status:", result.stdout)
        self.assertIn("UNCONFIRMED", result.stdout)
        self.assertNotIn("Vulnerability status: CONFIRMED", result.stdout)
        self.assertIn("Manual validation status (reviewer-reported; not authenticated by JARVIS): VALIDATED", result.stdout)
        self.assertNotIn("synthetic-bearer", result.stdout)
        self.assertNotIn("synthetic-session", result.stdout)
        self.assertNotIn("synthetic-api-secret", result.stdout)
        self.assertNotIn("synthetic.user@example.test", result.stdout)
        self.assertIn("Vulnerability status: UNCONFIRMED", report.read_text())
        self.assertTrue((self.root / "reports" / "review_notes" / "notes.jsonl").is_file())

    def test_validation_status_transitions_and_summary_counts_are_conservative(self):
        report = self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        details = self.validation_details()
        self.save_review_note(
            self.root / "reports", "manual.txt", "Verified in authorized lab",
            details["evidence"], details["limitations"],
            validation_status="VALIDATED", validation_details=details,
        )
        with self.assertRaisesRegex(ValueError, "Invalid validation status transition"):
            self.save_review_note(
                self.root / "reports", "manual.txt", "Needs more evidence",
                "New result", "More testing needed", validation_status="FALSE_POSITIVE",
                validation_details=self.validation_details(
                    actual_behavior="The control behaves as expected.",
                    evidence="The harmless fixture response was encoded.",
                ),
            )

        self.save_review_note(
            self.root / "reports", "manual.txt", "Needs more evidence",
            "Assessment reopened", "A separate reproduction is required.",
            validation_status="UNVERIFIED", validation_details=self.validation_details(),
        )
        false_positive = self.validation_details(
            actual_behavior="The value is consistently encoded in the fixture.",
            evidence="The apparent marker is inert text after parsing.",
            limitations="Only the local fixture was inspected.",
        )
        self.save_review_note(
            self.root / "reports", "manual.txt", "Needs more evidence",
            false_positive["evidence"], false_positive["limitations"],
            validation_status="FALSE_POSITIVE", validation_details=false_positive,
        )
        summary = self.build_summary(self.root / "reports")
        self.assertIn("VALIDATED: 0", summary)
        self.assertIn("UNVERIFIED: 0", summary)
        self.assertIn("FALSE_POSITIVE: 1", summary)
        self.assertIn("manual.txt: UNCONFIRMED", summary)
        self.assertIn("Vulnerability status: UNCONFIRMED", report.read_text())

        self.write_report("not-reproduced.txt", "Vulnerability status: UNCONFIRMED\n")
        not_reproduced = self.validation_details(
            actual_behavior="The observed behavior did not recur on the second local run.",
            evidence="Two documented attempts produced the expected encoded result.",
            limitations="Only the documented local fixture was retested.",
        )
        self.save_review_note(
            self.root / "reports", "not-reproduced.txt", "Not reproduced",
            not_reproduced["evidence"], not_reproduced["limitations"],
            validation_status="NOT_REPRODUCIBLE", validation_details=not_reproduced,
        )
        self.write_report("observed.txt", "Vulnerability status: UNCONFIRMED\n")
        observed = self.validation_details(
            actual_behavior="An unusual but non-security-relevant response was observed.",
            evidence="The local fixture returned its static demonstration page.",
        )
        self.save_review_note(
            self.root / "reports", "observed.txt", "Needs more evidence",
            observed["evidence"], observed["limitations"],
            validation_status="OBSERVED", validation_details=observed,
        )
        self.write_report("unverified.txt", "Vulnerability status: UNCONFIRMED\n")
        summary = self.build_summary(self.root / "reports")
        self.assertIn("NOT_REPRODUCIBLE: 1", summary)
        self.assertIn("OBSERVED: 1", summary)
        self.assertIn("UNVERIFIED: 1", summary)

    def test_malformed_structured_validation_note_is_skipped_conservatively(self):
        self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        notes_path = self.root / "reports" / "review_notes" / "notes.jsonl"
        notes_path.parent.mkdir(parents=True)
        malformed = {
            "report_filename": "manual.txt",
            "reviewed_at": "2026-10-12T12:00:00-04:00",
            "reviewer_conclusion": "Verified in authorized lab",
            "conclusion_attribution": "Reviewer-provided; not independently verified by JARVIS",
            "supporting_evidence": "A claim without a complete validation record.",
            "remaining_uncertainties": "Unknown",
            "validation_status": "VALIDATED",
            "validation_details": {"endpoint": "http://127.0.0.1/bWAPP/"},
        }
        notes_path.write_text(json.dumps(malformed) + "\n", encoding="utf-8")
        notes, skipped, error = self.read_review_notes(self.root / "reports")
        self.assertIsNone(error)
        self.assertEqual(notes, [])
        self.assertEqual(skipped, 1)
        summary = self.build_summary(self.root / "reports")
        self.assertIn("VALIDATED: 0", summary)
        self.assertIn("UNVERIFIED: 1", summary)
        self.assertIn("Malformed review-note records skipped: 1", summary)

    def test_review_note_rejects_invalid_selections_conclusions_and_blank_fields(self):
        self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        notes_path = self.root / "reports" / "review_notes" / "notes.jsonl"
        with self.assertRaisesRegex(ValueError, "path components"):
            self.save_review_note(
                self.root / "reports", "../manual.txt", "Not reproduced", "Evidence", "Unknown"
            )
        with self.assertRaisesRegex(ValueError, "not found"):
            self.save_review_note(
                self.root / "reports", "missing.txt", "Not reproduced", "Evidence", "Unknown"
            )
        with self.assertRaisesRegex(ValueError, "out of range"):
            self.save_review_note(
                self.root / "reports", "2", "Not reproduced", "Evidence", "Unknown"
            )
        (self.root / "reports" / "review_notes").mkdir()
        (self.root / "reports" / "review_notes" / "hidden.txt").write_text("sidecar")
        self.assertEqual(self.reviewable_report_names(self.root / "reports"), ["manual.txt"])

        invalid_notes = [
            ("Unexpected conclusion", "Evidence", "Unknown"),
            ("Needs more evidence ", "Evidence", "Unknown"),
            ("Not reproduced", "  ", "Unknown"),
            ("Not reproduced", "Evidence", "\t"),
        ]
        for conclusion, evidence, uncertainties in invalid_notes:
            with self.subTest(conclusion=conclusion, evidence=evidence, uncertainties=uncertainties):
                with self.assertRaises(ValueError):
                    self.save_review_note(
                        self.root / "reports", "manual.txt", conclusion, evidence, uncertainties
                    )
        self.assertFalse(notes_path.exists())

    def test_review_note_storage_error_preserves_existing_sidecar_data(self):
        self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        note_directory = self.root / "reports" / "review_notes" / "notes.jsonl"
        note_directory.mkdir(parents=True)
        sentinel = note_directory / "existing-note.txt"
        sentinel.write_text("prior note data")

        with self.assertRaises(OSError):
            self.save_review_note(
                self.root / "reports", "manual.txt", "Not reproduced", "Evidence", "Unknown"
            )
        self.assertEqual(sentinel.read_text(), "prior note data")

    def test_review_note_cli_selects_filename_and_writes_separate_note(self):
        report = self.write_report("cli.txt", "Vulnerability status: UNCONFIRMED\n")
        original = report.read_bytes()
        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            input=(
                "review-note\ncli.txt\nNot reproduced\n"
                "Local reproduction did not occur with this input.\n"
                "Only the checked path was considered.\nexit\n"
            ),
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )
        self.assertIn("Reviewer conclusion options:", result.stdout)
        self.assertIn("Reviewer note appended", result.stdout)
        notes_path = self.root / "reports" / "review_notes" / "notes.jsonl"
        saved = json.loads(notes_path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(saved["report_filename"], "cli.txt")
        self.assertEqual(saved["reviewer_conclusion"], "Not reproduced")
        self.assertEqual(report.read_bytes(), original)
        self.assertIn("Vulnerability status: UNCONFIRMED", report.read_text())

    def test_review_note_cli_reports_invalid_selection_and_continues(self):
        report = self.write_report("cli.txt", "Vulnerability status: UNCONFIRMED\n")
        original = report.read_bytes()
        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            input="review-note\n../cli.txt\n1\nEvidence\nUnknown\nreports\nexit\n",
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )
        self.assertIn("Review note was not saved", result.stdout)
        self.assertIn("path components", result.stdout)
        self.assertIn("JARVIS: Available reports:", result.stdout)
        self.assertFalse((self.root / "reports" / "review_notes" / "notes.jsonl").exists())
        self.assertEqual(report.read_bytes(), original)

    def test_review_note_cli_handles_early_input_eof_without_crashing(self):
        self.write_report("cli.txt", "Vulnerability status: UNCONFIRMED\n")
        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            input="review-note\n",
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )
        self.assertIn("Review note input ended early; no note was saved.", result.stdout)
        self.assertIn("Input closed; exiting.", result.stdout)
        self.assertFalse((self.root / "reports" / "review_notes" / "notes.jsonl").exists())

    def test_review_notes_lists_and_inspects_saved_note_read_only(self):
        report = self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        original = report.read_bytes()
        self.save_review_note(
            self.root / "reports",
            "manual.txt",
            "Needs more evidence",
            "Presence-only flag at sample.php:248; no value flow was established.",
            "Whether a submitted value reaches a sink remains unknown.",
        )
        notes_before = (self.root / "reports" / "review_notes" / "notes.jsonl").read_bytes()
        script = Path(__file__).resolve().parents[1] / "jarvis.py"

        result = subprocess.run(
            [sys.executable, str(script)],
            input="review-notes\nmanual.txt\nexit\n",
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )

        self.assertIn("JARVIS REVIEW NOTES (READ ONLY)", result.stdout)
        self.assertIn("manual.txt", result.stdout)
        self.assertIn("Reviewer-provided conclusion (not independently verified by JARVIS): Needs more evidence", result.stdout)
        self.assertNotIn("ORPHANED", result.stdout)
        self.assertIn("Evidence summary: Presence-only flag", result.stdout)
        self.assertIn("Supporting evidence: Presence-only flag at sample.php:248", result.stdout)
        self.assertIn("Remaining uncertainties: Whether a submitted value reaches a sink", result.stdout)
        self.assertIn("Automated report content and vulnerability status were not read or changed.", result.stdout)
        self.assertEqual(report.read_bytes(), original)
        self.assertIn("Vulnerability status: UNCONFIRMED", report.read_text())
        self.assertEqual((self.root / "reports" / "review_notes" / "notes.jsonl").read_bytes(), notes_before)

    def test_review_notes_marks_missing_report_as_orphaned_without_changing_note(self):
        reports_dir = self.root / "reports"
        notes_path = reports_dir / "review_notes" / "notes.jsonl"
        notes_path.parent.mkdir(parents=True)
        note = {
            "report_filename": "removed.txt",
            "reviewed_at": "2026-10-12T12:00:00-04:00",
            "reviewer_conclusion": "Needs more evidence",
            "conclusion_attribution": "Reviewer-provided; not independently verified by JARVIS",
            "supporting_evidence": "A source location was recorded before the report was removed.",
            "remaining_uncertainties": "The referenced report is unavailable.",
        }
        notes_path.write_text(json.dumps(note) + "\n", encoding="utf-8")
        notes_before = notes_path.read_bytes()

        with patch("builtins.input", return_value="removed.txt"):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.namespace["review_notes_workflow"](reports_dir)

        display = output.getvalue()
        self.assertIn("removed.txt", display)
        self.assertIn("ORPHANED: referenced report is missing", display)
        self.assertIn(
            "Reviewer-provided conclusion (not independently verified by JARVIS): Needs more evidence",
            display,
        )
        self.assertIn("Report availability: ORPHANED; referenced report is missing.", display)
        self.assertIn("Supporting evidence: A source location was recorded", display)
        self.assertEqual(notes_path.read_bytes(), notes_before)

    def test_review_notes_empty_or_missing_storage_is_handled(self):
        missing_root = self.root / "missing-reports"
        notes, malformed, error = self.read_review_notes(missing_root)
        self.assertEqual((notes, malformed, error), ([], 0, None))

        report_root = self.root / "reports"
        report_root.mkdir()
        notes, malformed, error = self.read_review_notes(report_root)
        self.assertEqual((notes, malformed, error), ([], 0, None))
        notes_path = report_root / "review_notes" / "notes.jsonl"
        notes_path.parent.mkdir()
        notes_path.write_text("", encoding="utf-8")
        notes, malformed, error = self.read_review_notes(report_root)
        self.assertEqual((notes, malformed, error), ([], 0, None))

    def test_review_notes_skips_malformed_jsonl_records(self):
        self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        notes_path = self.root / "reports" / "review_notes" / "notes.jsonl"
        notes_path.parent.mkdir()
        valid_note = {
            "report_filename": "manual.txt",
            "reviewed_at": "2026-10-12T12:00:00-04:00",
            "reviewer_conclusion": "Not reproduced",
            "conclusion_attribution": "Reviewer-provided; not independently verified by JARVIS",
            "supporting_evidence": "A local attempt did not reproduce the observation.",
            "remaining_uncertainties": "Other configurations were not tested.",
        }
        notes_path.write_text(
            "{broken json\n"
            + json.dumps({**valid_note, "report_filename": "../outside.txt"}) + "\n"
            + json.dumps(valid_note) + "\n",
            encoding="utf-8",
        )

        notes, malformed, error = self.read_review_notes(self.root / "reports")
        self.assertIsNone(error)
        self.assertEqual(malformed, 2)
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["report_filename"], "manual.txt")

        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        result = subprocess.run(
            [sys.executable, str(script)],
            input="review-notes\n\nexit\n",
            text=True,
            capture_output=True,
            cwd=self.root,
            check=True,
        )
        self.assertIn("Skipped 2 malformed review-note record(s)", result.stdout)
        self.assertIn("manual.txt", result.stdout)

    def test_review_notes_rejects_unknown_and_path_like_filenames(self):
        self.write_report("manual.txt", "Vulnerability status: UNCONFIRMED\n")
        self.save_review_note(
            self.root / "reports", "manual.txt", "Not reproduced", "Evidence", "Unknown"
        )
        script = Path(__file__).resolve().parents[1] / "jarvis.py"

        unknown = subprocess.run(
            [sys.executable, str(script)], input="review-notes\nmissing.txt\nexit\n",
            text=True, capture_output=True, cwd=self.root, check=True,
        )
        self.assertIn("No reviewer notes found for missing.txt", unknown.stdout)
        traversal = subprocess.run(
            [sys.executable, str(script)], input="review-notes\n../outside.txt\nexit\n",
            text=True, capture_output=True, cwd=self.root, check=True,
        )
        self.assertIn("Invalid report filename", traversal.stdout)
        self.assertNotIn("outside.txt |", traversal.stdout)

    def test_review_progress_counts_priorities_conclusions_and_integrity(self):
        high_report = """JARVIS: PHP source-flow analysis — high.php
Input evidence:
  [GET] id
    high.php:8: $id = $_GET['id'];
Sink observations:
  Sink text (output) at high.php:20: echo $id;
Unresolved analysis candidates:
  Unresolved output handling at high.php:20: review context.
Vulnerability status: UNCONFIRMED
"""
        medium_report = """JARVIS: PHP source-flow analysis — medium.php
Input evidence:
  [POST] name
    medium.php:12: $name = $_POST['name'];
Vulnerability status: UNCONFIRMED
"""
        low_report = """JARVIS: PHP source-flow analysis — low.php
Input evidence:
  [POST] flag
    low.php:18: $flag = isset($_POST['flag']) ? 1 : 0;
Unresolved analysis candidates:
  Unresolved assignment at low.php:18: presence-only value.
Vulnerability status: UNCONFIRMED
"""
        reports = {
            "a_high_open.txt": high_report,
            "b_high_reviewed.txt": high_report,
            "c_medium_reviewed.txt": medium_report,
            "d_low_open.txt": low_report,
            "e_unknown_open.txt": "legacy format with no priority marker\n",
        }
        report_paths = {name: self.write_report(name, body) for name, body in reports.items()}
        self.save_review_note(
            self.root / "reports", "b_high_reviewed.txt", "Needs more evidence", "High review evidence", "Impact remains unknown"
        )
        notes_path = self.root / "reports" / "review_notes" / "notes.jsonl"
        first_line = notes_path.read_text(encoding="utf-8").splitlines()[0]
        with notes_path.open("a", encoding="utf-8") as notes_file:
            notes_file.write(first_line + "\n")  # exact duplicate
        self.save_review_note(
            self.root / "reports", "b_high_reviewed.txt", "Not reproduced", "Second review attempt", "Other configurations remain untested"
        )
        self.save_review_note(
            self.root / "reports", "c_medium_reviewed.txt", "Verified in authorized lab", "Reviewer reproduced in isolated lab", "Production impact remains unknown"
        )
        unique_orphan = json.loads(first_line)
        unique_orphan["report_filename"] = "deleted_report.txt"
        with notes_path.open("a", encoding="utf-8") as notes_file:
            notes_file.write(json.dumps(unique_orphan) + "\n")
            notes_file.write("{malformed json\n")

        original_report_bytes = {name: path.read_bytes() for name, path in report_paths.items()}
        original_notes_bytes = notes_path.read_bytes()
        original_summary_parser = self.namespace["_build_findings_summary"]

        def without_unknown_priority(reports_dir, only_report=None):
            if only_report == "e_unknown_open.txt":
                return "No parseable priority recorded."
            return original_summary_parser(reports_dir, only_report=only_report)

        self.namespace["_build_findings_summary"] = without_unknown_priority
        try:
            progress = self.build_review_progress(self.root / "reports")
        finally:
            self.namespace["_build_findings_summary"] = original_summary_parser

        self.assertIn("Saved reports: 5", progress)
        self.assertIn("Reports with at least one valid review note: 2", progress)
        self.assertIn("Reports without review notes: 3", progress)
        self.assertIn("High: 1", progress)
        self.assertIn("Medium: 0", progress)
        self.assertIn("Low: 1", progress)
        self.assertIn("Unknown: 1", progress)
        self.assertIn("Needs more evidence: 1", progress)
        self.assertIn("Not reproduced: 1", progress)
        self.assertIn("Verified in authorized lab: 1", progress)
        self.assertIn("Malformed JSONL records skipped: 1", progress)
        self.assertIn("Exact duplicate note records ignored: 1", progress)
        self.assertIn("Orphaned valid notes (report no longer present): 1", progress)
        self.assertIn("Reviewer conclusions are reviewer-provided notes, not automated vulnerability statuses.", progress)
        self.assertLess(
            progress.index(f"High: {self.report_alias('a_high_open.txt')}"),
            progress.index(f"Low: {self.report_alias('d_low_open.txt')}"),
        )
        self.assertLess(
            progress.index(f"Low: {self.report_alias('d_low_open.txt')}"),
            progress.index(f"Unknown: {self.report_alias('e_unknown_open.txt')}"),
        )
        self.assertEqual({name: path.read_bytes() for name, path in report_paths.items()}, original_report_bytes)
        self.assertEqual(notes_path.read_bytes(), original_notes_bytes)
        self.assertTrue(all("Vulnerability status: UNCONFIRMED" in path.read_text() for path in report_paths.values() if path.name != "e_unknown_open.txt"))

    def test_review_progress_empty_or_missing_storage_counts_all_reports_unreviewed(self):
        empty_progress = self.build_review_progress(self.root / "no-reports")
        self.assertIn("Saved reports: 0", empty_progress)
        self.assertIn("Reports with at least one valid review note: 0", empty_progress)
        self.assertIn("Reports without review notes: 0", empty_progress)
        self.assertIn("High: 0", empty_progress)

        self.write_report("unreviewed.txt", "unrecognized legacy content\n")
        original_parser = self.namespace["_build_findings_summary"]
        self.namespace["_build_findings_summary"] = lambda reports_dir, only_report=None: "No priority marker"
        try:
            progress = self.build_review_progress(self.root / "reports")
        finally:
            self.namespace["_build_findings_summary"] = original_parser
        self.assertIn("Saved reports: 1", progress)
        self.assertIn("Reports with at least one valid review note: 0", progress)
        self.assertIn("Reports without review notes: 1", progress)
        self.assertIn("Unknown: 1", progress)
        self.assertIn(f"Unknown: {self.report_alias('unreviewed.txt')}", progress)

    def test_review_progress_cli_is_read_only_and_available_in_help(self):
        report = self.write_report("tracker.txt", "Vulnerability status: UNCONFIRMED\n")
        original = report.read_bytes()
        self.save_review_note(
            self.root / "reports", "tracker.txt", "Needs more evidence", "Reviewer observation", "Further validation pending"
        )
        notes_path = self.root / "reports" / "review_notes" / "notes.jsonl"
        original_notes = notes_path.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as help_output:
            self.show_help()
        self.assertIn("review-progress", help_output.getvalue())

        script = Path(__file__).resolve().parents[1] / "jarvis.py"
        result = subprocess.run(
            [sys.executable, str(script)], input="review-progress\nexit\n",
            text=True, capture_output=True, cwd=self.root, check=True,
        )
        self.assertIn("JARVIS REVIEW PROGRESS", result.stdout)
        self.assertIn("Saved reports: 1", result.stdout)
        self.assertEqual(report.read_bytes(), original)
        self.assertEqual(notes_path.read_bytes(), original_notes)
        self.assertIn("Vulnerability status: UNCONFIRMED", report.read_text())

    def test_user_finding_is_unverified_and_includes_required_context(self):
        evidence = "Source: sample.php:17: echo $value"
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_finding(
                "lab.local",
                "Output encoding review",
                "Review output handling",
                evidence,
                testing_context="Local fixture review only",
            )
        report_path = self.root / "reports" / "lab.local_output_encoding_review_finding.txt"
        report = report_path.read_text()

        self.assertIn("JARVIS POTENTIAL SECURITY FINDING", report)
        self.assertIn("Target: lab.local", report)
        self.assertIn("User-provided title (unverified): Output encoding review", report)
        self.assertIn("Observation confidence:\nNot independently assessed.", report)
        self.assertIn(
            "Vulnerability status:\nUNCONFIRMED; JARVIS has not independently validated",
            report,
        )
        self.assertIn("Severity:\nNot assessed", report)
        self.assertIn("sample.php:17", report)
        self.assertIn("Local fixture review only", report)
        self.assertIn("Remediation:", report)
        self.assertIn("Evidence and confidence limitations:", report)
        self.assertIn("JARVIS has not independently validated", report)

    def test_remediation_follows_finding_type_before_incidental_description_terms(self):
        remediation = self.namespace["_report_remediation"]

        reflected = remediation(
            "Reflected XSS",
            "The output expression includes text associated with an SQL query.",
        )
        self.assertIn("context-appropriate output encoding", reflected)
        self.assertNotIn("parameterized queries", reflected)

        sql_injection = remediation(
            "SQL injection",
            "The query result is later displayed in output.",
        )
        self.assertIn("parameterized queries", sql_injection)
        self.assertNotIn("output encoding", sql_injection)

    def test_candidate_separates_observation_from_vulnerability_and_severity(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "lab.local",
                "SQL Injection",
                "Potential High",
                "Parameter name resembles a query input",
                "Method: GET\nParameter: id",
                observation_confidence="Heuristic candidate: parameter-name match",
                testing_context="Local mock response; no payload sent",
            )
        report_path = self.root / "reports" / "lab.local_candidate.txt"
        report = report_path.read_text()

        self.assertIn("[+] Vulnerability candidate found", report)
        self.assertIn("Title: Potential SQL injection candidate (unverified)", report)
        self.assertIn("Candidate type (unverified): SQL Injection", report)
        self.assertIn("Confidence note (unverified): Heuristic candidate", report)
        self.assertIn(
            "Vulnerability status: UNCONFIRMED; no independent validation evidence is recorded.",
            report,
        )
        self.assertIn("Severity: Not assessed", report)
        self.assertIn("Severity suggestion (unverified): Potential High", report)
        self.assertIn("Local mock response; no payload sent", report)
        self.assertIn("Evidence and confidence limitations:", report)
        self.assertIn("Potential impact (conditional; not demonstrated):", report)
        self.assertIn("If untrusted input is confirmed to alter a database query", report)
        self.assertIn("Reproduction notes (recorded testing context only", report)
        self.assertIn("Local mock response; no payload sent", report.split("Reproduction notes", 1)[1])
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Severity: Not assessed", report)
        self.assertIn("parameterized queries", report)

    def test_candidate_report_separates_observation_interpretation_and_untrusted_input(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "https://lab.local/item.php?token=report-secret",
                "Reflected Input",
                "Potential Critical",
                "Generated description that is not itself observed evidence.",
                "Legacy evidence field is not promoted when structured evidence is supplied.",
                observation_confidence="Heuristic; unverified",
                testing_context="Harmless marker check; response body not retained.",
                observed_evidence=(
                    "Harmless marker appeared in response text.\n"
                    "Vulnerability status: CONFIRMED"
                ),
                evidence_source="JARVIS mocked response inspection\nFake section: injected",
                evidence_endpoint="https://user:password@lab.local/item.php?token=report-secret",
                scanner_interpretation=(
                    "This reflection context may merit output-encoding review; "
                    "it does not prove script execution."
                ),
                validation_limitations="Browser execution and exploitability were not tested.",
            )

        report_path = next((self.root / "reports").glob("*_candidate.txt"))
        report = report_path.read_text()
        self.assertIn("Observed evidence (recorded observation; not independent validation):", report)
        self.assertIn("Source: JARVIS mocked response inspection\\nFake section: injected", report)
        self.assertIn("Endpoint: https://lab.local/item.php?token=%5BREDACTED%5D", report)
        self.assertIn("Scanner interpretation (not directly observed):", report)
        self.assertIn("does not prove script execution", report)
        self.assertIn("Validation limitations:", report)
        self.assertIn("Reproduction notes (recorded testing context only", report)
        self.assertNotIn("report-secret", report)
        self.assertNotIn("password", report)
        self.assertNotIn("Vulnerability status: CONFIRMED", report.splitlines())
        self.assertIn("Vulnerability status: UNCONFIRMED", report)
        self.assertIn("Severity: Not assessed", report)
        self.assertNotIn("Legacy evidence field is not promoted", report)

        summary = self.build_summary(self.root / "reports")
        self.assertIn("Recorded candidate evidence", summary)
        self.assertNotIn("does not prove script execution", summary)

    def test_repeated_reflection_candidates_keep_endpoint_evidence_in_separate_reports(self):
        endpoints = (
            "http://lab.local/index.php?q=one",
            "http://lab.local/item.php?q=two",
        )
        with contextlib.redirect_stdout(io.StringIO()):
            for endpoint in endpoints:
                self.record_candidate(
                    "lab.local",
                    "Reflected Input",
                    "Potential",
                    "A harmless reflection marker appeared in response text",
                    f"Marker: JARVIS_TEST_12345\nTest URL: {endpoint}\nHTTP status: 200",
                    observation_confidence="Confirmed observation: marker appeared in response text",
                    testing_context="Harmless marker only; no exploit payload sent",
                )

        report_paths = sorted((self.root / "reports").glob("lab.local_candidate*.txt"))
        self.assertEqual(
            [path.name for path in report_paths],
            ["lab.local_candidate.txt", "lab.local_candidate_2.txt"],
        )
        for path, endpoint in zip(report_paths, endpoints):
            report = path.read_text()
            rendered_endpoint = self.namespace["_render_report_endpoint"](endpoint)
            self.assertIn(f"Test URL: {rendered_endpoint}", report)
            self.assertNotIn(endpoint.rsplit("=", 1)[-1], report)
            self.assertIn("Vulnerability status: UNCONFIRMED", report)
            self.assertEqual(report.count("JARVIS TRUSTED SEVERITY METADATA BEGIN"), 1)
            self.assertEqual(report.count("JARVIS TRUSTED SEVERITY METADATA END"), 1)

        summary = self.build_summary(self.root / "reports")
        for path in report_paths:
            self.assertIn(f"{path.name}: UNCONFIRMED", summary)
            self.assertIn(f"{path.name}: Unassessed", summary)

    def test_record_candidate_preserves_existing_legacy_candidate_report(self):
        legacy_text = """[+] Vulnerability candidate found
Type: Reflected Input
Target: lab.local
Vulnerability status: UNCONFIRMED
Severity: Not assessed
Evidence: recorded below; not independently verified
"""
        legacy_path = self.write_report("lab.local_candidate.txt", legacy_text)

        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "lab.local",
                "Reflected Input",
                "Potential",
                "A harmless marker appeared in response text",
                "Marker: JARVIS_TEST_12345\nTest URL: http://lab.local/item.php?q=two",
                observation_confidence="Confirmed observation: marker appeared in response text",
                testing_context="Harmless marker only; no exploit payload sent",
            )

        numbered_path = self.root / "reports" / "lab.local_candidate_2.txt"
        self.assertEqual(legacy_path.read_text(), legacy_text)
        self.assertTrue(numbered_path.is_file())
        summary = self.build_summary(self.root / "reports")
        self.assertIn("lab.local_candidate.txt: UNCONFIRMED", summary)
        self.assertIn("lab.local_candidate.txt: Unassessed", summary)
        self.assertIn("lab.local_candidate_2.txt: UNCONFIRMED", summary)
        self.assertIn("lab.local_candidate_2.txt: Unassessed", summary)

    def test_secret_values_are_redacted_in_finding_candidate_generic_report_and_logs(self):
        secret = "synthetic_report_secret_74"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.record_finding(
                "lab.local", "Secret handling", f"api_token='{secret}'",
                f"Evidence: API_TOKEN = '{secret}'",
            )
            self.record_candidate(
                "lab.local", "Secret exposure", "Critical",
                f"password='{secret}'", f"Observed api_key='{secret}'",
            )
            self.save_report(
                "lab.local/manual",
                [f"Authorization: Bearer {secret}", "ordinary message value"],
            )

        report_text = "\n".join(
            path.read_text() for path in (self.root / "reports").glob("*.txt")
        )
        self.assertNotIn(secret, report_text)
        self.assertNotIn(secret, output.getvalue())
        self.assertIn("[REDACTED]", report_text)
        self.assertIn("ordinary message value", report_text)

    def test_report_and_candidate_paths_redact_query_secrets_and_remain_distinct(self):
        targets = (
            "https://authorized.example/bWAPP/item.php?token=first-secret&id=1",
            "https://authorized.example/bWAPP/item.php?token=second-secret&id=1",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            for target in targets:
                self.save_report(target, ["Target: safe"])

        report_files = sorted((self.root / "reports").glob("*.txt"))
        self.assertEqual(len(report_files), 2)
        self.assertEqual(len({path.name for path in report_files}), 2)
        printed = output.getvalue()
        for secret in ("first-secret", "second-secret"):
            self.assertNotIn(secret, printed)
            self.assertFalse(any(secret in path.name for path in report_files))

        self.root.joinpath("reports").mkdir(exist_ok=True)
        candidate_output = io.StringIO()
        with contextlib.redirect_stdout(candidate_output):
            for index, target in enumerate(targets):
                self.record_candidate(
                    target, "Reflected Input", "Potential", "Marker observed",
                    f"Test URL: {target}",
                    testing_context=f"Mocked retest {index}",
                )
        candidate_files = sorted((self.root / "reports").glob("*_candidate*.txt"))
        self.assertEqual(len(candidate_files), 2)
        self.assertEqual(len({path.name for path in candidate_files}), 2)
        for path in candidate_files:
            text = path.read_text()
            self.assertNotIn("first-secret", text)
            self.assertNotIn("second-secret", text)
            self.assertIn("token=%5BREDACTED%5D", text)
            self.assertIn("Vulnerability status: UNCONFIRMED", text)
        for secret in ("first-secret", "second-secret"):
            self.assertNotIn(secret, candidate_output.getvalue())
            self.assertFalse(any(secret in path.name for path in candidate_files))

        finding_output = io.StringIO()
        with contextlib.redirect_stdout(finding_output):
            self.record_finding(
                targets[0],
                "Review https://authorized.example/path?password=title-secret",
                "URL handling requires review",
                "Evidence is user provided",
            )
        finding_files = list((self.root / "reports").glob("*_finding.txt"))
        self.assertEqual(len(finding_files), 1)
        self.assertNotIn("title-secret", finding_files[0].name)
        self.assertNotIn("first-secret", finding_files[0].name)
        self.assertNotIn("title-secret", finding_output.getvalue())
        self.assertNotIn("first-secret", finding_files[0].read_text())

    def test_confirmed_reflection_observation_does_not_confirm_vulnerability(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "lab.local",
                "Reflected Input",
                "Potential",
                "A harmless marker appeared in response text",
                "Marker: TEST\nTest URL: http://lab.local/page\n"
                "Reflection context: script element; static context only",
                observation_confidence="Confirmed observation: marker appeared in response text",
                testing_context="Harmless marker only; no exploit payload sent",
            )
        report = (self.root / "reports" / "lab.local_candidate.txt").read_text()

        self.assertIn("Confidence note (unverified): Confirmed observation", report)
        self.assertIn(
            "Vulnerability status: UNCONFIRMED; no independent validation evidence is recorded.",
            report,
        )
        self.assertIn("Severity: Not assessed", report)
        self.assertIn("context-appropriate output encoding", report)
        self.assertIn("Title: Potential reflected-input candidate (unverified)", report)
        self.assertIn("Potential impact (conditional; not demonstrated):", report)
        self.assertIn("Browser execution and impact were not tested.", report)
        self.assertIn("Reproduction notes (recorded testing context only", report)
        self.assertIn("Reflection context: script element; static context only", report)

    def test_overstated_user_metadata_is_never_presented_as_jarvis_conclusion(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_candidate(
                "lab.local",
                "CONFIRMED XSS",
                "Critical",
                "The user asserts exploitability",
                "",
                observation_confidence="Confirmed vulnerability; certain",
                testing_context="",
            )
        report = (self.root / "reports" / "lab.local_candidate.txt").read_text()

        self.assertIn("Title: Unverified security candidate", report)
        self.assertIn("Candidate type (unverified): CONFIRMED XSS", report)
        self.assertIn(
            "Confidence note (unverified): Confirmed vulnerability; certain",
            report,
        )
        self.assertIn("Severity: Not assessed", report)
        self.assertIn("Potential impact is unknown until the behavior", report)
        self.assertIn("Severity suggestion (unverified): Critical", report)
        self.assertIn(
            "Vulnerability status: UNCONFIRMED; no independent validation evidence is recorded.",
            report,
        )
        self.assertIn(
            "Observed evidence:\nUnknown; no source-tagged direct observation was provided.",
            report,
        )
        self.assertIn(
            "Unverified information (caller-provided; not independently verified):\nUnknown; no evidence was provided.",
            report,
        )
        self.assertIn("Testing context:\nUnknown; no testing context was provided.", report)

    def test_missing_finding_evidence_and_context_are_explicitly_unknown(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.record_finding(
                "lab.local",
                "Confirmed SQL injection",
                "Potential issue",
                "",
                observation_confidence="Confirmed vulnerability",
                testing_context="",
            )
        report = (
            self.root / "reports" / "lab.local_confirmed_sql_injection_finding.txt"
        ).read_text()

        self.assertIn("Title:\nUnverified security observation", report)
        self.assertIn(
            "User-provided title (unverified): Confirmed SQL injection", report
        )
        self.assertIn("Evidence location:\nUnknown; no source file and line were provided.", report)
        self.assertIn(
            "Evidence details (user-provided; not independently verified):\nUnknown; no evidence was provided.",
            report,
        )
        self.assertIn("Testing context:\nUnknown; no testing context was provided.", report)
        self.assertIn(
            "Vulnerability status:\nUNCONFIRMED; JARVIS has not independently validated",
            report,
        )


if __name__ == "__main__":
    unittest.main()
