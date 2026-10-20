import ast
import contextlib
import hashlib
import ipaddress
import io
import re
import tempfile
import unittest
from datetime import datetime
from html import unescape
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, quote_from_bytes, unquote, urljoin, urlparse, urlsplit, urlunsplit

import requests


class FakeResponse:
    def __init__(self, url="https://authorized.example/", text="", headers=None):
        self.url = url
        self.text = text
        self.status_code = 200
        self.headers = {} if headers is None else headers
        self.is_redirect = False
        self.closed = False

    def close(self):
        self.closed = True


class FakeSession:
    max_redirects = 30

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class ActiveAuditControlTests(unittest.TestCase):
    def setUp(self):
        self.source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        tree = ast.parse(self.source_path.read_text())
        names = {
            "scoped_get", "check_reflection", "_parse_audit_options",
            "_escape_report_header_value",
            "_safe_report_parameter_name", "_render_report_endpoint",
            "_render_report_target", "_report_target_filename_component",
            "_escape_report_user_field",
            "_render_discovered_get_parameter",
            "check_security_headers", "get_page_title", "audit_target", "get_info",
            "discover_links", "discover_parameters",
            "_extract_html_forms", "discover_forms", "_summarize_form", "_html_attributes",
            "_form_control_inventory",
            "identify_review_areas", "identify_high_risk_parameters",
            "crawl_local_pages",
            "_get_audit_page_data",
            "_build_findings_summary",
        }
        functions = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in names
        ]
        self.candidates = []
        self.saved_reports = []
        self.scope_checks = []
        self.session = None
        self.namespace = {
            "Path": Path,
            "re": re,
            "requests": requests,
            "datetime": datetime,
            "urljoin": urljoin,
            "quote": quote,
            "quote_from_bytes": quote_from_bytes,
            "hashlib": hashlib,
            "ipaddress": ipaddress,
            "unquote": unquote,
            "unescape": unescape,
            "urlparse": urlparse,
            "urlsplit": urlsplit,
            "urlunsplit": urlunsplit,
            "SimpleNamespace": SimpleNamespace,
            "DEFAULT_AUDIT_REQUEST_BUDGET": 25,
            "MAX_AUDIT_REQUEST_BUDGET": 100,
            "_ACTIVE_AUDIT_REQUEST_BUDGET": None,
            "check_scope": lambda target, **kwargs: self.scope_checks.append(target) or True,
            "get_url": lambda target: target,
            "crawl_local_pages": lambda url, **kwargs: [],
            "audit_local_pages": lambda pages, *args, **kwargs: None,
            "inventory_local_forms": lambda pages, *args, **kwargs: [],
            "discover_links": lambda response: [],
            "discover_forms": lambda response: [],
            "identify_high_risk_parameters": lambda parameters: [],
            "identify_review_areas": lambda parameters: [],
            "record_candidate": lambda *args, **kwargs: self.candidates.append((args, kwargs)),
            "record_finding": lambda *args, **kwargs: None,
            "save_report": lambda target, report: self.saved_reports.append((target, report)),
            "REPORTS_DIR": Path("reports"),
        }
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                str(self.source_path),
                "exec",
            ),
            self.namespace,
        )

    def set_responses(self, *responses):
        self.session = FakeSession(responses)
        self.namespace["session"] = self.session

    def run_audit(self, *args, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["audit_target"](*args, **kwargs)
        return output.getvalue()

    def test_default_audit_is_passive_and_records_skipped_active_checks(self):
        self.set_responses(FakeResponse(url="https://authorized.example/?q=old&keep=yes"))

        output = self.run_audit("https://authorized.example/")

        self.assertEqual(len(self.session.calls), 1)
        self.assertNotIn("params", self.session.calls[0][1])
        self.assertIn("Active Reflection Checks: skipped", output)
        self.assertIn(
            "explicit --active opt-in required",
            "\n".join(self.saved_reports[0][1]),
        )

    def test_page_cache_is_not_shared_between_audit_runs(self):
        self.set_responses(FakeResponse())
        self.run_audit("https://authorized.example/")
        first_session = self.session
        self.set_responses(FakeResponse())
        self.run_audit("https://authorized.example/")

        self.assertEqual(len(first_session.calls), 1)
        self.assertEqual(len(self.session.calls), 1)

    def test_cached_header_snapshot_preserves_case_insensitive_lookup(self):
        self.set_responses(FakeResponse(headers={
            "content-security-policy": "default-src 'self'",
        }))

        self.run_audit("https://authorized.example/")

        report = "\n".join(self.saved_reports[0][1])
        self.assertIn("Content-Security-Policy: PRESENT", report)
        self.assertIn("Observed value: default-src 'self'", report)

    def test_page_response_is_closed_when_snapshot_body_read_fails(self):
        class BrokenBodyResponse:
            url = "https://authorized.example/"
            status_code = 200
            headers = {"Content-Security-Policy": "default-src 'self'"}
            is_redirect = False

            def __init__(self):
                self.closed = False
                self.body_read_before_close = False

            @property
            def text(self):
                self.body_read_before_close = not self.closed
                raise RuntimeError("body read failed")

            def close(self):
                self.closed = True

        response = BrokenBodyResponse()
        self.set_responses(response)

        with self.assertRaisesRegex(RuntimeError, "body read failed"):
            self.namespace["_get_audit_page_data"](
                response.url, {}
            )

        self.assertTrue(response.body_read_before_close)
        self.assertTrue(response.closed)

    def test_explicit_opt_in_sends_reflection_probe_through_scoped_get(self):
        self.set_responses(
            FakeResponse(url="https://authorized.example/?q=old&keep=yes"),
            FakeResponse(text="value JARVIS_TEST_12345 appeared"),
        )

        self.run_audit(
            "https://authorized.example/", active_checks=True, request_budget=2
        )

        self.assertEqual(len(self.session.calls), 2)
        self.assertEqual(
            self.session.calls[1][0],
            "https://authorized.example/?q=JARVIS_TEST_12345&keep=yes",
        )
        self.assertNotIn("params", self.session.calls[1][1])
        self.assertEqual(self.session.calls[1][1]["timeout"], 10)
        reflection_candidate = next(
            candidate for candidate in self.candidates
            if candidate[0][1] == "Reflected Input"
        )
        evidence = reflection_candidate[0][4]
        self.assertIn("output context and browser execution were not assessed", evidence)
        self.assertIn("no exploit payload sent", reflection_candidate[1]["testing_context"])

    def test_reflection_response_is_closed_after_normal_candidate_recording(self):
        url = "https://authorized.example/item.php?q=old"
        response = FakeResponse(
            url="https://authorized.example/item.php?q=JARVIS_TEST_12345",
            text="JARVIS_TEST_12345 appeared",
        )
        self.set_responses(response)

        with contextlib.redirect_stdout(io.StringIO()):
            result = self.namespace["check_reflection"](url, "q", enabled=True)

        self.assertTrue(result)
        self.assertTrue(response.closed)
        self.assertEqual(self.candidates[0][0][2], "Potential")

    def test_reflection_response_is_closed_when_body_read_raises(self):
        class BrokenReflectionResponse:
            url = "https://authorized.example/item.php?q=JARVIS_TEST_12345"
            status_code = 200
            headers = {}
            is_redirect = False

            def __init__(self):
                self.closed = False
                self.body_read_before_close = False

            @property
            def text(self):
                self.body_read_before_close = not self.closed
                raise RuntimeError("reflection body read failed")

            def close(self):
                self.closed = True

        response = BrokenReflectionResponse()
        self.set_responses(response)

        with self.assertRaisesRegex(RuntimeError, "reflection body read failed"):
            self.namespace["check_reflection"](
                "https://authorized.example/item.php?q=old", "q", enabled=True
            )

        self.assertTrue(response.body_read_before_close)
        self.assertTrue(response.closed)

    def test_reflection_response_is_closed_when_candidate_recording_raises(self):
        response = FakeResponse(
            url="https://authorized.example/item.php?q=JARVIS_TEST_12345",
            text="JARVIS_TEST_12345 appeared",
        )
        self.set_responses(response)
        self.namespace["record_candidate"] = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("candidate recording failed")
        )

        with self.assertRaisesRegex(RuntimeError, "candidate recording failed"):
            self.namespace["check_reflection"](
                "https://authorized.example/item.php?q=old", "q", enabled=True
            )

        self.assertTrue(response.closed)

    def test_parameter_discovery_retains_entry_and_link_endpoint_provenance(self):
        entry_url = "https://authorized.example/index.php?q=entry&keep=one"
        linked_url = "https://authorized.example/item.php?q=linked&keep=two"
        response = FakeResponse(
            url=entry_url,
            text='<a href="/item.php?q=linked&amp;keep=two">item</a>',
        )

        with contextlib.redirect_stdout(io.StringIO()):
            parameters = self.namespace["discover_parameters"](response)

        self.assertEqual(
            parameters,
            [
                {"method": "GET", "name": "q", "url": entry_url},
                {"method": "GET", "name": "keep", "url": entry_url},
                {"method": "GET", "name": "q", "url": linked_url},
                {"method": "GET", "name": "keep", "url": linked_url},
            ],
        )

    def test_active_reflection_discovers_parameters_from_nested_crawled_pages(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php"
        section_url = "http://127.0.0.1/bWAPP/section.php"
        item_url = "http://127.0.0.1/bWAPP/item.php?id=7&keep=two"
        id_probe = "http://127.0.0.1/bWAPP/item.php?id=JARVIS_TEST_12345&keep=two"
        keep_probe = "http://127.0.0.1/bWAPP/item.php?id=7&keep=JARVIS_TEST_12345"
        self.set_responses(
            FakeResponse(
                url=entry_url,
                text='<a href="/bWAPP/section.php">section</a>',
            ),
            FakeResponse(
                url=section_url,
                text='<a href="/bWAPP/item.php?id=7&amp;keep=two">item</a>',
            ),
            FakeResponse(url=item_url, text="item page"),
            FakeResponse(url=id_probe, text="JARVIS_TEST_12345 reflected"),
            FakeResponse(url=keep_probe, text="JARVIS_TEST_12345 reflected"),
        )

        self.run_audit(entry_url, active_checks=True, request_budget=5)

        self.assertEqual(
            [call[0] for call in self.session.calls],
            [entry_url, section_url, item_url, id_probe, keep_probe],
        )
        self.assertTrue(all("params" not in call[1] for call in self.session.calls))
        reflected = [
            candidate for candidate in self.candidates
            if candidate[0][1] == "Reflected Input"
        ]
        self.assertEqual(len(reflected), 2)
        self.assertEqual({candidate[0][0] for candidate in reflected}, {item_url})
        self.assertTrue(any("GET: id" in line for line in self.saved_reports[0][1]))
        self.assertTrue(any("GET: keep" in line for line in self.saved_reports[0][1]))

    def test_saved_parameter_inventory_preserves_endpoint_and_query_variants(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php?id=entry"
        first_url = "http://127.0.0.1/bWAPP/item.php?id=7&keep=two"
        second_url = "http://127.0.0.1/bWAPP/item.php?id=8&keep=two"
        self.set_responses(
            FakeResponse(
                url=entry_url,
                text=(
                    '<a href="/bWAPP/item.php?id=7&amp;keep=two">first</a>'
                    '<a href="/bWAPP/item.php?id=8&amp;keep=two">second</a>'
                ),
            ),
            FakeResponse(url=first_url, text="first item"),
            FakeResponse(url=second_url, text="second item"),
        )

        self.run_audit(entry_url)

        report_lines = self.saved_reports[0][1]
        id_lines = [
            line for line in report_lines
            if line.startswith("  GET: id | Endpoint:")
        ]
        self.assertEqual(
            id_lines,
            [
                "  GET: id | Endpoint: "
                "http://127.0.0.1/bWAPP/index.php?id=%5BREDACTED%5D | Variant: 1",
                "  GET: id | Endpoint: "
                "http://127.0.0.1/bWAPP/item.php?id=%5BREDACTED%5D&keep=%5BREDACTED%5D "
                "| Variant: 2",
                "  GET: id | Endpoint: "
                "http://127.0.0.1/bWAPP/item.php?id=%5BREDACTED%5D&keep=%5BREDACTED%5D "
                "| Variant: 3",
            ],
        )
        self.assertIn(
            "  GET: keep | Endpoint: "
            "http://127.0.0.1/bWAPP/item.php?id=%5BREDACTED%5D&keep=%5BREDACTED%5D "
            "| Variant: 2",
            report_lines,
        )
        self.assertIn(
            "  GET: keep | Endpoint: "
            "http://127.0.0.1/bWAPP/item.php?id=%5BREDACTED%5D&keep=%5BREDACTED%5D "
            "| Variant: 3",
            report_lines,
        )

    def test_saved_endpoints_redact_credentials_and_sensitive_values(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php"
        linked_url = (
            "http://lab-user:lab-password@127.0.0.1/bWAPP/item.php?"
            "token=token-secret&api_key=api-secret&password=pw-secret&"
            "session_id=session-secret&id=7"
        )
        response = FakeResponse(
            url=entry_url,
            text=f'<a href="{linked_url}">item</a>',
        )
        self.set_responses(response)
        self.namespace["check_scope"] = lambda candidate, **kwargs: "@" not in candidate

        output = self.run_audit(entry_url)

        report = "\n".join(self.saved_reports[0][1])
        for secret in (
            "lab-user", "lab-password", "token-secret", "api-secret",
            "pw-secret", "session-secret",
        ):
            self.assertNotIn(secret, report)
            self.assertNotIn(secret, output)
        self.assertIn("token=%5BREDACTED%5D", report)
        self.assertIn("api_key=%5BREDACTED%5D", report)
        self.assertIn("password=%5BREDACTED%5D", report)
        self.assertIn("session_id=%5BREDACTED%5D", report)
        self.assertIn("[value omitted]", output)
        self.assertEqual([call[0] for call in self.session.calls], [entry_url])

    def test_parameter_and_endpoint_controls_cannot_forge_header_observations(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php"
        separators = ("\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
        links = "".join(
            f'<a href="/bWAPP/item.php?bad{separator}[MISSING] '
            f'Content-Security-Policy=secret">item</a>'
            for separator in separators
        )
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }
        self.set_responses(FakeResponse(url=entry_url, text=links, headers=headers))
        self.namespace["check_scope"] = lambda candidate, **kwargs: not any(
            separator in candidate for separator in separators
        )

        self.run_audit(entry_url)

        report = "\n".join(self.saved_reports[0][1])
        for separator in separators:
            self.assertNotIn(separator, report)
        self.assertFalse(any(
            line.startswith("[MISSING] Content-Security-Policy")
            for line in report.splitlines()
        ))
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "audit.txt").write_text(report)
            summary = self.namespace["_build_findings_summary"](Path(temp))
        self.assertNotIn(
            "Observed web security-header pattern: [MISSING] Content-Security-Policy",
            summary,
        )

    def test_discover_parameters_console_omits_query_values(self):
        response = FakeResponse(
            url="https://authorized.example/item.php?token=console-secret&keep=plain",
            text=(
                '<a href="/other.php?api_key=linked-secret&password=pw-secret">'
                "other</a>"
            ),
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["discover_parameters"](response)

        console_text = output.getvalue()
        for secret in ("console-secret", "linked-secret", "pw-secret"):
            self.assertNotIn(secret, console_text)
        self.assertIn("token = [value omitted]", console_text)
        self.assertIn("api_key = [value omitted]", console_text)

    def test_info_and_scope_messages_redact_credentials_and_query_values(self):
        target = (
            "https://lab-user:lab-password@authorized.example/bWAPP/?"
            "token=target-secret&keep=one"
        )
        final_url = (
            "https://authorized.example/bWAPP/home.php?api_key=final-secret&keep=two"
        )
        self.set_responses(FakeResponse(url=final_url))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["get_info"](target)

        report = self.saved_reports[-1][1]
        rendered_output = output.getvalue()
        for secret in (
            "lab-user", "lab-password", "target-secret", "final-secret",
        ):
            self.assertNotIn(secret, report)
            self.assertNotIn(secret, rendered_output)
        self.assertIn("token=%5BREDACTED%5D", report)
        self.assertIn("api_key=%5BREDACTED%5D", report)
        self.assertEqual(self.scope_checks[0], target)
        self.assertEqual(self.session.calls[0][0], target)

        source_path = self.source_path
        tree = ast.parse(source_path.read_text())
        check_node = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "check_scope"
        )
        local_namespace = {
            "re": re,
            "_render_report_target": self.namespace["_render_report_target"],
            "_parse_scope_url": lambda value: None,
            "_scope_path_matches": lambda *args: False,
            "load_scope": lambda: [],
            "get_url": lambda value: value,
        }
        exec(compile(ast.fix_missing_locations(ast.Module(body=[check_node], type_ignores=[])),
                     str(source_path), "exec"), local_namespace)
        denied = io.StringIO()
        with contextlib.redirect_stdout(denied):
            allowed = local_namespace["check_scope"](target)
        self.assertFalse(allowed)
        self.assertNotIn("lab-password", denied.getvalue())
        self.assertNotIn("target-secret", denied.getvalue())

    def test_form_markup_values_and_names_are_safe_in_console_and_report(self):
        target = "https://authorized.example/bWAPP/index.php"
        secret = "csrf-hidden-secret"
        forged_name = "field\n[MISSING] Content-Security-Policy"
        form_html = (
            f'<form method="post" action="/submit.php?token={secret}">'
            f'<input type="hidden" name="{forged_name}" value="{secret}">'
            f'<input name="username" value="private-user">'
            "</form>"
        )
        response = FakeResponse(url=target, text=form_html)
        self.set_responses(response)
        self.namespace["discover_forms"] = self.namespace["discover_forms"]
        output = self.run_audit(target)
        report = "\n".join(self.saved_reports[0][1])

        for untrusted in (secret, "private-user", "<form", "value="):
            self.assertNotIn(untrusted, output)
            self.assertNotIn(untrusted, report)
        self.assertIn("method=POST", report)
        self.assertIn("name=field%0A[MISSING]%20Content-Security-Policy", report)
        self.assertNotIn("[MISSING] Content-Security-Policy", report.splitlines())
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "audit.txt").write_text(report)
            summary = self.namespace["_build_findings_summary"](Path(temp))
        self.assertNotIn(
            "Observed web security-header pattern: [MISSING] Content-Security-Policy",
            summary,
        )

    def test_safe_parameter_renderer_handles_unpaired_surrogates(self):
        rendered = self.namespace["_safe_report_parameter_name"]("bad\ud800name")
        self.assertEqual(rendered, "bad%ED%A0%80name")

    def test_failed_discovered_page_is_reported_as_incomplete_coverage(self):
        entry_url = "https://authorized.example/bWAPP/index.php"
        failed_url = "https://authorized.example/bWAPP/page.php?token=private-value"
        self.set_responses(
            FakeResponse(
                url=entry_url,
                text='<a href="/bWAPP/page.php?token=private-value">page</a>',
            ),
            requests.ConnectionError("private transport details"),
        )

        self.run_audit(entry_url)

        report = "\n".join(self.saved_reports[0][1])
        coverage_line = next(
            line for line in report.splitlines()
            if line.startswith("  Not analyzed:")
        )
        self.assertIn("Crawl Coverage: INCOMPLETE", report)
        self.assertIn("https://authorized.example/bWAPP/page.php", coverage_line)
        self.assertIn("request failed; page was not analyzed", coverage_line)
        self.assertNotIn("private-value", coverage_line)
        self.assertNotIn("private transport details", coverage_line)
        self.assertNotIn(f"  {failed_url}", report)
        self.assertEqual([call[0] for call in self.session.calls], [
            entry_url, failed_url,
        ])

    def test_scope_blocked_discovered_page_is_reported_without_request(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php"
        blocked_url = "http://127.0.0.1/bWAPP/admin.php"
        self.set_responses(FakeResponse(
            url=entry_url,
            text='<a href="/bWAPP/admin.php">admin</a>',
        ))
        self.namespace["check_scope"] = lambda candidate, **kwargs: candidate != blocked_url

        self.run_audit(entry_url)

        report = "\n".join(self.saved_reports[0][1])
        coverage_line = next(
            line for line in report.splitlines()
            if line.startswith("  Not analyzed:")
        )
        self.assertIn("Crawl Coverage: INCOMPLETE", report)
        self.assertIn(blocked_url, coverage_line)
        self.assertIn("scope policy blocked the request or redirect", coverage_line)
        self.assertEqual([call[0] for call in self.session.calls], [entry_url])
        local_pages = report.split("Local Pages:", 1)[1].split(
            "Crawl Coverage:", 1
        )[0]
        self.assertNotIn(blocked_url, local_pages)

    def test_page_limit_reports_queued_pages_without_requesting_them(self):
        entry_url = "https://authorized.example/bWAPP/index.php"
        fetched_url = "https://authorized.example/bWAPP/fetched.php"
        skipped_urls = (
            "https://user:password@authorized.example/bWAPP/skipped-one.php?token=private-one",
            "https://authorized.example/bWAPP/skipped-two.php?api_key=private-two",
        )
        entry_response = FakeResponse(
            url=entry_url,
            text=(
                '<a href="/bWAPP/fetched.php">fetched</a>'
                f'<a href="{skipped_urls[0]}">skipped one</a>'
                f'<a href="{skipped_urls[1]}">skipped two</a>'
            ),
        )
        self.set_responses(
            entry_response,
            FakeResponse(url=fetched_url, text="fetched page"),
        )
        crawl = self.namespace["crawl_local_pages"]
        self.namespace["crawl_local_pages"] = lambda url, **kwargs: crawl(
            url, max_pages=2, **kwargs
        )

        self.run_audit(entry_url)

        self.assertEqual(
            [call[0] for call in self.session.calls], [entry_url, fetched_url]
        )
        report = "\n".join(self.saved_reports[0][1])
        self.assertIn("Crawl Coverage: INCOMPLETE", report)
        not_analyzed = [
            line for line in report.splitlines()
            if line.startswith("  Not analyzed:")
        ]
        self.assertEqual(len(not_analyzed), 2)
        self.assertTrue(any("skipped-one.php" in line for line in not_analyzed))
        self.assertTrue(any("skipped-two.php" in line for line in not_analyzed))
        self.assertTrue(all("page limit reached; page was not analyzed" in line for line in not_analyzed))
        for secret in ("user", "password", "private-one", "private-two", "?token", "?api_key"):
            self.assertNotIn(secret, "\n".join(not_analyzed))

    def test_page_limit_with_empty_queue_does_not_mark_coverage_incomplete(self):
        entry_url = "https://authorized.example/bWAPP/index.php"
        self.set_responses(FakeResponse(url=entry_url, text="no links"))
        crawl = self.namespace["crawl_local_pages"]
        self.namespace["crawl_local_pages"] = lambda url, **kwargs: crawl(
            url, max_pages=1, **kwargs
        )

        self.run_audit(entry_url)

        report = "\n".join(self.saved_reports[0][1])
        self.assertNotIn("Crawl Coverage: INCOMPLETE", report)
        self.assertEqual([call[0] for call in self.session.calls], [entry_url])

    def test_html_entity_link_parameters_are_probed_with_correct_query_structure(self):
        entry_url = "https://authorized.example/index.php"
        linked_url = "https://authorized.example/item.php?q=linked&keep=two"
        self.set_responses(
            FakeResponse(
                url=entry_url,
                text='<a href="/item.php?q=linked&amp;keep=two">item</a>',
            ),
            FakeResponse(text="q marker JARVIS_TEST_12345"),
            FakeResponse(text="keep marker JARVIS_TEST_12345"),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            discovered_links = self.namespace["discover_links"](
                FakeResponse(
                    url=entry_url,
                    text='<a href="/item.php?q=linked&amp;keep=two">item</a>',
                )
            )
        self.assertEqual(discovered_links[0][1], linked_url)

        self.run_audit(entry_url, active_checks=True, request_budget=3)

        self.assertEqual(
            [call[0] for call in self.session.calls],
            [
                entry_url,
                "https://authorized.example/item.php?q=JARVIS_TEST_12345&keep=two",
                "https://authorized.example/item.php?q=linked&keep=JARVIS_TEST_12345",
            ],
        )
        self.assertTrue(all("params" not in call[1] for call in self.session.calls))

    def test_sql_name_candidates_keep_their_discovered_get_endpoint(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php"
        first_url = "http://127.0.0.1/bWAPP/item.php?id=1"
        second_url = "http://127.0.0.1/bWAPP/item.php?id=2"
        self.set_responses(
            FakeResponse(
                url=entry_url,
                text=(
                    '<a href="/bWAPP/item.php?id=1">first</a>'
                    '<a href="/bWAPP/item.php?id=2">second</a>'
                ),
            ),
            FakeResponse(url=first_url, text="first item"),
            FakeResponse(url=second_url, text="second item"),
        )

        self.run_audit(entry_url)

        sql_candidates = [
            candidate for candidate in self.candidates
            if candidate[0][1] == "SQL Injection"
        ]
        self.assertEqual(len(sql_candidates), 2)
        evidence = [candidate[0][4] for candidate in sql_candidates]
        self.assertEqual(len(set(evidence)), 2)
        self.assertTrue(any(
            "Discovered GET endpoint (variant 1): "
            + self.namespace["_render_report_endpoint"](first_url) in item
            for item in evidence
        ))
        self.assertTrue(any(
            "Discovered GET endpoint (variant 2): "
            + self.namespace["_render_report_endpoint"](second_url) in item
            for item in evidence
        ))
        self.assertTrue(all(
            candidate[0][2] == "Potential High"
            and "parameter-name match only" in candidate[0][4]
            and "query handling was not observed" in candidate[0][4]
            for candidate in sql_candidates
        ))
        self.assertTrue(all(
            "id=1" not in item and "id=2" not in item for item in evidence
        ))

    def test_reflection_preserves_repeated_blank_query_values_and_fragment(self):
        source_url = (
            "https://authorized.example/item.php?choice=first&keep=&choice=second"
            "&keep=again#details"
        )
        self.set_responses(FakeResponse(text="no marker"))

        with contextlib.redirect_stdout(io.StringIO()):
            self.namespace["check_reflection"](source_url, "choice", enabled=True)

        self.assertEqual(
            self.session.calls[0][0],
            "https://authorized.example/item.php?choice=JARVIS_TEST_12345&keep="
            "&choice=JARVIS_TEST_12345&keep=again#details",
        )

    def test_active_reflection_probes_distinct_endpoints_once_and_preserves_queries(self):
        entry_url = "https://authorized.example/index.php?q=entry&keep=one"
        linked_url = "https://authorized.example/item.php?q=linked&keep=two"
        self.set_responses(
            FakeResponse(url=entry_url),
            FakeResponse(text="entry marker JARVIS_TEST_12345"),
            FakeResponse(text="entry keep marker JARVIS_TEST_12345"),
            FakeResponse(text="linked marker JARVIS_TEST_12345"),
            FakeResponse(text="linked keep marker JARVIS_TEST_12345"),
        )
        self.namespace["discover_links"] = lambda response: [
            ("LOCAL", linked_url, "/item.php?q=linked&keep=two"),
            ("LOCAL", linked_url, "/item.php?q=linked&keep=two"),
        ]

        self.run_audit(entry_url, active_checks=True, request_budget=5)

        self.assertEqual(
            [call[0] for call in self.session.calls],
            [
                entry_url,
                "https://authorized.example/index.php?q=JARVIS_TEST_12345&keep=one",
                "https://authorized.example/index.php?q=entry&keep=JARVIS_TEST_12345",
                "https://authorized.example/item.php?q=JARVIS_TEST_12345&keep=two",
                "https://authorized.example/item.php?q=linked&keep=JARVIS_TEST_12345",
            ],
        )
        self.assertTrue(all("params" not in call[1] for call in self.session.calls))
        reflection_candidates = [
            candidate for candidate in self.candidates
            if candidate[0][1] == "Reflected Input"
        ]
        self.assertEqual(len(reflection_candidates), 4)
        self.assertTrue(all(candidate[0][2] == "Potential" for candidate in reflection_candidates))
        self.assertTrue(all(
            "output context and browser execution were not assessed" in candidate[0][4]
            for candidate in reflection_candidates
        ))

    def test_active_reflection_keeps_post_fields_inventory_only(self):
        response = FakeResponse(
            url="https://authorized.example/login.php",
            text='<form method="post"><input name="password"></form>',
        )
        self.set_responses(response)

        self.run_audit(response.url, active_checks=True, request_budget=2)

        self.assertEqual(len(self.session.calls), 1)
        self.assertEqual(self.session.calls[0][0], response.url)
        self.assertEqual(self.session.calls[0][1].get("data"), None)

    def test_scope_rejection_blocks_link_reflection_request(self):
        entry_url = "https://authorized.example/index.php?q=entry"
        linked_url = "https://authorized.example/item.php?q=linked"
        self.set_responses(
            FakeResponse(url=entry_url),
            FakeResponse(text="entry marker JARVIS_TEST_12345"),
        )
        self.namespace["discover_links"] = lambda response: [
            ("LOCAL", linked_url, "/item.php?q=linked"),
        ]

        def selective_scope(target, **kwargs):
            self.scope_checks.append(target)
            return "/item.php" not in target

        self.namespace["check_scope"] = selective_scope
        self.run_audit(entry_url, active_checks=True, request_budget=3)

        self.assertEqual(len(self.session.calls), 2)
        self.assertTrue(any(target.startswith(linked_url.split("?", 1)[0]) for target in self.scope_checks))
        self.assertNotIn(linked_url, [call[0] for call in self.session.calls])

    def test_scope_rejection_blocks_get_form_action_before_request(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php"
        self.set_responses(FakeResponse(
            url=entry_url,
            text=(
                '<form method="get" action="http://outside.example/search.php">'
                '<input name="q"></form>'
            ),
        ))
        self.namespace["check_scope"] = lambda candidate, **kwargs: (
            self.scope_checks.append(candidate)
            or "outside.example" not in candidate
        )

        self.run_audit(entry_url, active_checks=True, request_budget=2)

        self.assertEqual([call[0] for call in self.session.calls], [entry_url])
        self.assertIn(
            "http://outside.example/search.php?q=JARVIS_TEST_12345",
            self.scope_checks,
        )

    def test_invalid_request_budgets_are_rejected_before_audit_requests(self):
        parse_options = self.namespace["_parse_audit_options"]
        self.assertEqual(parse_options("--active --request-budget 3"), (True, 3))
        for raw_budget in ("bad", "0", "-1", "101"):
            with self.subTest(budget=raw_budget), self.assertRaises(ValueError):
                parse_options(f"--active --request-budget {raw_budget}")
        with self.assertRaises(ValueError):
            parse_options("--active --request-budget")

        self.set_responses()
        output = self.run_audit(
            "https://authorized.example/", active_checks=True, request_budget=0
        )

        self.assertIn("Invalid audit controls", output)
        self.assertEqual(self.session.calls, [])
        self.assertEqual(self.scope_checks, [])

    def test_budget_exhaustion_stops_before_an_over_budget_active_request(self):
        self.set_responses(FakeResponse(url="https://authorized.example/?q=old"))

        output = self.run_audit(
            "https://authorized.example/", active_checks=True, request_budget=1
        )

        self.assertEqual(len(self.session.calls), 1)
        self.assertIn("request budget was exhausted (1 of 1 requests used)", output)
        self.assertIn("Remaining checks were not run", output)
        self.assertIn("audit report was not saved", output)
        self.assertEqual(self.saved_reports, [])

    def test_security_header_evidence_distinguishes_present_missing_and_unavailable(self):
        check_headers = self.namespace["check_security_headers"]
        response = FakeResponse(headers={
            "Content-Security-Policy": "default-src 'self'\r\nX-Injected: yes",
            "X-Frame-Options": "DENY",
        })

        results = {item["header"]: item for item in check_headers(response)}

        self.assertEqual(results["Content-Security-Policy"]["status"], "PRESENT")
        self.assertEqual(
            results["Content-Security-Policy"]["value"],
            "default-src 'self'\\r\\nX-Injected: yes",
        )
        self.assertEqual(results["X-Content-Type-Options"]["status"], "MISSING")
        self.assertNotIn("value", results["X-Content-Type-Options"])

        unavailable_response = FakeResponse()
        del unavailable_response.headers
        unavailable = check_headers(unavailable_response)

        self.assertEqual({item["status"] for item in unavailable}, {"NOT RECORDED"})

    def test_audit_report_preserves_status_lines_and_records_header_values(self):
        self.set_responses(FakeResponse(headers={
            "Content-Security-Policy": "default-src 'self'",
        }))

        self.run_audit("https://authorized.example/")

        report = "\n".join(self.saved_reports[0][1])
        self.assertIn("Content-Security-Policy: PRESENT", report)
        self.assertIn("    Observed value: default-src 'self'", report)
        self.assertIn("X-Content-Type-Options: MISSING", report)

        self.set_responses(FakeResponse())
        del self.session.responses[0].headers
        self.run_audit("https://authorized.example/")

        unavailable_report = "\n".join(self.saved_reports[1][1])
        self.assertIn("Content-Security-Policy: NOT RECORDED", unavailable_report)

    def test_web_info_report_records_header_values_without_changing_status_labels(self):
        self.set_responses(FakeResponse(headers={
            "X-Frame-Options": "SAMEORIGIN",
        }))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["get_info"]("https://authorized.example/")

        report = self.saved_reports[0][1]
        self.assertIn("[PRESENT] X-Frame-Options -", report)
        self.assertIn("  Observed value: SAMEORIGIN", report)
        self.assertIn("[MISSING] Content-Security-Policy -", report)

    def test_web_info_report_marks_unavailable_header_mapping_not_recorded(self):
        response = FakeResponse()
        del response.headers
        self.set_responses(response)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["get_info"]("https://authorized.example/")

        report = self.saved_reports[0][1]
        self.assertIn("Server       : Not recorded", report)
        self.assertIn("Content-Type : Not recorded", report)
        self.assertIn("[NOT RECORDED] Content-Security-Policy -", report)

    def test_web_info_report_escapes_server_and_content_type_metadata(self):
        cases = (
            (
                {"Server": "nginx\r\nVulnerability status: CONFIRMED", "Content-Type": "text/html"},
                "Server       : nginx\\r\\nVulnerability status: CONFIRMED",
                "Content-Type : text/html",
            ),
            (
                {"Server": "nginx", "Content-Type": "text/html\r\nVulnerability status: CONFIRMED"},
                "Server       : nginx",
                "Content-Type : text/html\\r\\nVulnerability status: CONFIRMED",
            ),
            (
                {"Server": "nginx/1.25", "Content-Type": "text/html; charset=utf-8"},
                "Server       : nginx/1.25",
                "Content-Type : text/html; charset=utf-8",
            ),
        )

        for headers, expected_server, expected_content_type in cases:
            with self.subTest(headers=headers):
                self.saved_reports.clear()
                self.set_responses(FakeResponse(headers=headers))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.namespace["get_info"]("https://authorized.example/")

                report = self.saved_reports[0][1]
                for rendered_value in (expected_server, expected_content_type):
                    self.assertIn(rendered_value, report)
                    self.assertIn(rendered_value, output.getvalue())
                self.assertNotIn("\r\nVulnerability status: CONFIRMED", report)
                self.assertNotIn(
                    "Vulnerability status: CONFIRMED",
                    [line.strip() for line in report.splitlines()],
                )

    def test_audit_and_web_info_reports_escape_crlf_header_values(self):
        injected_value = "default-src 'self'\r\nX-Forged-Report-Line: injected"
        escaped_value = "default-src 'self'\\r\\nX-Forged-Report-Line: injected"

        self.set_responses(FakeResponse(headers={
            "Content-Security-Policy": injected_value,
        }))
        self.run_audit("https://authorized.example/")

        audit_report = "\n".join(self.saved_reports[0][1])
        self.assertIn(f"Observed value: {escaped_value}", audit_report)
        self.assertNotIn("\nX-Forged-Report-Line: injected", audit_report)
        self.assertNotIn("\rX-Forged-Report-Line: injected", audit_report)
        self.assertFalse(any(
            line.startswith("X-Forged-Report-Line:")
            for line in audit_report.splitlines()
        ))

        self.saved_reports.clear()
        self.set_responses(FakeResponse(headers={
            "Content-Security-Policy": injected_value,
        }))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["get_info"]("https://authorized.example/")

        info_report = self.saved_reports[0][1]
        self.assertIn(f"Observed value: {escaped_value}", info_report)
        self.assertNotIn("\nX-Forged-Report-Line: injected", info_report)
        self.assertNotIn("\rX-Forged-Report-Line: injected", info_report)
        self.assertFalse(any(
            line.startswith("X-Forged-Report-Line:")
            for line in info_report.splitlines()
        ))

    def test_unicode_line_separators_are_escaped_in_header_reports_and_metadata(self):
        escapes = {
            "\x85": "\\x85",
            "\u2028": "\\u2028",
            "\u2029": "\\u2029",
        }

        for separator, escaped_separator in escapes.items():
            with self.subTest(separator=escaped_separator):
                injected_value = (
                    f"default-src 'self'{separator}X-Forged-Report-Line: injected"
                )
                escaped_value = (
                    f"default-src 'self'{escaped_separator}"
                    "X-Forged-Report-Line: injected"
                )

                self.saved_reports.clear()
                self.set_responses(FakeResponse(headers={
                    "Content-Security-Policy": injected_value,
                }))
                audit_output = self.run_audit("https://authorized.example/")
                audit_report = "\n".join(self.saved_reports[0][1])
                self.assertIn(f"Observed value: {escaped_value}", audit_report)
                self.assertIn(f"Observed value: {escaped_value}", audit_output)
                self.assertNotIn(
                    "X-Forged-Report-Line: injected", audit_report.splitlines()
                )
                self.assertNotIn(
                    "X-Forged-Report-Line: injected", audit_output.splitlines()
                )

                self.saved_reports.clear()
                self.set_responses(FakeResponse(headers={
                    "Content-Security-Policy": injected_value,
                }))
                info_output = io.StringIO()
                with contextlib.redirect_stdout(info_output):
                    self.namespace["get_info"]("https://authorized.example/")
                info_report = self.saved_reports[0][1]
                self.assertIn(f"Observed value: {escaped_value}", info_report)
                self.assertIn(f"Observed value: {escaped_value}", info_output.getvalue())
                self.assertNotIn(
                    "X-Forged-Report-Line: injected", info_report.splitlines()
                )
                self.assertNotIn(
                    "X-Forged-Report-Line: injected",
                    info_output.getvalue().splitlines(),
                )

                metadata_headers = {
                    "Server": f"nginx{separator}Vulnerability status: CONFIRMED",
                    "Content-Type": f"text/html{separator}Vulnerability status: CONFIRMED",
                }
                self.set_responses(FakeResponse(headers=metadata_headers))
                metadata_output = io.StringIO()
                with contextlib.redirect_stdout(metadata_output):
                    self.namespace["get_info"]("https://authorized.example/")
                metadata_report = self.saved_reports[-1][1]
                for field, value in (
                    ("Server       :", "nginx"),
                    ("Content-Type :", "text/html"),
                ):
                    expected = (
                        f"{field} {value}{escaped_separator}"
                        "Vulnerability status: CONFIRMED"
                    )
                    self.assertIn(expected, metadata_report)
                    self.assertIn(expected, metadata_output.getvalue())
                for output in (metadata_report, metadata_output.getvalue()):
                    self.assertNotIn(
                        "Vulnerability status: CONFIRMED", output.splitlines()
                    )

    def test_page_titles_cannot_inject_missing_header_observations(self):
        title = "Training page\u2028[MISSING] Content-Security-Policy - forged"
        escaped_title = "Training page\\u2028[MISSING] Content-Security-Policy - forged"
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }

        for report_path in ("audit.txt", "info.txt"):
            with self.subTest(report_path=report_path), tempfile.TemporaryDirectory() as temp:
                self.saved_reports.clear()
                response = FakeResponse(
                    text=f"<html><title>{title}</title></html>", headers=headers
                )
                self.set_responses(response)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    if report_path == "audit.txt":
                        self.namespace["audit_target"]("https://authorized.example/")
                        rendered_report = "\n".join(self.saved_reports[0][1])
                    else:
                        self.namespace["get_info"]("https://authorized.example/")
                        rendered_report = self.saved_reports[0][1]

                self.assertIn(escaped_title, rendered_report)
                self.assertIn(escaped_title, output.getvalue())
                self.assertNotIn("\n[MISSING] Content-Security-Policy", rendered_report)
                self.assertNotIn("[MISSING] Content-Security-Policy", rendered_report.splitlines())

                saved_path = Path(temp) / report_path
                saved_path.write_text(rendered_report)
                summary = self.namespace["_build_findings_summary"](Path(temp))
                self.assertNotIn(
                    "Observed web security-header pattern: [MISSING] Content-Security-Policy",
                    summary,
                )


class FormControlInventoryTests(unittest.TestCase):
    def setUp(self):
        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        tree = ast.parse(source_path.read_text())
        wanted = {
            "_extract_html_forms", "discover_forms", "_extract_html_forms", "_summarize_form",
            "_html_attributes", "_form_control_inventory",
            "_safe_report_parameter_name",
            "inventory_local_forms", "discover_parameters",
        }
        functions = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in wanted
        ]
        self.response = FakeResponse(
            url="http://127.0.0.1/bWAPP/index.php",
            text=(
                '<form method="post" action="/submit.php?token=action-secret">'
                '<input name="username" value="private-user">'
                '<input value="unnamed-secret">'
                '<input name="empty_value">'
                '<input name="disabled_input" disabled value="disabled-secret">'
                '<textarea name="comment">textarea-secret</textarea>'
                '<textarea name="empty_text"></textarea>'
                '<textarea>unnamed-textarea-secret</textarea>'
                '<textarea name="disabled_text" disabled>disabled-text-secret</textarea>'
                '<select name="choice" multiple><option value="one">One</option>'
                '<option value="two">Two</option></select>'
                '<select name="empty_choice"></select>'
                '<select name="disabled_choice" disabled>'
                '<option value="three">Three</option></select>'
                '<select><option value="four">Four</option></select>'
                '</form>'
            ),
        )
        self.fetches = []
        self.namespace = {
            "re": re,
            "unescape": unescape,
            "urljoin": urljoin,
            "urlparse": urlparse,
            "quote_from_bytes": quote_from_bytes,
            "requests": requests,
            "discover_links": lambda response: [],
            "_render_report_endpoint": lambda value: re.sub(
                r"token=[^&]+", "token=%5BREDACTED%5D", value
            ),
            "_get_audit_page_data": lambda url, cache: (
                self.fetches.append(url) or self.response
            ),
        }
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                str(source_path),
                "exec",
            ),
            self.namespace,
        )

    def test_form_summary_covers_input_textarea_and_select_without_values(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            forms = self.namespace["discover_forms"](self.response)

        self.assertEqual(len(forms), 1)
        displayed = output.getvalue()
        for expected in (
            "Form: method=POST | action=http://127.0.0.1/submit.php?token=%5BREDACTED%5D",
            "Input: type=text | name=username | value omitted",
            "Input: type=text | name=(unnamed) | value omitted",
            "Input: type=text | name=empty_value | value omitted",
            "Input: type=text | name=disabled_input | value omitted | disabled",
            "Textarea: name=comment | value omitted",
            "Textarea: name=empty_text | value omitted",
            "Textarea: name=(unnamed) | value omitted",
            "Textarea: name=disabled_text | value omitted | disabled",
            "Select: name=choice | options=2 | multiple | value omitted",
            "Select: name=empty_choice | options=0 | value omitted",
            "Select: name=disabled_choice | options=1 | value omitted | disabled",
            "Select: name=(unnamed) | options=1 | value omitted",
        ):
            self.assertIn(expected, displayed)
        for secret in (
            "private-user", "unnamed-secret", "textarea-secret",
            "unnamed-textarea-secret", "disabled-secret", "disabled-text-secret",
            "action-secret", "value=", "value=one", "value=two",
        ):
            self.assertNotIn(secret, displayed)

    def test_form_inventory_includes_only_named_enabled_controls_without_requests(self):
        output = io.StringIO()
        pages = [{
            "requested_url": self.response.url,
            "display_url": self.response.url,
        }]
        with contextlib.redirect_stdout(output):
            parameters = self.namespace["inventory_local_forms"](pages, {})

        self.assertEqual(
            parameters,
            [
                ("POST", "username"),
                ("POST", "empty_value"),
                ("POST", "comment"),
                ("POST", "empty_text"),
                ("POST", "choice"),
                ("POST", "empty_choice"),
            ],
        )
        self.assertEqual(self.fetches, [self.response.url])
        self.assertNotIn("disabled_input", [name for _, name in parameters])
        self.assertNotIn("disabled_text", [name for _, name in parameters])
        self.assertNotIn("disabled_choice", [name for _, name in parameters])
        self.assertNotIn("value=", output.getvalue())
        self.assertNotIn("textarea-secret", output.getvalue())

    def test_parameter_discovery_includes_named_textarea_and_select_controls(self):
        with contextlib.redirect_stdout(io.StringIO()):
            parameters = self.namespace["discover_parameters"](self.response)

        form_parameters = [item for item in parameters if item["method"] == "POST"]
        self.assertEqual(
            [item["name"] for item in form_parameters],
            ["username", "empty_value", "comment", "empty_text", "choice", "empty_choice"],
        )
        self.assertTrue(all(item["url"] is None for item in form_parameters))

    def test_parameter_discovery_preserves_form_methods_and_html_default(self):
        response = FakeResponse(
            url="http://127.0.0.1/bWAPP/forms.php",
            text=(
                '<form method="get" action="/search.php"><input name="q"></form>'
                '<form action="/default.php"><textarea name="term"></textarea></form>'
                '<form method="post"><select name="csrf"></select></form>'
            ),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            parameters = self.namespace["discover_parameters"](response)

        self.assertEqual(
            [(item["method"], item["name"], item["url"]) for item in parameters],
            [
                ("GET", "q", "http://127.0.0.1/search.php"),
                ("GET", "term", "http://127.0.0.1/default.php"),
                ("POST", "csrf", None),
            ],
        )

    def test_form_like_text_in_comments_is_not_a_real_form(self):
        response = FakeResponse(
            url="http://127.0.0.1/bWAPP/index.php",
            text=(
                '<!-- <form><input name="fake"></form> -->'
                '<form><input name="real"></form>'
            ),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            forms = self.namespace["discover_forms"](response)

        self.assertEqual(len(forms), 1)
        self.assertIn('name="real"', forms[0])
        self.assertNotIn('name="fake"', forms[0])

    def test_unclosed_form_does_not_consume_later_page_content(self):
        response = FakeResponse(
            url="http://127.0.0.1/bWAPP/index.php",
            text='<form><input name="unfinished">',
        )

        with contextlib.redirect_stdout(io.StringIO()):
            forms = self.namespace["discover_forms"](response)

        self.assertEqual(forms, [])


class AuditPageCacheTests(unittest.TestCase):
    def setUp(self):
        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        tree = ast.parse(source_path.read_text())
        names = {
            "scoped_get", "_get_audit_page_data", "crawl_local_pages",
            "audit_local_pages", "inventory_local_forms", "discover_links",
            "_safe_report_parameter_name", "_render_report_endpoint",
            "_escape_report_user_field", "_escape_report_header_value",
        }
        functions = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in names
        ]
        self.scope_checks = []
        self.session = None
        self.namespace = {
            "re": re,
            "requests": requests,
            "urljoin": urljoin,
            "quote": quote,
            "quote_from_bytes": quote_from_bytes,
            "urlparse": urlparse,
            "urlsplit": urlsplit,
            "urlunsplit": urlunsplit,
            "unescape": unescape,
            "SimpleNamespace": SimpleNamespace,
            "_ACTIVE_AUDIT_REQUEST_BUDGET": None,
            "check_scope": lambda url, **kwargs: self.scope_checks.append(url) or True,
            "discover_forms": lambda response: [],
            "get_page_title": lambda response: "Cache fixture",
        }
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                str(source_path),
                "exec",
            ),
            self.namespace,
        )

    def set_responses(self, *responses):
        self.session = FakeSession(responses)
        self.namespace["session"] = self.session

    def test_exact_urls_are_fetched_once_across_all_page_phases(self):
        entry = "http://127.0.0.1/bWAPP/index.php"
        first = "http://127.0.0.1/bWAPP/page.php?id=1"
        second = "http://127.0.0.1/bWAPP/page.php?id=2"
        entry_response = FakeResponse(
            url=entry,
            text=(
                '<a href="/bWAPP/page.php?id=1">one</a>'
                '<a href="/bWAPP/page.php?id=2">two</a>'
            ),
        )
        first_response = FakeResponse(url=first, text="first body")
        second_response = FakeResponse(url=second, text="second body")
        self.set_responses(entry_response, first_response, second_response)
        cache = {}

        entry_data = self.namespace["_get_audit_page_data"](entry, cache)
        pages = self.namespace["crawl_local_pages"](
            entry_data.final_url,
            response_cache=cache,
            initial_response=entry_data,
        )
        self.namespace["audit_local_pages"](pages, cache)
        self.namespace["inventory_local_forms"](pages, cache)

        self.assertEqual([call[0] for call in self.session.calls], [entry, first, second])
        self.assertEqual(set(cache), {entry, first, second})
        self.assertEqual({page["requested_url"] for page in pages}, {entry, first, second})
        self.assertTrue(all(response.closed for response in (
            entry_response, first_response, second_response
        )))
        self.assertIsNot(cache[entry], entry_response)
        self.assertEqual(cache[entry].requested_url, entry)
        self.assertEqual(cache[entry].final_url, entry)
        self.assertEqual(cache[first].text, "first body")

    def test_redirected_entry_cache_uses_requested_url_and_reuses_snapshot(self):
        entry = "http://127.0.0.1/bWAPP/index.php"
        final = "http://127.0.0.1/bWAPP/start.php?view=home"
        redirect = FakeResponse(url=entry, headers={"Location": final})
        redirect.is_redirect = True
        final_response = FakeResponse(
            url=final,
            text="<title>Redirected entry</title>",
            headers={"Content-Security-Policy": "default-src 'self'"},
        )
        self.set_responses(redirect, final_response)
        budget = {"limit": 2, "used": 0, "exhausted": False}
        self.namespace["_ACTIVE_AUDIT_REQUEST_BUDGET"] = budget
        cache = {}

        entry_data = self.namespace["_get_audit_page_data"](entry, cache)
        pages = self.namespace["crawl_local_pages"](
            entry_data.final_url,
            response_cache=cache,
            initial_response=entry_data,
        )
        self.namespace["audit_local_pages"](pages, cache)
        self.namespace["inventory_local_forms"](pages, cache)

        self.assertEqual([call[0] for call in self.session.calls], [entry, final])
        self.assertEqual(set(cache), {entry})
        self.assertNotIn(final, cache)
        self.assertEqual(entry_data.requested_url, entry)
        self.assertEqual(entry_data.final_url, final)
        self.assertEqual(entry_data.url, final)
        self.assertEqual(entry_data.status_code, 200)
        self.assertEqual(
            entry_data.headers["content-security-policy"], "default-src 'self'"
        )
        self.assertEqual(entry_data.text, "<title>Redirected entry</title>")
        self.assertEqual(
            pages,
            [{"requested_url": entry, "display_url": final}],
        )
        self.assertIn(entry, self.scope_checks)
        self.assertIn(final, self.scope_checks)
        self.assertEqual(budget, {"limit": 2, "used": 2, "exhausted": False})
        self.assertTrue(redirect.closed)
        self.assertTrue(final_response.closed)

    def test_scope_is_checked_before_a_cached_page_is_returned(self):
        blocked = "http://127.0.0.1/bWAPP/admin/page.php?id=1"
        self.namespace["check_scope"] = lambda url, **kwargs: url != blocked
        cached = SimpleNamespace(
            requested_url=blocked,
            final_url=blocked,
            url=blocked,
            status_code=200,
            headers={},
            text="must not be served",
        )
        self.set_responses()

        with self.assertRaises(requests.RequestException):
            self.namespace["_get_audit_page_data"](blocked, {blocked: cached})

        self.assertEqual(self.session.calls, [])

    def test_cache_miss_redirect_still_validates_and_closes_blocked_hop(self):
        entry = "http://127.0.0.1/bWAPP/index.php"
        redirect = FakeResponse(url=entry, headers={"Location": "http://outside.test/"})
        redirect.is_redirect = True
        self.set_responses(redirect)
        self.namespace["check_scope"] = lambda url, **kwargs: "outside.test" not in url
        cache = {}

        with self.assertRaises(requests.RequestException):
            self.namespace["_get_audit_page_data"](entry, cache)

        self.assertEqual(len(self.session.calls), 1)
        self.assertTrue(redirect.closed)
        self.assertEqual(cache, {})

    def test_cache_miss_redirect_hops_consume_budget_before_next_request(self):
        entry = "http://127.0.0.1/bWAPP/index.php"
        redirect = FakeResponse(url=entry, headers={"Location": "/bWAPP/final.php"})
        redirect.is_redirect = True
        self.set_responses(redirect)
        budget = {"limit": 1, "used": 0, "exhausted": False}
        self.namespace["_ACTIVE_AUDIT_REQUEST_BUDGET"] = budget
        cache = {}

        with self.assertRaisesRegex(requests.RequestException, "budget exhausted"):
            self.namespace["_get_audit_page_data"](entry, cache)

        self.assertEqual(len(self.session.calls), 1)
        self.assertEqual(budget, {"limit": 1, "used": 1, "exhausted": True})
        self.assertTrue(redirect.closed)
        self.assertEqual(cache, {})


if __name__ == "__main__":
    unittest.main()
