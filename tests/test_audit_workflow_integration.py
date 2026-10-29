"""End-to-end web-audit workflow tests using isolated functions and mocks."""

import ast
import contextlib
import io
import ipaddress
import json
import os
import re
import secrets
import tempfile
import unittest
from datetime import datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import (
    quote,
    quote_from_bytes,
    unquote,
    urljoin,
    urlparse,
    urlsplit,
    urlunsplit,
)

import hashlib
import requests


class MockResponse:
    def __init__(self, url, text="", status_code=200, headers=None, redirect=False):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = {} if headers is None else headers
        self.is_redirect = redirect
        self.closed = False

    def close(self):
        self.closed = True


class MockSession:
    max_redirects = 10

    def __init__(self, responses):
        self.responses = dict(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses.get(url)
        if response is None:
            raise requests.ConnectionError("mock response not configured")
        if isinstance(response, BaseException):
            raise response
        return response


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


class AuditWorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.scope_file = root / "scope.txt"
        self.scope_file.write_text(
            "ALLOW http://127.0.0.1:80/bWAPP/*\n"
            "EXCLUDE http://127.0.0.1:80/bWAPP/private/*\n"
        )
        self.reports_dir = root / "reports"
        self.clock = FakeClock()

        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        tree = ast.parse(source_path.read_text())
        definitions = [
            node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        ]
        self.namespace = {
            "Path": Path,
            "re": re,
            "os": os,
            "requests": requests,
            "time": SimpleNamespace(
                monotonic=self.clock.monotonic,
                sleep=self.clock.sleep,
            ),
            "datetime": datetime,
            "SimpleNamespace": SimpleNamespace,
            "HTMLParser": HTMLParser,
            "hashlib": hashlib,
            "ipaddress": ipaddress,
            "secrets": secrets,
            "json": json,
            "quote": quote,
            "quote_from_bytes": quote_from_bytes,
            "unquote": unquote,
            "unescape": unescape,
            "urljoin": urljoin,
            "urlparse": urlparse,
            "urlsplit": urlsplit,
            "urlunsplit": urlunsplit,
            "SCOPE_FILE": self.scope_file,
            "REPORTS_DIR": self.reports_dir,
            "DEFAULT_AUDIT_REQUEST_BUDGET": 25,
            "MAX_AUDIT_REQUEST_BUDGET": 100,
            "DEFAULT_AUDIT_REQUEST_INTERVAL_SECONDS": 0.25,
            "MAX_REDIRECT_HOPS": 5,
            "_ACTIVE_AUDIT_REQUEST_BUDGET": None,
            "_HTTP_SESSIONS": {},
            "_REPORT_DISPLAY_ALIASES": {},
            "targets": [],
        }
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=definitions, type_ignores=[])),
                str(source_path),
                "exec",
            ),
            self.namespace,
        )

    def run_audit(self, target, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["audit_target"](target, **kwargs)
        return output.getvalue()

    def run_summary(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.namespace["show_findings_summary"]()
        return output.getvalue()

    def test_passive_audit_discovers_provenance_saves_and_summarizes_safely(self):
        entry_url = (
            "http://127.0.0.1/bWAPP/index.php?token=entry-secret&section=home"
        )
        item_url = (
            "http://127.0.0.1/bWAPP/item.php?id=7&file=readme&token=linked-secret"
        )
        detail_url = "http://127.0.0.1/bWAPP/detail.php?keep=two&id=3"
        entry = MockResponse(
            entry_url,
            text=(
                '<a href="/bWAPP/item.php?id=7&amp;file=readme&amp;token=linked-secret">item</a>'
            ),
        )
        item = MockResponse(
            item_url,
            text='<a href="/bWAPP/detail.php?keep=two&amp;id=3">detail</a>',
        )
        detail = MockResponse(detail_url, text="<p>ordinary page</p>")
        session = MockSession({
            entry_url: entry,
            item_url: item,
            detail_url: detail,
        })
        self.namespace["session"] = session

        output = self.run_audit(entry_url)

        self.assertEqual([call[0] for call in session.calls], [entry_url, item_url, detail_url])
        self.assertIn("Active Reflection Checks: skipped", output)
        self.assertTrue(all(response.closed for response in (entry, item, detail)))

        report_paths = sorted(self.reports_dir.glob("*.txt"))
        self.assertEqual(len(report_paths), 2)  # Main report plus an inventory candidate.
        report_texts = [path.read_text() for path in report_paths]
        main_report = next(text for text in report_texts if text.startswith("Target:"))
        combined_reports = "\n".join(report_texts)
        self.assertIn("SQL Injection Heuristic Signals:", main_report)
        self.assertIn("State: detected for review only", main_report)
        self.assertIn("Active Reflection Checks: skipped", main_report)
        self.assertIn("Vulnerability status: UNCONFIRMED", combined_reports)
        self.assertIn("GET: id | Endpoint: http://127.0.0.1/bWAPP/item.php", main_report)
        self.assertIn("GET: id | Endpoint: http://127.0.0.1/bWAPP/detail.php", main_report)
        self.assertIn("keep=%5BREDACTED%5D&id=%5BREDACTED%5D", main_report)
        for secret in ("entry-secret", "linked-secret"):
            self.assertNotIn(secret, combined_reports)
            self.assertNotIn(secret, output)

        summary = self.run_summary()
        self.assertIn("UNCONFIRMED", summary)
        self.assertIn("Recorded candidate evidence", summary)
        self.assertIn("parameter name was present", summary)
        for secret in ("entry-secret", "linked-secret"):
            self.assertNotIn(secret, summary)

    def test_out_of_scope_target_and_redirect_are_rejected_without_report(self):
        session = MockSession({})
        self.namespace["session"] = session

        output = self.run_audit("http://127.0.0.1/outside/index.php")
        self.assertIn("NOT in the authorized scope", output)
        self.assertEqual(session.calls, [])
        self.assertFalse(self.reports_dir.exists())

        entry_url = "http://127.0.0.1/bWAPP/index.php"
        redirect = MockResponse(
            entry_url,
            status_code=302,
            headers={"Location": "/bWAPP/private/admin.php"},
            redirect=True,
        )
        session = MockSession({entry_url: redirect})
        self.namespace["session"] = session

        output = self.run_audit(entry_url)
        self.assertIn("Unable to connect", output)
        self.assertEqual([call[0] for call in session.calls], [entry_url])
        self.assertTrue(redirect.closed)
        self.assertFalse(self.reports_dir.exists())

    def test_request_budget_exhaustion_does_not_save_partial_report(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php?id=7"
        entry = MockResponse(entry_url, text="<p>page</p>")
        session = MockSession({entry_url: entry})
        self.namespace["session"] = session

        output = self.run_audit(entry_url, active_checks=True, request_budget=1)

        self.assertEqual([call[0] for call in session.calls], [entry_url])
        self.assertIn("request budget was exhausted (1 of 1 requests used)", output)
        self.assertIn("audit report was not saved", output)
        self.assertTrue(entry.closed)
        self.assertFalse(self.reports_dir.exists())

    def test_failed_crawl_is_reported_incomplete_and_page_is_not_called_analyzed(self):
        entry_url = "http://127.0.0.1/bWAPP/index.php"
        failed_url = "http://127.0.0.1/bWAPP/item.php?id=9&token=private"
        entry = MockResponse(
            entry_url,
            text='<a href="/bWAPP/item.php?id=9&amp;token=private">item</a>',
        )
        session = MockSession({
            entry_url: entry,
            failed_url: requests.ConnectionError("mock failure detail"),
        })
        self.namespace["session"] = session

        self.run_audit(entry_url)

        self.assertEqual([call[0] for call in session.calls], [entry_url, failed_url])
        report = next(self.reports_dir.glob("*.txt")).read_text()
        self.assertIn("Crawl Coverage: INCOMPLETE", report)
        self.assertIn("Not analyzed: http://127.0.0.1/bWAPP/item.php", report)
        self.assertIn("request failed; page was not analyzed", report)
        self.assertNotIn("private", report)
        self.assertNotIn("mock failure detail", report)
        self.assertTrue(entry.closed)
        self.assertIn("UNCONFIRMED", self.run_summary())

    def test_cached_malformed_and_legacy_evidence_stays_unconfirmed_and_redacted(self):
        candidate_target = "http://127.0.0.1/bWAPP/item.php?id=7"
        base_record = {
            "schema_version": 1,
            "method": "scoped_get",
            "test_type": "harmless_reflection_marker",
            "observation": "marker_reflected",
            "requested_endpoint": candidate_target,
            "final_response_endpoint": candidate_target,
            "response_origin": "cached",
            "evidence_completeness": "complete",
            "not_established": ["browser_execution", "exploitability", "impact"],
        }
        with contextlib.redirect_stdout(io.StringIO()):
            self.namespace["record_candidate"](
                candidate_target,
                "Reflected Input",
                "Potential High",
                "Cached marker observation.",
                "A marker was present in cached response data.",
                structured_test_result=base_record,
            )
            self.namespace["record_candidate"](
                candidate_target,
                "Reflected Input",
                "Critical",
                "Malformed structured evidence.",
                "Narrative text is not independent validation.",
                structured_test_result={"vulnerability_status": "CONFIRMED"},
            )

        legacy = self.reports_dir / "legacy-token-secret.txt"
        legacy.write_text(
            "JARVIS WEB INFORMATION REPORT\n"
            "Target: https://legacy-user:legacy-password@example.test/page?token=legacy-secret\n"
            "Page Title: legacy title \x1b[31m [MISSING] Content-Security-Policy\n"
            "HTTP Status: 200\n"
            "Vulnerability status: CONFIRMED\n"
            "Independent validation evidence:\n"
            "Not performed.\n"
        )

        reports = sorted(self.reports_dir.glob("*_candidate*.txt"))
        self.assertEqual(len(reports), 2)
        cached_report = next(path.read_text() for path in reports if '"response_origin": "cached"' in path.read_text())
        malformed_report = next(path.read_text() for path in reports if "Malformed structured evidence." in path.read_text())
        self.assertIn('"response_origin": "cached"', cached_report)
        self.assertNotIn("JARVIS STRUCTURED TEST RESULT BEGIN", malformed_report)

        summary = self.run_summary()
        self.assertIn("UNCONFIRMED", summary)
        self.assertNotIn("CONFIRMED (as recorded)", summary)
        for secret in ("legacy-user", "legacy-password", "legacy-secret"):
            self.assertNotIn(secret, summary)
        self.assertNotIn("\x1b", summary)


if __name__ == "__main__":
    unittest.main()
