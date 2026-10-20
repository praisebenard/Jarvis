import ast
import contextlib
import hashlib
import io
import ipaddress
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote, quote_from_bytes, unquote, urljoin, urlsplit, urlunsplit

import requests


class FakeResponse:
    def __init__(self, url, status_code=200, location=None):
        self.url = url
        self.status_code = status_code
        self.headers = {"Location": location} if location else {}
        self.is_redirect = location is not None
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
        return self.responses.pop(0)


class ScopeRedirectTests(unittest.TestCase):
    def setUp(self):
        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        tree = ast.parse(source_path.read_text())
        functions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name in {
                "load_scope", "_parse_scope_url", "_scope_path_matches",
                "check_scope", "scoped_get", "get_url",
                "_safe_report_parameter_name", "_render_report_endpoint",
                "_render_report_target",
            }
        ]
        isolated_module = ast.Module(body=functions, type_ignores=[])
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scope_file = Path(self.temp_dir.name) / "scope.txt"
        self.scope_file.write_text(
            "ALLOW http://127.0.0.1:80/bWAPP/*\n"
            "EXCLUDE http://127.0.0.1:80/bWAPP/admin/*\n"
        )
        self.namespace = {
            "Path": Path,
            "urljoin": urljoin,
            "urlsplit": urlsplit,
            "urlunsplit": urlunsplit,
            "quote": quote,
            "quote_from_bytes": quote_from_bytes,
            "hashlib": hashlib,
            "unquote": unquote,
            "ipaddress": ipaddress,
            "re": re,
            "requests": requests,
            "SCOPE_FILE": self.scope_file,
            "_ACTIVE_AUDIT_REQUEST_BUDGET": None,
        }
        exec(
            compile(
                ast.fix_missing_locations(isolated_module),
                str(source_path),
                "exec",
            ),
            self.namespace,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_scope(self, *rules):
        self.scope_file.write_text("\n".join(rules) + "\n")

    def test_follows_in_scope_relative_redirect(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/", status_code=302, location="home.php"
        )
        final = FakeResponse("http://127.0.0.1/bWAPP/home.php")
        session = FakeSession([first, final])
        self.namespace["session"] = session

        with contextlib.redirect_stdout(io.StringIO()):
            result = self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertIs(result, final)
        self.assertEqual(
            [call[0] for call in session.calls],
            ["http://127.0.0.1/bWAPP/", "http://127.0.0.1/bWAPP/home.php"],
        )
        self.assertTrue(
            all(not call[1]["allow_redirects"] for call in session.calls)
        )
        self.assertTrue(first.closed)

    def test_blocks_out_of_scope_redirect_before_request(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/",
            status_code=302,
            location="http://example.com/",
        )
        session = FakeSession([first])
        self.namespace["session"] = session

        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(requests.RequestException):
                self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(len(session.calls), 1)
        self.assertTrue(first.closed)

    def test_scope_check_uses_actual_hostname_with_user_information(self):
        with contextlib.redirect_stdout(io.StringIO()):
            allowed = self.namespace["check_scope"](
                "http://127.0.0.1@outside.example/"
            )

        self.assertFalse(allowed)

    def test_disallowed_same_host_port_is_blocked_before_request(self):
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1:8080/bWAPP/")

        self.assertEqual(session.calls, [])

    def test_omitted_standard_port_matches_explicit_scope_rule(self):
        self.write_scope("ALLOW https://example.test:443/app/*")

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.namespace["check_scope"]("https://example.test/app/page"))
            self.assertFalse(self.namespace["check_scope"]("https://example.test:444/app/page"))

    def test_excluded_path_is_blocked_before_request_and_exclusion_wins(self):
        self.write_scope(
            "EXCLUDE http://127.0.0.1:80/bWAPP/admin/*",
            "ALLOW http://127.0.0.1:80/bWAPP/*",
        )
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/admin/delete.php")

        self.assertEqual(session.calls, [])

    def test_repeated_slash_initial_path_is_blocked_before_request(self):
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"](
                "http://127.0.0.1/bWAPP//admin/delete.php"
            )

        self.assertEqual(session.calls, [])

    def test_repeated_slash_redirect_path_is_blocked_and_response_closed(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/",
            status_code=302,
            location="/bWAPP//admin/delete.php",
        )
        session = FakeSession([first])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(len(session.calls), 1)
        self.assertTrue(first.closed)

    def test_repeated_slash_in_scope_rule_invalidates_configuration(self):
        self.write_scope(
            "ALLOW http://127.0.0.1:80/bWAPP/*",
            "EXCLUDE http://127.0.0.1:80/bWAPP//admin/*",
        )
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(session.calls, [])

    def test_query_string_repeated_slashes_do_not_change_path_scope_match(self):
        url = (
            "http://127.0.0.1/bWAPP/home.php?"
            "next=//admin/delete.php&encoded=%25252Fadmin"
        )
        response = FakeResponse(url)
        session = FakeSession([response])
        self.namespace["session"] = session

        result = self.namespace["scoped_get"](url)

        self.assertIs(result, response)
        self.assertEqual([call[0] for call in session.calls], [url])

    def test_nested_encoded_path_boundaries_are_rejected_in_rules_targets_and_redirects(self):
        nested_paths = (
            "%25252Fadmin",
            "%25255Cadmin",
            "%25252e%25252e/admin",
        )

        for nested_path in nested_paths:
            with self.subTest(nested_path=nested_path):
                self.write_scope(
                    "ALLOW http://127.0.0.1:80/bWAPP/*",
                    f"EXCLUDE http://127.0.0.1:80/bWAPP/{nested_path}/*",
                )
                session = FakeSession([])
                self.namespace["session"] = session
                with self.assertRaises(requests.RequestException):
                    self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")
                self.assertEqual(session.calls, [])

                self.write_scope(
                    "ALLOW http://127.0.0.1:80/bWAPP/*",
                    "EXCLUDE http://127.0.0.1:80/bWAPP/admin/*",
                )
                session = FakeSession([])
                self.namespace["session"] = session
                target = f"http://127.0.0.1/bWAPP/{nested_path}"
                with self.assertRaises(requests.RequestException):
                    self.namespace["scoped_get"](target)
                self.assertEqual(session.calls, [])

                redirect = FakeResponse(
                    "http://127.0.0.1/bWAPP/",
                    status_code=302,
                    location=f"/bWAPP/{nested_path}",
                )
                session = FakeSession([redirect])
                self.namespace["session"] = session
                with self.assertRaises(requests.RequestException):
                    self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")
                self.assertEqual(len(session.calls), 1)
                self.assertTrue(redirect.closed)

    def test_nested_encoded_query_text_and_ordinary_path_remain_allowed(self):
        url = (
            "http://127.0.0.1/bWAPP/home.php?"
            "next=%25252Fadmin&return=%25255Cprivate"
        )
        response = FakeResponse(url)
        session = FakeSession([response])
        self.namespace["session"] = session

        result = self.namespace["scoped_get"](url)

        self.assertIs(result, response)
        self.assertEqual([call[0] for call in session.calls], [url])

    def test_path_that_does_not_stabilize_within_eight_decodes_is_denied_before_request(self):
        safe_segment = "%61"
        for _ in range(9):
            safe_segment = safe_segment.replace("%", "%25")
        target = f"http://127.0.0.1/bWAPP/{safe_segment}"
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"](target)

        self.assertEqual(session.calls, [])

    def test_once_decoded_safe_path_matches_scope_and_original_url_is_requested(self):
        self.write_scope("ALLOW http://127.0.0.1:80/bWAPP/a.php")
        url = "http://127.0.0.1/bWAPP/%61.php"
        response = FakeResponse(url)
        session = FakeSession([response])
        self.namespace["session"] = session

        result = self.namespace["scoped_get"](url)

        self.assertIs(result, response)
        self.assertEqual([call[0] for call in session.calls], [url])

    def test_redirect_into_excluded_path_is_blocked_and_response_closed(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/",
            status_code=302,
            location="/bWAPP/admin/delete.php",
        )
        session = FakeSession([first])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(len(session.calls), 1)
        self.assertTrue(first.closed)

    def test_malformed_scope_rule_invalidates_entire_configuration(self):
        self.write_scope(
            "ALLOW http://127.0.0.1:80/bWAPP/*",
            "127.0.0.1",
        )
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(session.calls, [])

    def test_scope_rule_requires_an_explicit_path(self):
        self.write_scope("ALLOW http://127.0.0.1:80")
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(session.calls, [])

    def test_malformed_url_is_denied_before_request(self):
        session = FakeSession([])
        self.namespace["session"] = session

        for url in (
            "http://[::1/bWAPP/",
            "http://127.0.0.1:/bWAPP/",
            "http://127.0.0.1/bWAPP/%GG",
            "http://127.0.0.1/bWAPP/%2Fadmin/",
            "http://127.0.0.1/bWAPP/%252Fadmin/",
            "ftp://127.0.0.1/bWAPP/",
            " http://127.0.0.1/bWAPP/ ",
        ):
            with self.subTest(url=url), self.assertRaises(requests.RequestException):
                self.namespace["scoped_get"](url)

        self.assertEqual(session.calls, [])

    def test_malformed_redirect_destination_is_closed_and_blocked(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/",
            status_code=302,
            location="http://[::1/bWAPP/",
        )
        session = FakeSession([first])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(len(session.calls), 1)
        self.assertTrue(first.closed)

    def test_redirect_limit_and_response_cleanup_are_preserved(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/", status_code=302, location="home.php"
        )
        second = FakeResponse(
            "http://127.0.0.1/bWAPP/home.php", status_code=302, location="next.php"
        )
        session = FakeSession([first, second])
        session.max_redirects = 1
        self.namespace["session"] = session

        with self.assertRaises(requests.TooManyRedirects) as raised:
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(len(session.calls), 2)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)
        self.assertIs(raised.exception.response, second)

    def test_audit_request_budget_counts_redirect_hops_before_sending_next_request(self):
        redirect = FakeResponse(
            "http://127.0.0.1/bWAPP/", status_code=302, location="home.php"
        )
        session = FakeSession([redirect])
        self.namespace["session"] = session
        budget = {"limit": 1, "used": 0, "exhausted": False}
        self.namespace["_ACTIVE_AUDIT_REQUEST_BUDGET"] = budget

        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(requests.RequestException, "budget exhausted"):
                self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(len(session.calls), 1)
        self.assertEqual(budget["used"], 1)
        self.assertTrue(budget["exhausted"])
        self.assertTrue(redirect.closed)


if __name__ == "__main__":
    unittest.main()
