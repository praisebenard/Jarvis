import ast
import contextlib
import ipaddress
import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, quote_from_bytes, unquote, urljoin, urlsplit, urlunsplit

import requests


class SessionCheckTests(unittest.TestCase):
    def _load_session_check(self):
        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        scope_file = Path(temp_dir.name) / "scope.txt"
        scope_file.write_text(
            "ALLOW http://127.0.0.1:80/bWAPP/*\n"
            "ALLOW http://127.0.0.1:80/other-app/*\n"
        )
        tree = ast.parse(source_path.read_text())
        functions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name in {
                "load_scope",
                "_parse_scope_url",
                "_scope_path_matches",
                "_session_for_url",
                "_authorized_scope_context",
                "_hackerone_handle_for_url",
                "_remove_hackerone_header",
                "_keep_safe_redirect_headers",
                "_snapshot_http_response_metadata",
                "_attach_http_response_metadata",
                "_render_report_endpoint",
                "check_scope",
                "scoped_get",
                "get_url",
                "check_bWAPP_session",
                "set_session_cookie",
            }
        ]
        namespace = {
            "Path": Path,
            "urljoin": urljoin,
            "urlsplit": urlsplit,
            "urlunsplit": urlunsplit,
            "quote": quote,
            "quote_from_bytes": quote_from_bytes,
            "unquote": unquote,
            "SimpleNamespace": SimpleNamespace,
            "ipaddress": ipaddress,
            "re": re,
            "requests": requests,
            "os": os,
            "SCOPE_FILE": scope_file,
            "_ACTIVE_AUDIT_REQUEST_BUDGET": None,
            "_HTTP_SESSIONS": {},
            "MAX_REDIRECT_HOPS": 5,
            "session": requests.Session(),
        }
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                str(source_path),
                "exec",
            ),
            namespace,
        )
        return namespace

    def test_request_error_returns_false(self):
        namespace = self._load_session_check()

        class FailingSession:
            def get(self, *args, **kwargs):
                raise requests.RequestException("lab unavailable")

        namespace["session"] = FailingSession()

        with contextlib.redirect_stdout(io.StringIO()):
            result = namespace["check_bWAPP_session"]()

        self.assertIs(result, False)

    def test_response_is_closed_for_authenticated_and_login_results(self):
        class Response:
            def __init__(self, url):
                self.url = url
                self.is_redirect = False
                self.headers = {}
                self.closed = False

            def close(self):
                self.closed = True

        for url, expected in (
            ("http://127.0.0.1/bWAPP/home.php", True),
            ("http://127.0.0.1/bWAPP/login.php", False),
        ):
            with self.subTest(url=url):
                namespace = self._load_session_check()
                response = Response(url)

                class Session:
                    def get(self, *args, **kwargs):
                        return response

                namespace["session"] = Session()
                with contextlib.redirect_stdout(io.StringIO()):
                    result = namespace["check_bWAPP_session"]()

                self.assertIs(result, expected)
                self.assertTrue(response.closed)

    def test_session_cookie_is_isolated_to_authorized_target_scope_and_not_printed(self):
        namespace = self._load_session_check()
        secret = "very-secret-session-value"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            namespace["set_session_cookie"](f"lab_session={secret}")

        lab_session = namespace["_session_for_url"](
            "http://127.0.0.1/bWAPP/index.php"
        )
        other_scope_session = namespace["_session_for_url"](
            "http://127.0.0.1/other-app/index.php"
        )
        same_scope_session = namespace["_session_for_url"](
            "http://127.0.0.1/bWAPP/next.php"
        )
        self.assertIsNot(lab_session, other_scope_session)
        self.assertIs(lab_session, same_scope_session)

        # Model a response cookie with Path=/ without making any HTTP request.
        lab_session.cookies.set(
            "broad_path_test", "local-test-value", domain="127.0.0.1", path="/"
        )
        lab_request = lab_session.prepare_request(
            requests.Request("GET", "http://127.0.0.1/bWAPP/index.php")
        )
        other_request = other_scope_session.prepare_request(
            requests.Request("GET", "http://127.0.0.1/other-app/index.php")
        )

        self.assertIn(secret, lab_request.headers.get("Cookie", ""))
        self.assertNotIn(secret, other_request.headers.get("Cookie", ""))
        self.assertIn("broad_path_test=local-test-value", lab_request.headers.get("Cookie", ""))
        self.assertNotIn("broad_path_test", other_request.headers.get("Cookie", ""))
        self.assertNotIn(secret, output.getvalue())

    def test_session_check_does_not_print_sensitive_request_exception_text(self):
        namespace = self._load_session_check()
        secret = "token=do-not-print"

        class FailingSession:
            def get(self, *args, **kwargs):
                raise requests.RequestException(
                    f"failed while requesting http://127.0.0.1/?{secret}"
                )

        namespace["session"] = FailingSession()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(namespace["check_bWAPP_session"]())

        self.assertNotIn(secret, output.getvalue())


if __name__ == "__main__":
    unittest.main()
