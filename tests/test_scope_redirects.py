import ast
import contextlib
import hashlib
import io
import ipaddress
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace
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


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        self.sleeps.append(duration)
        self.now += duration


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
                "_session_for_url",
                "_authorized_scope_context",
                "_hackerone_handle_for_url",
                "_remove_hackerone_header",
                "_keep_safe_redirect_headers",
                "_snapshot_http_response_metadata",
                "_attach_http_response_metadata",
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
        self.clock = FakeClock()
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
            "SimpleNamespace": SimpleNamespace,
            "os": os,
            "time": SimpleNamespace(
                monotonic=self.clock.monotonic,
                sleep=self.clock.sleep,
            ),
            "MAX_REDIRECT_HOPS": 5,
            "_HTTP_SESSIONS": {},
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

    def capture_prepared_redirect(
        self, rules, start_url, location, headers=None, base_session_setup=None
    ):
        self.write_scope(*rules)
        base_session = requests.Session()
        if base_session_setup is not None:
            base_session_setup(base_session)
        self.namespace["session"] = base_session
        prepared_requests = []
        responses = []

        def mocked_send(request_session, prepared_request, **kwargs):
            prepared_requests.append((request_session, prepared_request))
            redirect_location = location if len(prepared_requests) == 1 else None
            response = FakeResponse(
                prepared_request.url,
                status_code=302 if redirect_location else 200,
                location=redirect_location,
            )
            responses.append(response)
            return response

        with patch.object(requests.Session, "send", new=mocked_send):
            self.namespace["scoped_get"](start_url, headers=headers or {})
        return base_session, prepared_requests, responses

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

    def test_hackerone_handle_is_opt_in_and_only_sent_to_configured_scoped_asset(self):
        self.write_scope(
            "ALLOW http://127.0.0.1:80/bWAPP/*",
            "ALLOW http://other.example:80/app/*",
        )
        session = FakeSession([
            FakeResponse("http://127.0.0.1/bWAPP/"),
            FakeResponse("http://other.example/app/home"),
        ])
        self.namespace["session"] = session
        with patch.dict(os.environ, {
            "JARVIS_HACKERONE_HANDLE": "researcher-handle",
            "JARVIS_HACKERONE_ASSETS": "http://127.0.0.1:80/bWAPP/*",
        }, clear=False):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")
            self.namespace["scoped_get"]("http://other.example/app/home")

        first_headers = session.calls[0][1]["headers"]
        second_headers = session.calls[1][1].get("headers", {})
        self.assertEqual(first_headers["X-HackerOne-Handle"], "researcher-handle")
        self.assertNotIn("X-HackerOne-Handle", second_headers)

    def test_hackerone_header_is_not_added_from_untrusted_caller_headers_by_default(self):
        session = FakeSession([FakeResponse("http://127.0.0.1/bWAPP/")])
        self.namespace["session"] = session
        with patch.dict(os.environ, {}, clear=True):
            self.namespace["scoped_get"](
                "http://127.0.0.1/bWAPP/",
                headers={"x-hackerone-handle": "unapproved-value", "X-Test": "ok"},
            )

        headers = session.calls[0][1]["headers"]
        self.assertNotIn("x-hackerone-handle", headers)
        self.assertNotIn("X-HackerOne-Handle", headers)
        self.assertEqual(headers["X-Test"], "ok")

    def test_hackerone_header_is_not_forwarded_to_redirect_destination(self):
        self.write_scope(
            "ALLOW http://127.0.0.1:80/bWAPP/*",
            "ALLOW http://other.example:80/app/*",
        )
        redirect = FakeResponse(
            "http://127.0.0.1/bWAPP/start",
            status_code=302,
            location="http://other.example/app/final",
        )
        final = FakeResponse("http://other.example/app/final")
        session = FakeSession([redirect, final])
        self.namespace["session"] = session
        with patch.dict(os.environ, {
            "JARVIS_HACKERONE_HANDLE": "researcher-handle",
            "JARVIS_HACKERONE_ASSETS": "http://127.0.0.1:80/bWAPP/*",
        }, clear=False):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/start")

        self.assertEqual(len(session.calls), 2)
        self.assertIn("X-HackerOne-Handle", session.calls[0][1]["headers"])
        self.assertNotIn("X-HackerOne-Handle", session.calls[1][1].get("headers", {}))
        self.assertTrue(redirect.closed)

    def test_session_default_handle_is_removed_and_redirect_rechecks_asset_path(self):
        self.write_scope("ALLOW http://127.0.0.1:80/bWAPP/*")
        real_session = requests.Session()
        real_session.headers["x-hackerone-handle"] = "stale-session-default"
        prepared_requests = []
        redirect = FakeResponse(
            "http://127.0.0.1/bWAPP/selected/start",
            status_code=302,
            location="/bWAPP/unconfigured/final",
        )
        final = FakeResponse("http://127.0.0.1/bWAPP/unconfigured/final")
        responses = [redirect, final]

        def prepare_without_sending(url, **kwargs):
            request = requests.Request("GET", url, headers=kwargs.get("headers"))
            prepared_requests.append(real_session.prepare_request(request))
            return responses.pop(0)

        real_session.get = prepare_without_sending
        self.namespace["session"] = real_session
        with patch.dict(os.environ, {
            "JARVIS_HACKERONE_HANDLE": "configured-handle",
            "JARVIS_HACKERONE_ASSETS": "http://127.0.0.1:80/bWAPP/selected/*",
        }, clear=True):
            self.namespace["scoped_get"](
                "http://127.0.0.1/bWAPP/selected/start",
                headers={"X-HackerOne-Handle": "caller-injected"},
            )

        self.assertEqual(len(prepared_requests), 2)
        self.assertEqual(
            prepared_requests[0].headers.get("X-HackerOne-Handle"),
            "configured-handle",
        )
        self.assertNotIn("X-HackerOne-Handle", prepared_requests[1].headers)
        self.assertNotIn("x-hackerone-handle", real_session.headers)
        self.assertTrue(redirect.closed)

    def test_sensitive_headers_and_cookies_are_dropped_on_cross_origin_redirect(self):
        source_url = "http://127.0.0.1/bWAPP/start"
        destination_url = "http://other.example/app/final"
        sensitive = {
            "Authorization": "Bearer test-only-value",
            "X-Auth-Key": "test-only-auth-key",
            "X-Auth-Token": "test-only-auth-token",
            "X-Access-Token": "test-only-access-token",
            "X-Session-ID": "test-only-session-id",
            "X-Password": "test-only-password",
            "Proxy-Authorization": "Basic test-only-proxy-value",
            "X-Test-Trace": "preserve-me",
            "User-Agent": "JARVIS-Offline-Test/1.0",
        }
        base_session, requests_seen, responses = self.capture_prepared_redirect(
            (
                "ALLOW http://127.0.0.1:80/bWAPP/*",
                "ALLOW http://other.example:80/app/*",
            ),
            source_url,
            destination_url,
            sensitive,
            base_session_setup=lambda selected: (
                selected.headers.update({
                    "X-API-Key": "session-default-api-key",
                }),
                selected.cookies.set(
                    "wide_test_cookie", "local-test-value",
                    domain="127.0.0.1", path="/",
                ),
            ),
        )

        self.assertEqual(len(requests_seen), 2)
        source_session, source_request = requests_seen[0]
        destination_session, destination_request = requests_seen[1]
        self.assertIsNot(source_session, destination_session)
        self.assertEqual(source_request.headers.get("Authorization"), sensitive["Authorization"])
        self.assertEqual(
            source_request.headers.get("Proxy-Authorization"),
            sensitive["Proxy-Authorization"],
        )
        self.assertIn("wide_test_cookie=local-test-value", source_request.headers.get("Cookie", ""))
        self.assertEqual(
            source_request.headers.get("X-Auth-Key"), "test-only-auth-key"
        )
        self.assertEqual(
            source_request.headers.get("X-API-Key"), "session-default-api-key"
        )
        for header in (
            "Authorization", "Cookie", "Proxy-Authorization", "X-API-Key",
            "X-Auth-Key", "X-Auth-Token", "X-Access-Token", "X-Session-ID",
            "X-Password",
        ):
            self.assertNotIn(header, destination_request.headers)
        self.assertEqual(destination_request.headers.get("X-Test-Trace"), "preserve-me")
        self.assertEqual(
            destination_request.headers.get("User-Agent"),
            "JARVIS-Offline-Test/1.0",
        )
        self.assertTrue(responses[0].closed)

    def test_sensitive_headers_are_dropped_when_redirect_changes_scope_root(self):
        _, prepared_requests, responses = self.capture_prepared_redirect(
            (
                "ALLOW http://127.0.0.1:80/bWAPP/*",
                "ALLOW http://127.0.0.1:80/other-app/*",
            ),
            "http://127.0.0.1/bWAPP/start",
            "/other-app/final",
            {
                "Authorization": "Bearer test-only-value",
                "Cookie": "session=test-only-cookie",
                "Proxy-Authorization": "Basic test-only-proxy-value",
                "X-Session-ID": "test-only-session-id",
                "X-Auth-Key": "test-only-auth-key",
                "X-Auth-Token": "test-only-auth-token",
                "X-Access-Token": "test-only-access-token",
                "X-API-Key": "test-only-api-key",
                "X-Test-Trace": "preserve-me",
                "User-Agent": "JARVIS-Offline-Test/1.0",
            },
        )

        self.assertEqual(len(prepared_requests), 2)
        self.assertIsNot(prepared_requests[0][0], prepared_requests[1][0])
        for header in (
            "Authorization", "Cookie", "Proxy-Authorization", "X-Session-ID",
            "X-Auth-Key", "X-Auth-Token", "X-Access-Token", "X-API-Key",
        ):
            self.assertNotIn(header, prepared_requests[1][1].headers)
        self.assertEqual(
            prepared_requests[1][1].headers.get("X-Test-Trace"), "preserve-me"
        )
        self.assertEqual(
            prepared_requests[1][1].headers.get("User-Agent"),
            "JARVIS-Offline-Test/1.0",
        )
        self.assertTrue(responses[0].closed)

    def test_sensitive_headers_remain_on_redirect_within_same_scope_root(self):
        _, prepared_requests, _ = self.capture_prepared_redirect(
            ("ALLOW http://127.0.0.1:80/bWAPP/*",),
            "http://127.0.0.1/bWAPP/start",
            "/bWAPP/final",
            {
                "Authorization": "Bearer test-only-value",
                "Cookie": "session=test-only-cookie",
                "X-Auth-Key": "test-only-auth-key",
                "X-Test-Trace": "preserve-me",
            },
        )

        self.assertEqual(len(prepared_requests), 2)
        self.assertIs(prepared_requests[0][0], prepared_requests[1][0])
        self.assertEqual(
            prepared_requests[1][1].headers.get("Authorization"),
            "Bearer test-only-value",
        )
        self.assertEqual(
            prepared_requests[1][1].headers.get("Cookie"),
            "session=test-only-cookie",
        )
        self.assertEqual(
            prepared_requests[1][1].headers.get("X-Auth-Key"),
            "test-only-auth-key",
        )
        self.assertEqual(
            prepared_requests[1][1].headers.get("X-Test-Trace"), "preserve-me"
        )

    def test_explicit_cookies_and_auth_are_dropped_across_scope_boundary(self):
        self.write_scope(
            "ALLOW http://127.0.0.1:80/bWAPP/*",
            "ALLOW http://127.0.0.1:80/other-app/*",
        )
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/start",
            status_code=302,
            location="/other-app/final",
        )
        final = FakeResponse("http://127.0.0.1/other-app/final")
        session = FakeSession([first, final])
        self.namespace["session"] = session

        self.namespace["scoped_get"](
            "http://127.0.0.1/bWAPP/start",
            cookies={"explicit_cookie": "test-cookie-value"},
            auth=("test-user", "test-password"),
        )

        self.assertEqual(len(session.calls), 2)
        self.assertEqual(
            session.calls[0][1]["cookies"],
            {"explicit_cookie": "test-cookie-value"},
        )
        self.assertEqual(session.calls[0][1]["auth"], ("test-user", "test-password"))
        self.assertNotIn("cookies", session.calls[1][1])
        self.assertNotIn("auth", session.calls[1][1])

    def test_explicit_cookies_and_auth_remain_within_scope_root(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/start",
            status_code=302,
            location="/bWAPP/final",
        )
        final = FakeResponse("http://127.0.0.1/bWAPP/final")
        session = FakeSession([first, final])
        self.namespace["session"] = session

        self.namespace["scoped_get"](
            "http://127.0.0.1/bWAPP/start",
            cookies={"explicit_cookie": "test-cookie-value"},
            auth=("test-user", "test-password"),
        )

        self.assertEqual(len(session.calls), 2)
        for _url, kwargs in session.calls:
            self.assertEqual(
                kwargs["cookies"], {"explicit_cookie": "test-cookie-value"}
            )
            self.assertEqual(kwargs["auth"], ("test-user", "test-password"))

    def test_hackerone_header_config_fails_closed_for_malformed_assets(self):
        self.write_scope("ALLOW http://example.test:80/*")
        session = FakeSession([FakeResponse("http://example.test/app/page")])
        self.namespace["session"] = session

        with patch.dict(os.environ, {
            "JARVIS_HACKERONE_HANDLE": "configured-handle",
            "JARVIS_HACKERONE_ASSETS": "http://example.test/app/*",
        }, clear=True):
            self.namespace["scoped_get"]("http://example.test/app/page")

        self.assertEqual(len(session.calls), 1)
        self.assertNotIn(
            "X-HackerOne-Handle", session.calls[0][1].get("headers", {})
        )

    def test_hackerone_asset_matching_normalizes_host_port_and_respects_path_boundary(self):
        self.write_scope("ALLOW http://example.test:80/*")
        session = FakeSession([
            FakeResponse("http://EXAMPLE.TEST/app/page"),
            FakeResponse("http://EXAMPLE.TEST/application/page"),
        ])
        self.namespace["session"] = session

        with patch.dict(os.environ, {
            "JARVIS_HACKERONE_HANDLE": "configured-handle",
            "JARVIS_HACKERONE_ASSETS": "http://example.test:80/app/*",
        }, clear=True):
            self.namespace["scoped_get"]("http://EXAMPLE.TEST/app/page")
            self.namespace["scoped_get"]("http://EXAMPLE.TEST/application/page")
            with self.assertRaises(requests.RequestException):
                self.namespace["scoped_get"]("http://example.test:8080/app/page")

        self.assertEqual(len(session.calls), 2)
        self.assertEqual(
            session.calls[0][1]["headers"]["X-HackerOne-Handle"],
            "configured-handle",
        )
        self.assertNotIn(
            "X-HackerOne-Handle", session.calls[1][1].get("headers", {})
        )

    def test_hackerone_header_is_not_sent_after_out_of_scope_redirect(self):
        redirect = FakeResponse(
            "http://127.0.0.1/bWAPP/start",
            status_code=302,
            location="https://outside.example/collect",
        )
        session = FakeSession([redirect])
        self.namespace["session"] = session
        with patch.dict(os.environ, {
            "JARVIS_HACKERONE_HANDLE": "researcher-handle",
            "JARVIS_HACKERONE_ASSETS": "http://127.0.0.1:80/bWAPP/*",
        }, clear=False):
            with self.assertRaises(requests.RequestException):
                self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/start")

        self.assertEqual(len(session.calls), 1)
        self.assertIn("X-HackerOne-Handle", session.calls[0][1]["headers"])
        self.assertTrue(redirect.closed)

    def test_active_scope_does_not_include_anthropic_or_other_external_hosts(self):
        active_scope = Path(__file__).resolve().parents[1] / "scope.txt"
        rules = [
            line.strip() for line in active_scope.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

        self.assertTrue(rules)
        self.assertTrue(all("127.0.0.1" in line for line in rules))
        self.assertFalse(any("anthropic" in line.casefold() for line in rules))

    def test_redirect_loop_stops_at_small_hop_limit_and_closes_every_response(self):
        responses = [
            FakeResponse(
                "http://127.0.0.1/bWAPP/loop.php",
                status_code=302,
                location="/bWAPP/loop.php",
            )
            for _ in range(6)
        ]
        session = FakeSession(responses)
        self.namespace["session"] = session

        with self.assertRaises(requests.TooManyRedirects):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/loop.php")

        self.assertEqual(len(session.calls), 6)
        self.assertTrue(all(response.closed for response in responses))

    def test_shared_budget_paces_each_request_including_redirect_hops(self):
        first = FakeResponse(
            "http://127.0.0.1/bWAPP/first.php",
            status_code=302,
            location="/bWAPP/second.php",
        )
        second = FakeResponse(
            "http://127.0.0.1/bWAPP/second.php",
            status_code=302,
            location="/bWAPP/third.php",
        )
        final = FakeResponse("http://127.0.0.1/bWAPP/third.php")
        session = FakeSession([first, second, final])
        self.namespace["session"] = session
        budget = {
            "limit": 3,
            "used": 0,
            "exhausted": False,
            "minimum_interval": 0.25,
            "last_request_at": None,
        }
        self.namespace["_ACTIVE_AUDIT_REQUEST_BUDGET"] = budget

        result = self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/first.php")

        self.assertIs(result, final)
        self.assertEqual(budget["used"], 3)
        self.assertEqual(self.clock.sleeps, [0.25, 0.25])
        self.assertEqual(len(session.calls), 3)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

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

    def test_missing_scope_file_fails_closed_before_request(self):
        missing_scope = self.scope_file.with_name("missing-scope.txt")
        self.namespace["SCOPE_FILE"] = missing_scope
        session = FakeSession([])
        self.namespace["session"] = session

        with self.assertRaises(requests.RequestException):
            self.namespace["scoped_get"]("http://127.0.0.1/bWAPP/")

        self.assertEqual(session.calls, [])

    def test_unreadable_scope_path_fails_closed_before_request(self):
        unreadable_scope = Path(self.temp_dir.name) / "scope-directory"
        unreadable_scope.mkdir()
        self.namespace["SCOPE_FILE"] = unreadable_scope
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

    def test_scope_configuration_is_resolved_from_project_directory(self):
        project_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as unrelated_cwd:
            result = subprocess.run(
                [sys.executable, str(project_root / "jarvis.py")],
                input="check http://127.0.0.1/bWAPP/\nexit\n",
                text=True,
                capture_output=True,
                cwd=unrelated_cwd,
                timeout=10,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("is in the authorized scope", result.stdout)


if __name__ == "__main__":
    unittest.main()
