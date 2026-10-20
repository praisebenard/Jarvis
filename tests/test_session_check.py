import ast
import contextlib
import ipaddress
import io
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

import requests


class SessionCheckTests(unittest.TestCase):
    def test_request_error_returns_false(self):
        source_path = Path(__file__).resolve().parents[1] / "jarvis.py"
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        scope_file = Path(temp_dir.name) / "scope.txt"
        scope_file.write_text("ALLOW http://127.0.0.1:80/bWAPP/*\n")
        tree = ast.parse(source_path.read_text())
        functions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name in {
                "load_scope",
                "_parse_scope_url",
                "_scope_path_matches",
                "check_scope",
                "scoped_get",
                "get_url",
                "check_bWAPP_session",
            }
        ]
        isolated_module = ast.Module(body=functions, type_ignores=[])
        namespace = {
            "Path": Path,
            "urljoin": urljoin,
            "urlsplit": urlsplit,
            "unquote": unquote,
            "ipaddress": ipaddress,
            "re": re,
            "requests": requests,
            "SCOPE_FILE": scope_file,
            "_ACTIVE_AUDIT_REQUEST_BUDGET": None,
        }
        exec(
            compile(
                ast.fix_missing_locations(isolated_module),
                str(source_path),
                "exec",
            ),
            namespace,
        )

        class FailingSession:
            def get(self, *args, **kwargs):
                raise requests.RequestException("lab unavailable")

        namespace["session"] = FailingSession()

        with contextlib.redirect_stdout(io.StringIO()):
            result = namespace["check_bWAPP_session"]()

        self.assertIs(result, False)


if __name__ == "__main__":
    unittest.main()
