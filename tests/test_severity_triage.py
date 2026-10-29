"""Synthetic tests for conservative evidence-based severity triage."""

import ast
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_triage():
    source_path = PROJECT_ROOT / "jarvis.py"
    tree = ast.parse(source_path.read_text())
    names = {"_triage_static_severity", "_source_flow_severity_lines"}
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    namespace = {}
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                str(source_path), "exec"),
        namespace,
    )
    return namespace["_triage_static_severity"], namespace["_source_flow_severity_lines"]


class SeverityTriageTests(unittest.TestCase):
    def setUp(self):
        self.triage, self.static_report_lines = load_triage()

    def complete_evidence(self, **overrides):
        evidence = {
            "vulnerability_class": "SQL injection",
            "source_locations": ["app.php:10"],
            "sink_locations": ["app.php:20"],
            "impact": "serious",
            "exploitability": "demonstrated",
            "trust_boundary": "cross-tenant merchant data",
            "authentication": "none",
            "in_scope": True,
            "controls_reviewed": True,
            "controls_effective": False,
        }
        evidence.update(overrides)
        return evidence

    def test_explicit_evidence_maps_to_each_supported_severity_tier(self):
        cases = (
            ({"impact": "severe"}, "Critical"),
            ({"impact": "serious", "authentication": "standard"}, "High"),
            ({"impact": "moderate"}, "Medium"),
            ({"impact": "low"}, "Low"),
            ({"impact": "low", "controls_effective": True}, "Informational"),
        )
        for overrides, expected in cases:
            with self.subTest(expected=expected):
                result = self.triage(self.complete_evidence(**overrides))
                self.assertEqual(result["severity"], expected)
                self.assertTrue(result["rationale"])
                self.assertIn(result["confidence"], {"High", "Medium"})

    def test_static_source_to_sink_pattern_alone_needs_review(self):
        result = self.triage({
            "vulnerability_class": "cross-site scripting",
            "source_locations": ["widget.js:1"],
            "sink_locations": ["widget.js:3"],
            "impact": None,
            "exploitability": "pattern_only",
            "trust_boundary": None,
            "authentication": None,
            "in_scope": None,
            "controls_reviewed": False,
            "controls_effective": None,
        })
        self.assertEqual(result["severity"], "NEEDS_REVIEW")
        self.assertIn("do not demonstrate exploitability", result["rationale"])

    def test_missing_evidence_or_out_of_scope_target_needs_review(self):
        missing = self.triage({"vulnerability_class": "authorization"})
        out_of_scope = self.triage(self.complete_evidence(in_scope=False))
        self.assertEqual(missing["severity"], "NEEDS_REVIEW")
        self.assertIn("missing or invalid evidence", missing["rationale"])
        self.assertEqual(out_of_scope["severity"], "NEEDS_REVIEW")
        self.assertIn("in-scope status is not established", out_of_scope["rationale"])
        malformed_location = self.triage(self.complete_evidence(source_locations=[""]))
        self.assertEqual(malformed_location["severity"], "NEEDS_REVIEW")

    def test_critical_requires_severe_proven_cross_tenant_unauthenticated_impact(self):
        base = self.complete_evidence(impact="severe")
        self.assertEqual(self.triage(base)["severity"], "Critical")
        self.assertEqual(
            self.triage(self.complete_evidence(impact="severe", authentication="low"))["severity"],
            "High",
        )
        self.assertEqual(
            self.triage(self.complete_evidence(impact="severe", trust_boundary="same-user data"))["severity"],
            "High",
        )

    def test_unreviewed_or_effective_controls_prevent_overstated_tier(self):
        unreviewed = self.triage(self.complete_evidence(controls_reviewed=False))
        protected = self.triage(self.complete_evidence(controls_effective=True, impact="serious"))
        self.assertEqual(unreviewed["severity"], "NEEDS_REVIEW")
        self.assertEqual(protected["severity"], "NEEDS_REVIEW")

    def test_static_report_keeps_candidate_unconfirmed_and_severity_uncertain(self):
        lines = self.static_report_lines(
            "unsafe HTML rendering", ["app.js:1"], ["app.js:3"]
        )
        report = "\n".join(lines)
        self.assertIn("Severity: NEEDS_REVIEW", report)
        self.assertIn("Vulnerability status remains UNCONFIRMED", report)
        self.assertIn("impact", report)
        self.assertIn("authentication", report)
        self.assertIn("scope", report)
        self.assertIn("IDOR", report)
        self.assertIn("not generally analyzed", report)


if __name__ == "__main__":
    unittest.main()
