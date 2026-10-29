"""Offline, labeled regression benchmark for the supported JavaScript analyzer subset."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests" / "fixtures" / "js_benchmark"
POSITIVE_MARKER = "Candidate 1: Potential unsafe HTML insertion"


CASES = (
    {
        "category": "direct innerHTML flow", "file": "direct_innerhtml/location_search.js",
        "label": "positive", "rationale": "location.search is assigned directly to innerHTML.",
        "evidence": ("location.search at location_search.js:1", "innerHTML at location_search.js:1"),
    },
    {
        "category": "direct innerHTML flow", "file": "direct_innerhtml/static_markup.js",
        "label": "benign", "rationale": "A fixed literal reaches innerHTML without a recognized browser source.",
        "evidence": ("No complete supported source-to-innerHTML trace detected.",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "aliases and indirect assignments", "file": "aliases/alias_chain.js",
        "label": "positive", "rationale": "A browser hash source passes through two simple aliases to innerHTML.",
        "evidence": (
            "window.location.hash at alias_chain.js:1", "Assignment evidence: Line 2: firstCopy = input",
            "Assignment evidence: Line 3: secondCopy = firstCopy", "innerHTML at alias_chain.js:4",
        ),
    },
    {
        "category": "aliases and indirect assignments", "file": "aliases/disconnected_source.js",
        "label": "benign", "rationale": "A tracked source and an innerHTML sink use different variables.",
        "evidence": ("No complete supported source-to-innerHTML trace detected.",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "aliases and indirect assignments", "file": "aliases/reassigned_alias.js",
        "label": "unresolved", "rationale": "Reassignment invalidates the earlier source alias before the sink.",
        "evidence": ("reassignment of input makes later flows ambiguous",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "URLSearchParams static-key flow", "file": "url_search_params/static_key.js",
        "label": "positive", "rationale": "The supported URLSearchParams(location.search) and static .get key reach innerHTML.",
        "evidence": (
            "location.search at static_key.js:1", "Assignment evidence: Line 1: const params = new URLSearchParams(location.search);",
            'Assignment evidence: Line 2: message = params.get("message")',
            "innerHTML at static_key.js:3",
        ),
    },
    {
        "category": "URLSearchParams static-key flow", "file": "url_search_params/static_query.js",
        "label": "unresolved", "rationale": "A constant query string is not a recognized browser source; the unsupported .get expression is left unresolved.",
        "evidence": ("unsupported URLSearchParams or .get() expression",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "URLSearchParams static-key flow", "file": "url_search_params/unrelated_receiver.js",
        "label": "unresolved", "rationale": "An arbitrary .get receiver is not connected to the recognized URLSearchParams object.",
        "evidence": (".get() receiver unrelated is not connected",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "text-only output", "file": "output_semantics/text_content.js",
        "label": "benign", "rationale": "location.search is assigned to textContent, outside the analyzer's innerHTML sink model.",
        "evidence": ("No complete supported source-to-innerHTML trace detected.",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "misleading names", "file": "misleading_names/static_user_input.js",
        "label": "benign", "rationale": "Variables named userInput and html contain only a local constant, not a supported browser source.",
        "evidence": ("No complete supported source-to-innerHTML trace detected.",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "safe-looking transformations", "file": "transformations/encode_uri_component.js",
        "label": "unresolved", "rationale": "encodeURIComponent is not a documented safe innerHTML transform and the compound call is unsupported.",
        "evidence": ("unsupported assignment expression involving tracked data",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "unsupported syntax", "file": "unsupported_syntax/conditional_sink.js",
        "label": "unresolved", "rationale": "Control flow is outside the line-oriented supported subset, so the trace is withheld.",
        "evidence": ("control flow or compound expression is unsupported",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "unsupported syntax", "file": "unsupported_syntax/template_sink.js",
        "label": "unresolved", "rationale": "Template literal syntax is explicitly unsupported and cannot be interpreted as a safe or unsafe flow.",
        "evidence": ("template literal syntax is unsupported",),
        "no_evidence": (POSITIVE_MARKER,),
    },
    {
        "category": "template literal interpolation",
        "file": "unsupported_syntax/template_simple.js",
        "label": "positive",
        "rationale": "A single variable interpolation carries location.search to innerHTML.",
        "evidence": (
            "location.search at template_simple.js:1",
            "innerHTML at template_simple.js:2",
            "Vulnerability status: UNCONFIRMED",
        ),
    },
)


class JSAnalyzerBenchmarkTests(unittest.TestCase):
    """Measure analyzer behavior only against these labeled synthetic files."""

    def analyze_fixture(self, case):
        fixture = FIXTURE_ROOT / case["file"]
        self.assertTrue(fixture.is_file(), f"missing synthetic fixture: {fixture}")
        # Point the existing CLI at the fixture, but put any generated report
        # into a fresh temporary working directory. The JavaScript is never run.
        with tempfile.TemporaryDirectory(prefix="jarvis-js-benchmark-") as directory:
            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "jarvis.py")],
                input=f"js-flow {fixture.resolve()}\nexit\n",
                text=True,
                capture_output=True,
                cwd=directory,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            reports = list((Path(directory) / "reports").glob("*_js_flow.txt"))
            self.assertEqual(len(reports), 1, result.stdout + result.stderr)
            return reports[0].read_text(encoding="utf-8")

    def test_labeled_synthetic_javascript_benchmark(self):
        fields = ("tp", "tn", "fp", "fn", "unresolved")
        counts = {
            category: {field: 0 for field in fields}
            for category in dict.fromkeys(case["category"] for case in CASES)
        }
        errors = []
        for case in CASES:
            self.assertTrue(case.get("rationale"), f"missing rationale for {case['file']}")
            report = self.analyze_fixture(case)
            for fragment in case["evidence"]:
                if fragment not in report:
                    errors.append(f"{case['file']}: missing expected evidence {fragment!r}")
            for fragment in case.get("no_evidence", ()):
                if fragment in report:
                    errors.append(f"{case['file']}: unexpected evidence {fragment!r}")

            observed = POSITIVE_MARKER in report
            category_counts = counts[case["category"]]
            if case["label"] == "positive":
                category_counts["tp" if observed else "fn"] += 1
                if observed and (
                    "Severity: NEEDS_REVIEW" not in report
                    or "Vulnerability status: UNCONFIRMED" not in report
                ):
                    errors.append(f"{case['file']}: candidate lacks conservative severity/status")
            elif case["label"] == "benign":
                category_counts["fp" if observed else "tn"] += 1
            else:
                category_counts["unresolved"] += 1
                if observed:
                    errors.append(f"{case['file']}: unresolved flow was reported as a candidate")
                if "Unresolved or unsupported evidence:" not in report:
                    errors.append(f"{case['file']}: unresolved case lacks an unresolved report section")

        print("Synthetic JavaScript benchmark only; unresolved cases are excluded from rates:")
        for category, result in counts.items():
            positive_total = result["tp"] + result["fn"]
            benign_total = result["tn"] + result["fp"]
            fp_rate = f"{result['fp'] / benign_total:.0%}" if benign_total else "n/a"
            missed_rate = f"{result['fn'] / positive_total:.0%}" if positive_total else "n/a"
            print(
                f"  {category}: TP={result['tp']} TN={result['tn']} FP={result['fp']} "
                f"FN={result['fn']} unresolved={result['unresolved']} "
                f"FP rate={fp_rate} missed-pattern rate={missed_rate}"
            )

        self.assertEqual(errors, [], "\n".join(errors))
        for category, result in counts.items():
            self.assertEqual(result["fn"], 0, f"{category}: labeled positive pattern was missed")
            self.assertEqual(result["fp"], 0, f"{category}: labeled benign case produced a candidate")


if __name__ == "__main__":
    unittest.main()
