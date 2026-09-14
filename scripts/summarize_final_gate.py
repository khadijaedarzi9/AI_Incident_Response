"""Derive the final-gate summary exclusively from produced artifacts."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "artifacts" / "proof"


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> int:
    junit = ET.parse(PROOF / "junit.xml").getroot()
    suites = [junit] if junit.tag == "testsuite" else list(junit.findall("testsuite"))
    tests = sum(int(suite.attrib.get("tests", 0)) for suite in suites)
    failures = sum(int(suite.attrib.get("failures", 0)) for suite in suites)
    errors = sum(int(suite.attrib.get("errors", 0)) for suite in suites)
    skipped = sum(int(suite.attrib.get("skipped", 0)) for suite in suites)

    coverage = _json(PROOF / "coverage.json")
    scenarios = _json(ROOT / "artifacts" / "scenarios" / "results.json")
    ablations = _json(ROOT / "artifacts" / "benchmark" / "results.json")
    auditability = _json(
        ROOT / "artifacts" / "benchmark" / "auditability.json"
    )
    network = _json(ROOT / "artifacts" / "benchmark" / "network-results.json")

    summary = {
        "schema_version": "bcp1-final-gate-v2",
        "valid": failures == 0 and errors == 0,
        "tests_collected": tests,
        "tests_passed": tests - failures - errors - skipped,
        "tests_failed": failures + errors,
        "tests_skipped": skipped,
        "coverage_percent": coverage["totals"]["percent_covered_display"],
        "judge_scenarios_total": scenarios["scenario_count"],
        "judge_scenarios_passed": sum(
            bool(scenario["passed"]) for scenario in scenarios["results"]
        ),
        "bcp1_ablation_failures": ablations["bcp1_failures"],
        "baseline_ablation_failures": ablations["baseline_failures"],
        "auditability_claims_access_log": auditability["claim_matrix"][
            "access_log"
        ]["verified_claim_count"],
        "auditability_claims_signed_line_log": auditability["claim_matrix"][
            "signed_line_log"
        ]["verified_claim_count"],
        "auditability_claims_bcp1": auditability["claim_matrix"]["bcp1_bundle"][
            "verified_claim_count"
        ],
        "docker_network_probes_total": len(network["results"]),
        "docker_network_probes_passed": sum(
            bool(result["result_matches_expectation"])
            for result in network["results"]
        ),
    }
    if (
        not summary["valid"]
        or summary["judge_scenarios_passed"] != summary["judge_scenarios_total"]
        or summary["bcp1_ablation_failures"] != 0
        or summary["docker_network_probes_passed"]
        != summary["docker_network_probes_total"]
    ):
        raise SystemExit("final-gate artifacts contain a failed check")
    (PROOF / "final-gate-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
