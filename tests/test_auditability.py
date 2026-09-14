from __future__ import annotations

from benchmarks.auditability import run_auditability_study


def test_bcp1_closes_measured_auditability_gap() -> None:
    result = run_auditability_study()
    matrix = result["claim_matrix"]
    assert matrix["access_log"]["verified_claim_count"] == 0
    assert matrix["signed_line_log"]["verified_claim_count"] == 1
    assert matrix["bcp1_bundle"]["verified_claim_count"] == 5
    assert result["record_reduction_vs_access_log"] >= 10_000
    assert result["byte_reduction_vs_access_log"] >= 100
    assert result["byte_reduction_vs_signed_log"] >= 100

