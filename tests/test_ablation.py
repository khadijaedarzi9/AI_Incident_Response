from __future__ import annotations

from benchmarks.ablation import result_document, run_benchmark


def test_every_ablation_fails_and_full_bcp1_passes() -> None:
    results = run_benchmark()
    assert len(results) == 5
    assert {item.scenario_id for item in results} == {
        "canary-alert-without-page",
        "permit-kill-race",
        "unsafe-public-second-hop",
        "evidence-equivocation",
        "request-flood-after-kill",
    }
    assert all(not item.baseline_passed for item in results)
    assert all(item.bcp1_passed for item in results)


def test_ablation_result_document_reports_measured_failures() -> None:
    document = result_document(run_benchmark())
    assert document["schema_version"] == "bcp1-ablation-v1"
    assert document["scenario_count"] == 5
    assert document["baseline_failures"] == 5
    assert document["bcp1_failures"] == 0

