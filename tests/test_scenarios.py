from __future__ import annotations

from demo.scenarios.run import run_scenarios


def test_all_judge_facing_scenarios_pass() -> None:
    results = run_scenarios()
    assert len(results) == 4
    assert all(result["passed"] for result in results)
    assert results[0]["dispatch_count"] == 1
    assert results[1]["dispatch_count"] == 0
    assert results[2]["dispatch_count"] == 0
    assert results[3]["model_started"] is False

