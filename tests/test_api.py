from __future__ import annotations

from fastapi.testclient import TestClient

from app.action import Action
from app.factory import build_reference_runtime, demo_spki_pin
from app.main import create_agent_app, create_control_app
from app.models import HttpMethod, canonical_json_bytes


def _action(credential_id: str) -> Action:
    return Action.build(
        request_id="request:api",
        method=HttpMethod.POST,
        host="packages.example.test",
        port=443,
        path="/v1/packages/resolve",
        resolved_ip="203.0.113.17",
        tls_spki_sha256=demo_spki_pin(),
        body={"name": "numpy", "version": "2.0.0"},
        credential_id=credential_id,
    )


def test_demo_api_dispatches_an_allowed_action() -> None:
    runtime = build_reference_runtime()
    with TestClient(create_agent_app(runtime)) as client:
        response = client.post(
            "/v1/dispatch",
            content=canonical_json_bytes(_action("credential:package-read")),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200
        assert response.json()["accepted"] is True
        status = client.get("/v1/status").json()
        assert status["counters"]["dispatched"] == 1
        assert status["phase"] == "RUNNING"
        assert client.post("/v1/complete").status_code == 404
        assert client.get("/v1/receipt").status_code == 404
    with TestClient(
        create_control_app(runtime, bearer_token="test-control-token")
    ) as control:
        assert control.get("/v1/receipt").status_code == 401
        assert (
            control.get(
                "/v1/receipt",
                headers={"authorization": "Bearer test-control-token"},
            ).status_code
            == 409
        )
        completed = control.post(
            "/v1/complete",
            headers={"authorization": "Bearer test-control-token"},
        )
        assert completed.status_code == 200
        assert completed.json()["body"]["status"] == "COMPLETED"


def test_demo_api_reports_canary_containment_and_receipt() -> None:
    runtime = build_reference_runtime()
    with TestClient(create_agent_app(runtime)) as client:
        response = client.post(
            "/v1/dispatch",
            content=canonical_json_bytes(_action("credential:canary")),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 403
        assert response.json()["reason_code"] == "credential.canary_used"
        assert client.get("/v1/receipt").status_code == 404
    with TestClient(
        create_control_app(runtime, bearer_token="test-control-token")
    ) as control:
        receipt = control.get(
            "/v1/receipt",
            headers={"authorization": "Bearer test-control-token"},
        )
        assert receipt.status_code == 200
        assert receipt.json()["body"]["status"] == "KILLED"


def test_agent_api_rejects_oversized_body_before_json_parsing() -> None:
    runtime = build_reference_runtime()
    oversized = b"{" + b"x" * (
        runtime.manifest.body.kill_criteria.max_event_payload_bytes + 1
    )
    with TestClient(create_agent_app(runtime)) as client:
        response = client.post(
            "/v1/dispatch",
            content=oversized,
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 413
    assert runtime.state.snapshot().admitted_request_count == 0


def test_agent_api_rejects_non_json_media_type() -> None:
    runtime = build_reference_runtime()
    with TestClient(create_agent_app(runtime)) as client:
        response = client.post(
            "/v1/dispatch",
            content=b"{}",
            headers={"content-type": "text/plain"},
        )
    assert response.status_code == 415
