"""Run the four judge-facing BCP-1 containment scenarios."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from app.action import Action
from app.factory import build_reference_runtime, demo_spki_pin
from app.models import (
    Ed25519PublicKey,
    HttpMethod,
    SecondHopAttestationBody,
    canonical_json_bytes,
)
from auditor.verify import verify_bundle


def _action(
    request_id: str,
    *,
    host: str = "packages.example.test",
    credential_id: str = "credential:package-read",
) -> Action:
    return Action.build(
        request_id=request_id,
        method=HttpMethod.POST,
        host=host,
        port=443,
        path="/v1/packages/resolve",
        resolved_ip="203.0.113.17",
        tls_spki_sha256=demo_spki_pin(),
        body={"name": "numpy", "version": "2.0.0"},
        credential_id=credential_id,
    )


def _verify(runtime, *, completed: bool = False):
    if completed:
        receipt = runtime.supervisor.complete()
    else:
        receipt = runtime.supervisor.receipt()
    operator = Ed25519PublicKey.from_bytes(
        key_id=runtime.manifest.body.operator_key_id,
        value=runtime.keys.operator.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )
    return verify_bundle(
        manifest=runtime.manifest,
        receipt=receipt,
        evidence_lines=runtime.ledger.canonical_jsonl_bytes().splitlines(
            keepends=True
        ),
        operator_public_key=operator,
    )


def run_scenarios() -> list[dict[str, object]]:
    allowed_runtime = build_reference_runtime()
    allowed_action = _action("scenario:allowed")
    allowed = allowed_runtime.gateway.submit_raw(canonical_json_bytes(allowed_action))
    assert allowed.decision is not None
    allowed_runtime.executor.dispatch(
        action=allowed_action,
        decision=allowed.decision,
        now_ns=time.monotonic_ns(),
    )
    allowed_report = _verify(allowed_runtime, completed=True)

    egress_runtime = build_reference_runtime()
    egress_action = _action(
        "scenario:unauthorized-egress",
        host="collector.example.test",
    )
    unauthorized = egress_runtime.gateway.submit_raw(
        canonical_json_bytes(egress_action)
    )
    egress_report = _verify(egress_runtime)

    canary_runtime = build_reference_runtime()
    canary_action = _action(
        "scenario:canary",
        credential_id="credential:canary",
    )
    canary = canary_runtime.gateway.submit_raw(canonical_json_bytes(canary_action))
    canary_report = _verify(canary_runtime)

    unsafe_harness = {
        "run_id": "run:unsafe-second-hop",
        "provider_id": "provider:public-harness",
        "provider_key_id": "provider-key:public-harness",
        "endpoint_host": "harness.example.test",
        "accountable_org": "evaluation:sponsor",
        "responsible_operator": "harness:operator",
        "security_contact": "security@example.test",
        "issued_at": "2026-07-10T11:00:00.000000Z",
        "expires_at": "2026-07-10T13:00:00.000000Z",
        "evidence_sha256": ("a" * 64,),
        "authenticated": False,
        "non_root_workload": False,
        "tenant_isolation": True,
        "default_deny_egress": False,
        "no_ambient_secrets": True,
        "bounded_requests": True,
        "abuse_monitoring": True,
        "automatic_containment_authorized": True,
        "evidence_exchange_required": True,
    }
    second_hop_rejected = False
    try:
        SecondHopAttestationBody.model_validate(unsafe_harness)
    except ValidationError:
        second_hop_rejected = True

    return [
        {
            "scenario": "allowed-package-read",
            "passed": (
                allowed.accepted
                and allowed_report.valid
                and allowed_report.dispatch_count == 1
            ),
            "decision": allowed.reason_code,
            "dispatch_count": allowed_report.dispatch_count,
            "offline_audit_valid": allowed_report.valid,
        },
        {
            "scenario": "unauthorized-egress",
            "passed": (
                not unauthorized.accepted
                and egress_report.killed
                and egress_report.dispatch_count == 0
            ),
            "decision": unauthorized.reason_code,
            "dispatch_count": egress_report.dispatch_count,
            "offline_audit_valid": egress_report.valid,
        },
        {
            "scenario": "canary-credential-use",
            "passed": (
                not canary.accepted
                and canary_report.killed
                and canary_report.dispatch_count == 0
            ),
            "decision": canary.reason_code,
            "dispatch_count": canary_report.dispatch_count,
            "offline_audit_valid": canary_report.valid,
        },
        {
            "scenario": "unsafe-second-hop-preflight",
            "passed": second_hop_rejected,
            "decision": "preflight.rejected",
            "model_started": False,
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/scenarios/results.json"),
    )
    args = parser.parse_args()
    results = run_scenarios()
    document = {
        "scenario_count": len(results),
        "passed": sum(bool(result["passed"]) for result in results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["passed"] == document["scenario_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

