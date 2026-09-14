"""Run a canary-triggered containment and verify its evidence offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from app.action import Action
from app.factory import build_reference_runtime, demo_spki_pin
from app.models import Ed25519PublicKey, HttpMethod, canonical_json_bytes
from auditor.verify import verify_bundle


def run_demo(output: Path) -> dict[str, object]:
    runtime = build_reference_runtime()
    action = Action.build(
        request_id="request:canary",
        method=HttpMethod.POST,
        host="packages.example.test",
        port=443,
        path="/v1/packages/resolve",
        resolved_ip="203.0.113.17",
        tls_spki_sha256=demo_spki_pin(),
        body={"name": "numpy", "version": "2.0.0"},
        credential_id="credential:canary",
    )
    decision = runtime.gateway.submit_raw(canonical_json_bytes(action))
    if decision.accepted:
        raise RuntimeError("canary action was unexpectedly allowed")
    receipt = runtime.supervisor.receipt()
    operator_key = Ed25519PublicKey.from_bytes(
        key_id=runtime.manifest.body.operator_key_id,
        value=runtime.keys.operator.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )
    evidence = runtime.ledger.canonical_jsonl_bytes()
    report = verify_bundle(
        manifest=runtime.manifest,
        receipt=receipt,
        evidence_lines=evidence.splitlines(keepends=True),
        operator_public_key=operator_key,
    )

    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_bytes(canonical_json_bytes(runtime.manifest))
    (output / "evidence.jsonl").write_bytes(evidence)
    (output / "receipt.json").write_bytes(canonical_json_bytes(receipt))
    (output / "operator-key.json").write_bytes(canonical_json_bytes(operator_key))
    return {
        "audit_valid": report.valid,
        "decision": decision.reason_code,
        "event_count": report.event_count,
        "forbidden_requests_forwarded": report.dispatch_count,
        "kill_latency_ns": (
            receipt.body.kill_acknowledgement.body.kill_latency_ns
            if receipt.body.kill_acknowledgement
            else None
        ),
        "run_status": receipt.body.status,
        "witness_checkpoint": report.witness_checkpoint_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/demo"),
        help="directory for the offline evidence bundle",
    )
    args = parser.parse_args()
    print(json.dumps(run_demo(args.output), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
