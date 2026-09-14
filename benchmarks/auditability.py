"""Measure the offline auditability gap between logs and a BCP-1 bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable

from app.models import canonical_json_bytes
from auditor.verify import verify_bundle
from benchmarks.ablation import (
    FLOOD_REQUESTS,
    _action,
    _operator_public,
    _runtime,
)


HMAC_KEY = b"benchmark-only-signed-log-key"
CLAIMS = (
    "operator_signed_contract_honored",
    "zero_forbidden_dispatches_in_mediated_path",
    "kill_bound_to_trigger",
    "included_event_tamper_detected",
    "conflicting_root_rejected",
)


def _flood_runtime():
    runtime = _runtime(
        max_requests_per_window=1,
        max_admitted_requests=FLOOD_REQUESTS,
    )
    first = canonical_json_bytes(_action(request_id="auditability:first"))
    excess = canonical_json_bytes(_action(request_id="auditability:excess"))
    assert runtime.gateway.submit_raw(first).accepted
    assert not runtime.gateway.submit_raw(excess).accepted
    for _ in range(FLOOD_REQUESTS - 2):
        runtime.gateway.submit_raw(excess)
    return runtime


def _baseline_logs() -> tuple[bytes, bytes]:
    access = bytearray()
    signed = bytearray()
    for index in range(FLOOD_REQUESTS):
        if index == 0:
            status = "allowed"
            reason = "policy.allowed"
        elif index == 1:
            status = "overload"
            reason = "admission.overload"
        else:
            status = "dropped"
            reason = "run.not_dispatchable"
        line = canonical_json_bytes(
            {
                "reason": reason,
                "request_id": f"request:{index}",
                "status": status,
            }
        )
        access.extend(line + b"\n")
        signature = base64.urlsafe_b64encode(
            hmac.new(HMAC_KEY, line, hashlib.sha256).digest()
        ).rstrip(b"=")
        signed.extend(signature + b" " + line + b"\n")
    return bytes(access), bytes(signed)


def _verify_access(data: bytes) -> None:
    for line in io.BytesIO(data):
        json.loads(line)


def _verify_signed(data: bytes) -> None:
    for line in io.BytesIO(data):
        encoded_signature, payload = line.rstrip(b"\n").split(b" ", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(HMAC_KEY, payload, hashlib.sha256).digest()
        ).rstrip(b"=")
        if not hmac.compare_digest(encoded_signature, expected):
            raise ValueError("signed log line was modified")
        json.loads(payload)


def _records_expose_fields(
    data: bytes,
    *,
    signed: bool,
    required: set[str],
) -> bool:
    for line in io.BytesIO(data):
        payload = line.rstrip(b"\n")
        if signed:
            _, payload = payload.split(b" ", 1)
        record = json.loads(payload)
        if isinstance(record, dict) and required.issubset(record):
            return True
    return False


def _signed_log_for(access_log: bytes) -> bytes:
    output = bytearray()
    for line in io.BytesIO(access_log):
        payload = line.rstrip(b"\n")
        signature = base64.urlsafe_b64encode(
            hmac.new(HMAC_KEY, payload, hashlib.sha256).digest()
        ).rstrip(b"=")
        output.extend(signature + b" " + payload + b"\n")
    return bytes(output)


def _measure(operation: Callable[[], None]) -> dict[str, int]:
    tracemalloc.start()
    started = time.perf_counter_ns()
    operation()
    elapsed = time.perf_counter_ns() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "verify_elapsed_ns": elapsed,
        "verify_peak_bytes": peak,
    }


def _succeeds(operation: Callable[[], None]) -> bool:
    try:
        operation()
    except Exception:
        return False
    return True


def run_auditability_study() -> dict[str, Any]:
    runtime = _flood_runtime()
    receipt = runtime.supervisor.receipt()
    bcp1_evidence = runtime.ledger.canonical_jsonl_bytes()
    access_log, signed_log = _baseline_logs()

    access_cost = _measure(lambda: _verify_access(access_log))
    signed_cost = _measure(lambda: _verify_signed(signed_log))

    def verify_bcp1() -> None:
        report = verify_bundle(
            manifest=runtime.manifest,
            receipt=receipt,
            evidence_lines=io.BytesIO(bcp1_evidence),
            operator_public_key=_operator_public(runtime),
        )
        if not report.valid:
            raise ValueError("BCP-1 bundle did not verify")

    bcp1_cost = _measure(verify_bcp1)

    tampered_access = access_log.replace(b"policy.allowed", b"policy.denied", 1)
    _verify_access(tampered_access)
    access_tamper_detected = False

    tampered_signed = signed_log.replace(b"policy.allowed", b"policy.denied", 1)
    signed_tamper_detected = False
    try:
        _verify_signed(tampered_signed)
    except ValueError:
        signed_tamper_detected = True

    tampered_bcp1 = bcp1_evidence.replace(b"numpy", b"scipy", 1)
    bcp1_tamper_detected = False
    try:
        verify_bundle(
            manifest=runtime.manifest,
            receipt=receipt,
            evidence_lines=io.BytesIO(tampered_bcp1),
            operator_public_key=_operator_public(runtime),
        )
    except ValueError:
        bcp1_tamper_detected = True

    access_contract = _records_expose_fields(
        access_log,
        signed=False,
        required={"manifest_hash", "operator_signature"},
    )
    signed_contract = _records_expose_fields(
        signed_log,
        signed=True,
        required={"manifest_hash", "operator_signature"},
    )
    access_dispatch_proof = _records_expose_fields(
        access_log,
        signed=False,
        required={"decision_hash", "authorization_id", "action_sha256"},
    )
    signed_dispatch_proof = _records_expose_fields(
        signed_log,
        signed=True,
        required={"decision_hash", "authorization_id", "action_sha256"},
    )
    access_kill_binding = _records_expose_fields(
        access_log,
        signed=False,
        required={"trigger_event_hash", "kill_latency_ns"},
    )
    signed_kill_binding = _records_expose_fields(
        signed_log,
        signed=True,
        required={"trigger_event_hash", "kill_latency_ns"},
    )

    conflicting_access = tampered_access
    conflicting_signed = _signed_log_for(conflicting_access)
    access_conflict_rejected = False
    signed_conflict_rejected = False
    try:
        _verify_access(access_log)
        _verify_access(conflicting_access)
    except ValueError:
        access_conflict_rejected = True
    try:
        _verify_signed(signed_log)
        _verify_signed(conflicting_signed)
    except ValueError:
        signed_conflict_rejected = True

    bcp1_contract = _succeeds(
        lambda: runtime.manifest.verify(_operator_public(runtime).as_bytes())
    )
    canary_runtime = _runtime()
    canary = _action(
        request_id="auditability:canary",
        credential_id="credential:canary",
    )
    canary_result = canary_runtime.gateway.submit_raw(canonical_json_bytes(canary))
    canary_receipt = canary_runtime.supervisor.receipt()
    canary_report = verify_bundle(
        manifest=canary_runtime.manifest,
        receipt=canary_receipt,
        evidence_lines=io.BytesIO(canary_runtime.ledger.canonical_jsonl_bytes()),
        operator_public_key=_operator_public(canary_runtime),
    )
    bcp1_zero_forbidden = (
        not canary_result.accepted
        and canary_report.dispatch_count == 0
        and canary_receipt.body.dispatched_request_count == 0
    )
    bcp1_kill_binding = (
        canary_report.killed
        and canary_receipt.body.kill_acknowledgement is not None
    )
    checkpoint = runtime.supervisor.witness.checkpoint(
        manifest=runtime.manifest,
        event_count=receipt.body.event_count,
        final_event_hash=receipt.body.final_event_hash,
        evidence_file_sha256=receipt.body.evidence_file_sha256,
    )
    bcp1_conflict_rejected = False
    try:
        runtime.supervisor.witness.checkpoint(
            manifest=runtime.manifest,
            event_count=checkpoint.body.event_count,
            final_event_hash=checkpoint.body.final_event_hash,
            evidence_file_sha256="f" * 64,
        )
    except ValueError:
        bcp1_conflict_rejected = True

    claim_matrix = {
        "access_log": {
            "operator_signed_contract_honored": access_contract,
            "zero_forbidden_dispatches_in_mediated_path": access_dispatch_proof,
            "kill_bound_to_trigger": access_kill_binding,
            "included_event_tamper_detected": access_tamper_detected,
            "conflicting_root_rejected": access_conflict_rejected,
        },
        "signed_line_log": {
            "operator_signed_contract_honored": signed_contract,
            "zero_forbidden_dispatches_in_mediated_path": signed_dispatch_proof,
            "kill_bound_to_trigger": signed_kill_binding,
            "included_event_tamper_detected": signed_tamper_detected,
            "conflicting_root_rejected": signed_conflict_rejected,
        },
        "bcp1_bundle": {
            "operator_signed_contract_honored": bcp1_contract,
            "zero_forbidden_dispatches_in_mediated_path": bcp1_zero_forbidden,
            "kill_bound_to_trigger": bcp1_kill_binding,
            "included_event_tamper_detected": bcp1_tamper_detected,
            "conflicting_root_rejected": bcp1_conflict_rejected,
        },
    }
    for claims in claim_matrix.values():
        claims["verified_claim_count"] = sum(
            value for value in claims.values() if isinstance(value, bool)
        )

    event_count = len(runtime.ledger.events())
    evidence = {
        "access_log": {
            "bytes": len(access_log),
            "records": FLOOD_REQUESTS,
            **access_cost,
        },
        "signed_line_log": {
            "bytes": len(signed_log),
            "records": FLOOD_REQUESTS,
            **signed_cost,
        },
        "bcp1_bundle": {
            "bytes": len(bcp1_evidence),
            "records": event_count,
            **bcp1_cost,
        },
    }
    return {
        "schema_version": "bcp1-auditability-gap-v1",
        "scope": (
            "reference evidence profiles under a 50000-request synthetic "
            "post-kill burst; BCP-1 completeness still depends on BCP-01"
        ),
        "claims": list(CLAIMS),
        "claim_matrix": claim_matrix,
        "evidence_economics": evidence,
        "record_reduction_vs_access_log": FLOOD_REQUESTS / event_count,
        "byte_reduction_vs_access_log": len(access_log) / len(bcp1_evidence),
        "byte_reduction_vs_signed_log": len(signed_log) / len(bcp1_evidence),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/benchmark/auditability.json"),
    )
    args = parser.parse_args()
    result = run_auditability_study()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

